# Provisioning users from a directory

Genkan has no built-in SCIM server. Users are `User` objects in Genkan's namespace, so keeping
them in step with Okta, Entra ID, Google Workspace, LDAP or an HR system is a small program
that reads the directory and writes those objects with the Kubernetes API. This guide sets up
the permissions such a program needs, and an admission policy that limits the damage if it is
wrong or compromised. Day-to-day commands are in [managing-users.md](managing-users.md).

## What the sync tool does

| Directory event | Kubernetes write |
|---|---|
| Person added | create `User` (labelled as managed by the tool) |
| Name or groups changed | update `spec.displayName` / `spec.groups` |
| Person suspended | set `spec.disabled: true` |
| Person removed | set `spec.disabled: true`; an admin deletes later |

It does **not**:

- **Create `Credential`s.** Linking a passkey or upstream account happens only through a
  one-time link the person opens, so a sync tool can never decide who signs in as whom.
- **Create `Invitation`s.** An invitation link enrols a passkey on an existing user, so whoever
  can create invitations can take over any account. Keep that power with admins
  (`genkanctl invite --username <name>`), or give it to a separate, admin-equivalent job.
- **Assign elevated groups.** Admin rights stay a decision made by hand: an admin may add
  elevated groups to a managed user, and the tool's later updates keep them as they are.
- **Delete users.** Removing a user safely means deleting its credentials and sessions first
  (see [managing-users.md](managing-users.md#suspend-or-remove-someone)); disabling is enough
  to stop sign-ins, and is reversible.

Match people by the directory's own immutable ID, kept in an annotation on the `User`, never by
email address: email addresses get reassigned.

## 1. A service account with write access to users only

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: user-sync
  namespace: genkan-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: user-sync
  namespace: genkan-system
rules:
- apiGroups: [genkan.engawahq.dev]
  resources: [users]
  verbs: [get, list, watch, create, update, patch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: user-sync
  namespace: genkan-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: user-sync
subjects:
- kind: ServiceAccount
  name: user-sync
  namespace: genkan-system
```

There is no `delete`, and no access to credentials, invitations, grants or Secrets.

## 2. An admission policy that bounds it

RBAC cannot restrict writes by label or field value, so a `ValidatingAdmissionPolicy`
(Kubernetes 1.30 or later) enforces the rest. It applies only to `user-sync` and fails closed.
Edit the allowlist (`'dev', 'ops'`) to the groups the directory may assign.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: genkan-user-sync
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: [genkan.engawahq.dev]
      apiVersions: ["*"]
      operations: [CREATE, UPDATE]
      resources: [users]
  matchConditions:
  - name: user-sync
    expression: request.userInfo.username == 'system:serviceaccount:genkan-system:user-sync'
  variables:
  - name: managed
    expression: >-
      has(object.metadata.labels) &&
      'genkan.engawahq.dev/source' in object.metadata.labels &&
      object.metadata.labels['genkan.engawahq.dev/source'] == 'directory'
  - name: wasManaged
    expression: >-
      request.operation == 'CREATE' || (has(oldObject.metadata.labels) &&
      'genkan.engawahq.dev/source' in oldObject.metadata.labels &&
      oldObject.metadata.labels['genkan.engawahq.dev/source'] == 'directory')
  - name: elevated
    expression: "has(object.spec.elevatedGroups) ? object.spec.elevatedGroups : []"
  - name: wasElevated
    expression: >-
      request.operation == 'UPDATE' && has(oldObject.spec.elevatedGroups) ?
      oldObject.spec.elevatedGroups : []
  validations:
  - expression: variables.wasManaged
    message: user-sync may only change users it created
  - expression: variables.managed
    message: users written by user-sync must keep the label genkan.engawahq.dev/source=directory
  - expression: object.spec.username == object.metadata.name
    message: the object name must equal the username, so a username cannot be taken twice
  - expression: "!has(object.spec.groups) || object.spec.groups.all(g, g in ['dev', 'ops'])"
    message: user-sync may only assign allowlisted groups
  - expression: variables.elevated == variables.wasElevated
    message: user-sync never assigns or changes elevated groups
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: genkan-user-sync
spec:
  policyName: genkan-user-sync
  validationActions: [Deny]
```

Elevated groups must stay exactly as they were: empty when the tool creates a user, and
unchanged by its updates. Admission sees the whole resulting object, and server-side apply keeps
fields the tool's manifest leaves out, so elevated groups an admin added survive every sync.

Why the username rule: Kubernetes sees every `User` as `genkan:<username>`, so two objects with
the same username would be the same person to RBAC. Object names are unique, and `genkanctl`
always names a user after its username, so requiring the two to be equal keeps the tool from
creating a second `admin`.

The `User` schema limits usernames to DNS subdomains of at most 63 characters: lowercase
letters, digits, `-` and `.`, with each dot-separated label starting and ending in a letter or
digit. No `@`, `+` or `_`. Map an email address to a DNS-compatible directory short name;
`genkanctl invite` and `genkanctl setup-link` use the same contract. If two people could map to
the same name, the directory-ID check below stops one from taking over the other's `User`.
The 63-character cap also keeps the full username within Kubernetes' label-value limit for
invitations, credentials and grants.

Check the policy before trusting it:

```sh
as=(--as=system:serviceaccount:genkan-system:user-sync)
# Refused: touches a user the tool did not create.
kubectl -n genkan-system patch gkuser admin "${as[@]}" --type=merge -p '{"spec":{"disabled":true}}'
# Refused: elevated group.
kubectl -n genkan-system apply "${as[@]}" -f - <<'EOF'
apiVersion: genkan.engawahq.dev/v1alpha1
kind: User
metadata:
  name: mallory
  namespace: genkan-system
  labels: {genkan.engawahq.dev/source: directory}
spec: {username: mallory, elevatedGroups: [admins]}
EOF
```

## 3. The sync loop

Any language with a Kubernetes client works; this is the shape of it in shell, run as the
`user-sync` service account (a `CronJob`, or outside the cluster with a token from
`kubectl -n genkan-system create token user-sync`). `directory-export` stands for whatever
lists people from your directory as JSON lines `{"id", "username", "name", "groups", "active"}`,
and exits non-zero when it cannot list everyone.

```sh
#!/usr/bin/env bash
set -euo pipefail
ns=genkan-system
failed=0

# Read the whole export before writing anything: a failing exporter stops the job here.
people=$(directory-export)
if [[ -z "$people" ]]; then
  echo "the export is empty; refusing to sync" >&2
  exit 1
fi

while read -r person; do
  username=$(jq -r .username <<<"$person")
  jq -n --arg ns "$ns" --argjson p "$person" '{
    apiVersion: "genkan.engawahq.dev/v1alpha1",
    kind: "User",
    metadata: {
      name: $p.username,
      namespace: $ns,
      labels: {"genkan.engawahq.dev/source": "directory"},
      annotations: {"example.com/directory-id": $p.id}
    },
    spec: {
      username: $p.username,
      displayName: $p.name,
      groups: $p.groups,
      disabled: ($p.active | not)
    }
  }' | kubectl apply --server-side --field-manager=user-sync -f - ||
    { echo "failed: $username" >&2; failed=1; continue; }
  echo "synced $username"
done <<<"$people"
exit "$failed"
```

The export is read in full first, so an exporter that fails part-way fails the job before any
write, instead of leaving later users (and their suspensions) out while the job looks
successful. An empty export is refused too: once the tool disables users missing from the
export, an empty one would disable everyone. Use whatever completeness check your directory
offers (a total count, a pagination end marker) inside `directory-export`.

One refused user must not stop the others: a suspension further down the export still has to
be written. The loop reports each failure and exits non-zero at the end, so the job shows as
failed.

The tool owns `displayName`, `groups` and `disabled` of the users it manages (its field
manager). Change those in the directory, not with `kubectl`: a hand edit makes the next apply
fail with a field conflict for that user. Elevated groups are the exception, since the tool
never writes them.

Before applying, a real tool should also:

- Refuse to change the directory-ID annotation of an existing user, so a renamed or recycled
  account in the directory cannot inherit someone else's `User`.
- Disable managed users that are no longer in the export
  (`kubectl get gkuser -l genkan.engawahq.dev/source=directory`).
- Lowercase usernames and check that they are valid object names and fit the `User` schema
  (at most 63 characters,
  `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`) before writing.

New people still need a link to enrol: an admin runs `genkanctl invite --username <name>` for
each new user and sends it to them.

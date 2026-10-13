# Provisioning users from a directory

If your team already lives in Okta, Entra ID, Google Workspace, LDAP or an HR system, you can
keep Genkan's users in step with it. Genkan has no built-in connector (it does not speak SCIM).
Instead, you run a small sync program that reads your directory and writes `User` objects
through the Kubernetes API.

This guide sets up:

1. a service account that can write users and nothing else;
2. an admission policy that limits the damage if the program is buggy or compromised;
3. the sync program itself, as a shell example.

For everyday commands, see [Managing users](managing-users.md).

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

Match people by the directory's own permanent ID, kept in an annotation on the `User`. Never
match by email address: addresses get reused when people leave.

## 1. A service account with write access to users only

Save this as `user-sync-rbac.yaml` and apply it with `kubectl apply -f user-sync-rbac.yaml`:

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

RBAC can say "may write users", but not "may write only these users, with only these groups".
A `ValidatingAdmissionPolicy` (Kubernetes 1.30 or later) adds those rules. It applies only to
the `user-sync` account, and if the policy cannot be evaluated, the write is refused.

It enforces that the sync program:

- only changes users it created (label `genkan.engawahq.dev/source=directory`);
- never assigns or changes elevated groups;
- only assigns groups from an allowlist. Edit `['dev', 'ops']` below to yours;
- names each object after its username (see [why](#why-the-name-must-equal-the-username)).

Save this as `user-sync-policy.yaml` and apply it with `kubectl apply -f user-sync-policy.yaml`:

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

An admin can still add elevated groups to a synced user by hand. The sync program's later
updates leave them alone, because server-side apply keeps fields the program does not send.

### Why the name must equal the username

Kubernetes sees every `User` as `genkan:<username>`. Two objects with the same username would
be the same person to RBAC. Object names are unique, so requiring the name to equal the
username stops the program from creating a second `admin`.

### Username rules

Use the same value for `metadata.name` and `spec.username`. The `User` schema accepts lowercase
DNS subdomains of at most 63 characters: letters, digits, `-` and `.`, with each dot-separated
label starting and ending in a letter or digit. No `@`, `+` or `_`. The exact pattern is:

```text
^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$
```

`genkanctl invite` and `genkanctl setup-link` enforce the same rule.

If your directory identifies people by email address, derive a short name that fits these
rules (for example `alice.chen` from `alice.chen@example.com`). Two people can end up with the
same short name, so the sync program must still check the directory ID before updating a user;
see [the sync loop](#3-the-sync-loop).

### Test the policy

Before trusting the policy, check that it refuses what it should. Both commands below must
fail:

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

Write the program in any language with a Kubernetes client. Run it as the `user-sync` service
account: as a `CronJob` in the cluster, or elsewhere with a token from
`kubectl -n genkan-system create token user-sync`.

Below is the shape of it in shell. `directory-export` stands for your own command that lists
everyone in the directory, one JSON object per line with `id`, `username`, `name`, `groups` and
`active`, and exits with an error when it cannot list everyone.

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

Why it is written this way:

- **It reads the whole export before writing anything.** If the export fails half-way, the job
  stops before changing anyone, instead of quietly skipping the rest (and their suspensions).
  Use whatever completeness check your directory offers, such as a total count or an
  end-of-list marker, inside `directory-export`.
- **It refuses an empty export.** Once the program disables users missing from the export, an
  empty export would disable everyone.
- **One failed user does not stop the others.** A suspension further down the list still has to
  be written. The loop reports each failure and exits with an error at the end, so the job
  shows as failed.

The program owns `displayName`, `groups` and `disabled` on the users it manages. Change those in
the directory, not with `kubectl`: a hand edit makes the next sync fail for that user with a
field conflict. Elevated groups are the exception, since the program never writes them.

Before applying, a real tool should also:

- Refuse to change the directory-ID annotation of an existing user, so a renamed or recycled
  account in the directory cannot inherit someone else's `User`.
- Disable managed users that are no longer in the export
  (`kubectl get gkuser -l genkan.engawahq.dev/source=directory`).
- Lowercase usernames and check them against the [username rules](#username-rules) before
  writing.

## 4. Send new people their links

The sync program creates users, but they still need a one-time link to set up a passkey. An
admin sends it, as in [Add someone](managing-users.md#add-someone). The link works only if the
Genkan server runs with `--invitations`; see
[If the link does not work](managing-users.md#if-the-link-does-not-work).

```sh
export GENKAN_ISSUER=https://genkan.example.test     # your issuer
genkanctl invite --username <name>
```

# Managing users

Everything Genkan knows about people is a custom resource in its namespace, so managing users
is `genkanctl` for links and `kubectl` (or GitOps) for the rest. The commands assume the
cluster from [get-started.md](get-started.md): namespace `genkan-system`, issuer
`https://genkan-k3s.shared`, run with the cluster admin's kubeconfig.

```sh
export GENKAN_ISSUER=https://genkan-k3s.shared
```

| Object | Short name | Who writes it |
|---|---|---|
| `User` | `gkuser` | you (`spec`); Genkan writes only `status` |
| `Credential` | `gkcred` | Genkan, when someone enrols a passkey or links an account; you, to revoke |
| `Invitation` | `gkinvite` | `genkanctl invite`; Genkan deletes it when redeemed or expired |
| `Grant` | `gkgrant` | Genkan, one per signed-in session (refresh-token family) |

Credentials, invitations and grants carry the label `genkan.engawahq.dev/user=<User name>`, so
`-l genkan.engawahq.dev/user=alice` selects everything belonging to `alice`.

## Add someone

```sh
genkanctl invite --username alice --display-name "Alice Chen" --group dev
```

This creates the `User` `alice` in group `dev` (Kubernetes sees `genkan:alice` in
`genkan:dev`) and prints a one-time link, valid for 7 days (`--valid-for`). Send it over a
channel you trust; whoever opens it first enrols a passkey, or links a GitHub or Google account
if those are enabled ([github-sign-in.md](github-sign-in.md)).

Genkan does not send mail. The link goes to stdout and the notes to stderr, so a script can
deliver it however your team works, for example:

```sh
link=$(genkanctl invite --username alice --group dev)
printf 'Open this link on the device that will keep your passkey:\n\n%s\n' "$link" |
  mail -s "Set up your passkey" alice@example.com
```

Anyone holding the link can enrol a passkey as Alice until it is used or expires, so send it
only to her.

Bind roles to the group, not to the person:

```sh
kubectl create rolebinding dev-edit --clusterrole=edit --group=genkan:dev -n dev
```

## Change groups or the display name

Edit the `User`; the next token Genkan issues carries the change. Tokens already issued keep
their groups until they expire (at most ten minutes for `kubectl`).

```sh
kubectl -n genkan-system patch gkuser alice --type=merge -p '{"spec":{"groups":["dev","oncall"]}}'
```

For users a directory sync manages (label `genkan.engawahq.dev/source=directory`), change the
name and groups in the directory instead; see [provisioning-users.md](provisioning-users.md).

`username` is immutable, because RBAC bindings and audit logs refer to it. To rename someone,
create a new user and remove the old one.

### Admin rights

Elevated groups are the only way to powerful roles: Kubernetes sees them as
`genkan:elevated:<group>`, only in a five-minute token issued right after a passkey sign-in that
asks for it.

```sh
kubectl -n genkan-system patch gkuser alice --type=merge -p '{"spec":{"elevatedGroups":["admins"]}}'
```

This works the same for directory-managed users: the sync tool never touches elevated groups.

The install binds `genkan:elevated:admins` to `cluster-admin`. Bind other elevated groups to
narrower roles in the same way.

## Add another passkey or device

Most passkeys sync through the platform's account (iCloud Keychain, Google Password Manager),
so a new phone usually needs nothing. For a separate security key, invite the same username
again: the existing `User` and passkeys stay as they are, and the link adds one more
credential.

```sh
genkanctl invite --username alice
```

## See and revoke credentials

```sh
kubectl -n genkan-system get gkcred -l genkan.engawahq.dev/user=alice
kubectl -n genkan-system delete gkcred <name>
```

A deleted credential cannot sign in again. Sessions it already started continue until you
sign them out (next section).

## Sign someone out

Each signed-in session is a `Grant`. Deleting it ends the session: the refresh token stops
working, and the access token in hand expires within ten minutes.

```sh
kubectl -n genkan-system get gkgrant -l genkan.engawahq.dev/user=alice
kubectl -n genkan-system delete gkgrant -l genkan.engawahq.dev/user=alice
```

## Lost passkey (account recovery)

```sh
kubectl -n genkan-system delete gkinvite -l genkan.engawahq.dev/user=alice
genkanctl setup-link --username alice --reset
```

Delete Alice's pending invitations first: an unredeemed invitation adds a passkey to her account
whenever it is opened, and `--reset` does not revoke invitations yet
([#25](https://github.com/engawahq/genkan/issues/25)). `--reset` then deletes all of her
credentials and sessions and prints a one-time link valid for an hour. Confirm who you are
talking to before sending it: the link's holder becomes Alice.

## Suspend or remove someone

Suspend first. A disabled user cannot sign in, and refresh tokens stop working at their next
use; nothing is deleted, so it is reversible.

```sh
kubectl -n genkan-system patch gkuser alice --type=merge -p '{"spec":{"disabled":true}}'
```

To remove the person for good, delete their credentials, sessions and pending invitations
before the `User`:

```sh
for kind in gkcred gkgrant gkinvite; do
  kubectl -n genkan-system delete "$kind" -l genkan.engawahq.dev/user=alice
done
kubectl -n genkan-system delete gkuser alice
```

Do this in that order. Credentials, sessions and invitations Genkan creates carry an owner
reference to the `User`, so deleting only the `User` also removes them, but eventually rather
than at once, and not at all with `--cascade=orphan` or for records without an owner reference
(written before owner references were added, or created by hand). Until they are gone, a new
`User` given the same name would be signed in by the old credentials.

## Keep users in Git

`User` objects are plain manifests, so they can live in a GitOps repository like any other
resource. Leave `Credential`, `Grant` and `Invitation` out: Genkan creates and deletes them, and
a sync tool that prunes them would sign people out or revoke their passkeys.

```yaml
apiVersion: genkan.engawahq.dev/v1alpha1
kind: User
metadata:
  name: alice
  namespace: genkan-system
spec:
  username: alice
  displayName: Alice Chen
  groups: [dev]
```

To keep users in step with a company directory instead, see
[provisioning-users.md](provisioning-users.md).

# Managing users

Genkan stores people, passkeys and sessions as Kubernetes objects in its own namespace. You
manage them with two tools:

- `genkanctl` creates the one-time links people use to set up a passkey;
- `kubectl` (or your GitOps tool) does everything else: groups, admin rights, signing people
  out, removing them.

The examples assume the cluster from [Get started](get-started.md): namespace `genkan-system`
and issuer `https://genkan.example.test`. Run them where you have the cluster admin's kubeconfig,
and use your own issuer:

```sh
export GENKAN_ISSUER=https://genkan.example.test
```

`genkanctl` reads the issuer from `GENKAN_ISSUER`, so the commands below do not repeat it.

## The objects

| Object | Short name | What it is | Who creates it |
|---|---|---|---|
| `User` | `gkuser` | a person: username, display name, groups | you |
| `Credential` | `gkcred` | one passkey, or one linked GitHub or Google account | Genkan, when someone uses a link |
| `Invitation` | `gkinvite` | a pending one-time link | `genkanctl invite`; Genkan deletes it once used or expired |
| `Grant` | `gkgrant` | one signed-in session | Genkan, at each sign-in |

Credentials, invitations and grants carry the label `genkan.engawahq.dev/user=<username>`, so
`-l genkan.engawahq.dev/user=alice` selects everything that belongs to `alice`.

The lifetimes below are the defaults: everyday tokens last 10 minutes and admin tokens 5
minutes. See [token limits](../crates/genkanctl/README.md#configure-token-limits-and-certificates)
if you changed them.

## Add someone

```sh
genkanctl invite --username alice --display-name "Alice Chen" --group dev
```

This creates the user `alice` in the group `dev`, and prints a one-time link. Send the link to
Alice over a channel you trust. When she opens it, she creates a passkey, or links her
[GitHub](github-sign-in.md) or [Google](google-sign-in.md) account if you enabled them.

Things to know:

- **Anyone with the link can become Alice** until it is used or expires. Send it only to her.
- **The link lasts 7 days.** Use `--valid-for 24h`, for example, for a shorter window.
- **Options apply only to new users.** `--group`, `--elevated-group` and `--display-name` set
  up a new user. For an existing username, the invitation only adds a passkey or a linked
  GitHub or Google account; it does not change groups or the name.
- **Repeat `--group`** to add several groups.
- **Genkan sends no mail.** The link goes to stdout and everything else to stderr, so a script
  can deliver it however your team works:

  ```sh
  link=$(genkanctl invite --username alice --group dev)
  mail -s "Set up your passkey" alice@example.com <<EOF
  Open this link on the device that will keep your passkey:

  $link
  EOF
  ```

Kubernetes sees Alice as the user `genkan:alice` in the group `genkan:dev`. Give permissions to
the group, not to the person:

```sh
kubectl create rolebinding dev-edit --clusterrole=edit --group=genkan:dev -n dev
```

### If the link does not work

Invitation links need the server's `--invitations` option. [Get started](get-started.md)
turns it on. If your installation does not have it, regenerate the deployment with it:

```sh
genkanctl manifests --image docker.io/library/genkan:dev \
  --serve-arg=--invitations | kubectl apply --server-side -f -
kubectl -n genkan-system rollout status deploy/genkan
```

`genkanctl manifests` does not remember earlier options. Pass the same image, namespace,
`--config-secret` and `--serve-arg` options you installed with, plus the new one.

## Change groups or the display name

Edit the `User`:

```sh
kubectl -n genkan-system patch gkuser alice --type=merge -p '{"spec":{"groups":["dev","oncall"]}}'
```

The change shows up in the next token Genkan issues. Tokens already issued keep the old groups
until they expire, within ten minutes for `kubectl`.

If a directory sync manages the user (label `genkan.engawahq.dev/source=directory`), change the
name and groups in the directory instead; see [Provisioning users](provisioning-users.md).

You cannot rename a user: RBAC bindings and audit logs refer to the username. To rename
someone, create a new user and remove the old one.

## Admin rights

Everyday tokens can only do what the user's ordinary groups allow. For powerful roles, give
the user an **elevated group**:

```sh
kubectl -n genkan-system patch gkuser alice --type=merge -p '{"spec":{"elevatedGroups":["admins"]}}'
```

Alice gets the elevated group only when she asks for it, for example through the admin
`kubectl` context, and signs in with her passkey again. Kubernetes then sees her in `genkan:elevated:admins`, for five
minutes. Her everyday tokens never carry it.

The installation binds `genkan:elevated:admins` to `cluster-admin`. Bind other elevated groups
to narrower roles in the same way, for example `--group=genkan:elevated:dev-admins`.

Directory sync never touches elevated groups, so this works the same for synced users.

### Which applications may ask for admin rights

Only clients registered with `allowElevation: true` can ask. Others get an `invalid_scope`
error. Turn it on for the client you administer the cluster with, such as `kubectl` in
[Get started](get-started.md), and leave it off for web applications that only sign people in:

```sh
kubectl -n genkan-system patch gkclient kubectl --type=merge -p '{"spec":{"allowElevation":true}}'
```

Turning it off takes effect at once, even for sign-ins in progress. When an application asks
for admin rights, the sign-in page says so and shows for how long.

## Add another passkey or device

Most passkeys sync through the platform account (iCloud Keychain, Google Password Manager), so
a new phone usually needs nothing. For a separate security key, or to link a GitHub or Google
account, invite the same username again. The new link adds one passkey or linked account and
leaves everything else as it is:

```sh
genkanctl invite --username alice
```

## Remove a passkey or linked account

```sh
kubectl -n genkan-system get gkcred -l genkan.engawahq.dev/user=alice
kubectl -n genkan-system delete gkcred <name>
```

The deleted credential cannot sign in again. Sessions it already started keep working until you
[sign them out](#sign-someone-out).

## Sign someone out

Each signed-in session is a `Grant`. Delete it to end the session:

```sh
kubectl -n genkan-system get gkgrant -l genkan.engawahq.dev/user=alice
kubectl -n genkan-system delete gkgrant -l genkan.engawahq.dev/user=alice
```

The session cannot renew its token any more. The token already in hand still works until it
expires, within ten minutes.

## Lost passkey (account recovery)

```sh
genkanctl setup-link --username alice --reset
```

This deletes all of Alice's passkeys, sessions and pending invitations, and prints a new
one-time link that lasts an hour. Whoever opens the link becomes Alice, so confirm you are
talking to her before you send it.

## Suspend or remove someone

**Suspend first.** A disabled user cannot sign in, and their sessions stop renewing. Nothing is
deleted, so you can undo it:

```sh
kubectl -n genkan-system patch gkuser alice --type=merge -p '{"spec":{"disabled":true}}'
```

**To remove someone for good**, delete their passkeys, sessions and invitations first, then the
`User`:

```sh
for kind in gkcred gkgrant gkinvite; do
  kubectl -n genkan-system delete "$kind" -l genkan.engawahq.dev/user=alice
done
kubectl -n genkan-system delete gkuser alice
```

> [!WARNING]
> Keep this order. Deleting only the `User` leaves the old passkeys around for a while: until
> Kubernetes garbage collection removes them, or forever for objects created by hand without an
> owner reference. If you create a new `User` with the same name in the meantime, the old
> passkeys sign in as that new user.

## Keep users in Git

`User` objects are plain manifests, so they can live in a GitOps repository:

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

Keep `Credential`, `Grant` and `Invitation` out of Git. Genkan creates and deletes them, and a
sync tool that prunes them would remove people's passkeys or sign them out.

To keep users in step with a company directory instead, see
[Provisioning users](provisioning-users.md).

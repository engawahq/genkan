# Sign in with GitHub

Genkan can offer "Continue with GitHub" next to the passkey on its sign-in page. This guide
adds it to the cluster from [get-started.md](get-started.md); the commands assume that setup
(issuer `https://genkan-k3s.shared`, namespace `genkan-system`, `genkanctl` and `kubectl` on the
VM inside `nix develop`).

```sh
export GENKAN_ISSUER=https://genkan-k3s.shared
```

`genkanctl` reads `GENKAN_ISSUER`, so the commands below do not pass an issuer argument.

## What it does and does not do

- **A GitHub account signs in only as a user it was linked to.** Nothing is created on the
  first sign-in, and GitHub organisation or team membership is not consulted: Genkan asks
  GitHub for no scope and reads only the account's numeric ID. Groups still come from the
  `User` object.
- **Accounts are keyed by GitHub's numeric user ID**, never the login name or email, which can
  change hands.
- **Ordinary access only.** A GitHub sign-in proves nothing about user verification, so it
  never yields elevated groups. The `genkan-k3s-admin` context (scope `elevate`) does not offer
  GitHub and refuses to start it; elevation always needs a passkey.

## 1. Register a GitHub OAuth app

On GitHub: **Settings → Developer settings → OAuth Apps → New OAuth App** (or the same under an
organisation's settings, so the app does not depend on one person's account).

| Field | Value |
|---|---|
| Application name | for example `Genkan (genkan-k3s)`; people see it on GitHub's consent page |
| Homepage URL | `https://genkan-k3s.shared` |
| Authorization callback URL | `https://genkan-k3s.shared/upstream/github/callback` |
| Enable Device Flow | off |

The callback URL is only a browser redirect, so the host does not have to be reachable from the
internet. Genkan itself, however, calls `github.com` (code exchange) and `api.github.com`
(account ID) from its pod, so the cluster needs outbound HTTPS to both.

After registering, note the **Client ID** and generate a **client secret**.

## 2. Store the client secret

Genkan reads secrets from files in a Secret mounted at `/etc/genkan`. Create it without
putting the secret in your shell history or the process list:

```sh
read -rs GITHUB_SECRET     # paste the client secret, then Enter
printf %s "$GITHUB_SECRET" | kubectl -n genkan-system create secret generic genkan-config \
  --from-file=github-client-secret=/dev/stdin
unset GITHUB_SECRET
```

If `genkan-config` already exists, add the key instead of replacing the other secrets:
`kubectl -n genkan-system edit secret genkan-config`, or recreate it with every
`--from-literal`/`--from-file`. For the other provider, see [Google sign-in](google-sign-in.md).

## 3. Enable the provider

Re-apply the manifests with the Secret, the client ID and `--invitations` (step 4 links accounts
with invitation links). Keep your deployed image, namespace, `--config-secret` and every
existing `--serve-arg` when regenerating; omitted options are not preserved by
`genkanctl manifests`.

```sh
GITHUB_CLIENT_ID=Ov23li...   # from step 1; not a secret
genkanctl manifests --image docker.io/library/genkan:dev \
  --config-secret genkan-config \
  --serve-arg=--invitations \
  --serve-arg=--github-client-id=$GITHUB_CLIENT_ID \
  --serve-arg=--github-client-secret-file=/etc/genkan/github-client-secret \
  | kubectl apply --server-side -f -
kubectl -n genkan-system rollout status deploy/genkan
```

The pod runs with `fsGroup` set so that it can read the mounted files (mode 0440). The sign-in
page now shows **Continue with GitHub**.

## 4. Link GitHub accounts to users

For a [new person](managing-users.md#add-someone), send an invitation as described in
Managing users. For an [existing user](managing-users.md#add-another-passkey-or-device),
invite the same username to add a credential without changing their existing account.
On either link, choose **Continue with GitHub** and select the intended GitHub account
instead of enrolling a passkey. Each link adds one credential; use another link to add a
passkey or another account.

### Directly, as the cluster admin

When you know the person's GitHub account, you can create the `Credential` yourself. Its name
must match Genkan's derivation from the issuer and numeric ID, because Genkan looks up the
account by name. Include the user label so the shared management commands can find it, and an
owner reference to the `User`'s current UID so Kubernetes removes it when the `User` is deleted.

**Warning:** without the owner reference, the credential outlives the `User` and signs in as
any later `User` with the same name. Garbage collection is eventual even with the reference;
follow the [safe removal order](managing-users.md#suspend-or-remove-someone).

```sh
LOGIN=octocat
USER_NAME=alice                                   # an existing User object
USER_UID=$(kubectl -n genkan-system get users.genkan.engawahq.dev "$USER_NAME" -o jsonpath='{.metadata.uid}')
GH_ID=$(curl -fsS https://api.github.com/users/$LOGIN | jq -r .id)
NAME=c-$(printf 'genkan/external/v1/https://github.com\0%s' "$GH_ID" | sha256sum | cut -d' ' -f1)
kubectl apply -f - <<EOF
apiVersion: genkan.engawahq.dev/v1alpha1
kind: Credential
metadata:
  name: $NAME
  namespace: genkan-system
  labels: {genkan.engawahq.dev/user: "$USER_NAME"}
  ownerReferences:
    - {apiVersion: genkan.engawahq.dev/v1alpha1, kind: User, name: $USER_NAME, uid: $USER_UID}
spec:
  type: GitHub
  user: $USER_NAME
  external: {issuer: "https://github.com", subject: "$GH_ID"}
EOF
```

Check the ID before applying; a wrong ID links someone else's account.

## 5. Try it

On the Mac, sign out of the cached session first so that kubelogin opens the browser again:

```sh
rm -rf ~/.kube/cache/oidc-login
export KUBECONFIG=~/.kube/genkan-k3s.yaml
kubectl auth whoami          # choose "Continue with GitHub"; the user is genkan:<username>
```

For a passkey sign-in, `kubectl auth whoami` lists `genkan.engawahq.dev/amr` as `swk`, `mfa`;
a GitHub sign-in has no `amr` values. The admin context still asks for a passkey:

```sh
kubectl --context genkan-k3s-admin auth whoami
```

## Removing access

Use Managing users to [see and revoke credentials](managing-users.md#see-and-revoke-credentials),
[end existing sessions](managing-users.md#sign-someone-out), or
[suspend or remove a user](managing-users.md#suspend-or-remove-someone). Deleting a GitHub
credential stops new sign-ins, but does not end the sessions it already started.

To turn GitHub sign-in off, re-apply the manifests without the two `--github-*` arguments,
keeping all other deployment options, and delete the OAuth app on GitHub. This does not
remove stored credentials or end existing Genkan sessions; use the shared management flows
if you want to revoke them too.

## Troubleshooting

- **GitHub says the redirect URI is not associated with the application:** the callback URL in
  the OAuth app must be exactly `<issuer>/upstream/github/callback`.
- **"This account is not linked to any user here":** the GitHub account has no `Credential`;
  link it with step 4. A credential created by hand with a wrong name or ID shows the same
  message.
- **"This sign-in needs a passkey":** the request asked for elevation; use a passkey.
- **"This provider is not enabled":** the Deployment lacks `--github-client-id`; check
  `kubectl -n genkan-system get deploy genkan -o jsonpath='{.spec.template.spec.containers[0].args}'`.
- **The pod cannot read `/etc/genkan/...`:** check that `--config-secret genkan-config`
  mounts the Secret, that it contains `github-client-secret`, and that
  `--github-client-secret-file` points to `/etc/genkan/github-client-secret`. If you customize
  the pod's security context or mounts, retain the generated `fsGroup` and read permissions.
- **Sign-in fails after GitHub returns:** the pod cannot reach `github.com` or
  `api.github.com`; check egress (proxy, firewall, NetworkPolicy) and
  `kubectl -n genkan-system logs deploy/genkan`.

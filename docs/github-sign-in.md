# Sign in with GitHub

Genkan can offer "Continue with GitHub" next to the passkey on its sign-in page. This guide
adds it to the cluster from [get-started.md](get-started.md); the commands assume that setup
(issuer `https://genkan-k3s.shared`, namespace `genkan-system`, `genkanctl` and `kubectl` on the
VM inside `nix develop`).

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
putting the secret in your shell history:

```sh
read -rs GITHUB_SECRET     # paste the client secret, then Enter
kubectl -n genkan-system create secret generic genkan-config \
  --from-literal=github-client-secret="$GITHUB_SECRET"
unset GITHUB_SECRET
```

If `genkan-config` already exists (SMTP, SCIM or Google files), add the key to it instead:
`kubectl -n genkan-system edit secret genkan-config`, or recreate it with every
`--from-literal`/`--from-file`.

## 3. Enable the provider

Re-apply the manifests with the Secret, the client ID and `--invitations` (step 4 links accounts
with invitation links). `genkanctl manifests` is declarative: pass every `--serve-arg` you want
to keep each time.

```sh
ISSUER=https://genkan-k3s.shared
GITHUB_CLIENT_ID=Ov23li...   # from step 1; not a secret
genkanctl manifests --issuer $ISSUER --image docker.io/library/genkan:dev \
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

Pick one of three ways.

### A new person, with an invitation

```sh
genkanctl invite --issuer $ISSUER --username alice --display-name "Alice" --group developers
```

Send Alice the printed link (valid for 7 days, single use). On that page she can create a
passkey or choose **Continue with GitHub**; either links the credential to `alice`. A
redeemed link is gone; issue another invitation to link a second credential.

`developers` is just a group name. Kubernetes sees it as `genkan:developers`, so give it rights
the usual way, for example read access to one namespace:

```sh
kubectl create namespace demo --dry-run=client -o yaml | kubectl apply -f -
kubectl -n demo create rolebinding developers-view --clusterrole=view --group=genkan:developers
```

### An existing user, such as `admin`

Invite the same username. The existing `User` and its passkeys stay as they are; the link only
adds a credential.

```sh
genkanctl invite --issuer $ISSUER --username admin
```

Open the link and choose **Continue with GitHub**.

### Directly, as the cluster admin

When you know the person's GitHub account, create the `Credential` yourself. Its name must be
derived from the issuer and the numeric ID exactly as Genkan derives it, because Genkan looks
the account up by name. Give it an owner reference to the User's current UID, as Genkan does
for credentials it creates, so that deleting the User also deletes the credential; without
one, the credential outlives the User and signs in as any later User given the same name:

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

Credentials are immutable; revoking one is deleting it.

```sh
kubectl -n genkan-system get credentials -o custom-columns=NAME:.metadata.name,TYPE:.spec.type,USER:.spec.user
kubectl -n genkan-system delete credential <name>
```

Deleting a credential stops new sign-ins with it. Sessions it already started live on as
refresh-token grants; end them too by deleting the user's grants:

```sh
kubectl -n genkan-system get grants -o json \
  | jq -r '.items[] | select(.spec.user == "alice") | .metadata.name' \
  | xargs -r kubectl -n genkan-system delete grant
```

An access token already issued stays valid until it expires (10 minutes by default), because
kube-apiserver cannot revoke tokens. To lock a person out entirely, set `spec.disabled: true` on
their `User`.

To turn GitHub sign-in off, re-apply the manifests without the two `--github-*` arguments and
delete the OAuth app on GitHub.

## Troubleshooting

- **GitHub says the redirect URI is not associated with the application:** the callback URL in
  the OAuth app must be exactly `<issuer>/upstream/github/callback`.
- **"This account is not linked to any user here":** the GitHub account has no `Credential`;
  link it with step 4. A credential created by hand with a wrong name or ID shows the same
  message.
- **"This sign-in needs a passkey":** the request asked for elevation; use a passkey.
- **"This provider is not enabled":** the Deployment lacks `--github-client-id`; check
  `kubectl -n genkan-system get deploy genkan -o jsonpath='{.spec.template.spec.containers[0].args}'`.
- **The pod restarts and logs `Permission denied` for `/etc/genkan/...`:** either the manifests
  came from a `genkanctl` older than the `fsGroup` fix (rebuild `genkanctl` and apply them
  again), or the image was built before `build-image.sh` staged `/etc` with mode 0755: older
  images have a 0444 `/etc` that the non-root user cannot enter, which also hides the CA bundle.
  Rebuild the image, import it and restart the Deployment.
- **Sign-in fails after GitHub returns:** the pod cannot reach `github.com` or
  `api.github.com`; check egress (proxy, firewall, NetworkPolicy) and
  `kubectl -n genkan-system logs deploy/genkan`.

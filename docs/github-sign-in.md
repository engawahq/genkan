# Sign in with GitHub

Genkan can show **Continue with GitHub** next to the passkey button on its sign-in page, so
people can sign in with their GitHub account for everyday access. This guide adds it to the
cluster from [Get started](get-started.md). Run the commands on the server inside `nix develop`,
with your own issuer:

```sh
export GENKAN_ISSUER=https://genkan.example.test
```

## What to expect

- **You decide who can sign in.** A GitHub account works only after it has been linked to a
  Genkan user (step 4). Signing in with an unknown account creates nothing, and GitHub
  organisations and teams play no part. Groups still come from the `User`.
- **Genkan remembers GitHub's numeric account ID**, not the login name or email, because those
  can pass to someone else.
- **Not for admin rights.** GitHub cannot tell Genkan whether the person proved their presence
  with a fingerprint or PIN, so admin sign-ins (such as the `genkan-k3s-admin` context) always
  need a passkey and do not offer GitHub.

## 1. Register a GitHub OAuth app

On GitHub: **Settings → Developer settings → OAuth Apps → New OAuth App** (or the same under an
organisation's settings, so the app does not depend on one person's account).

| Field | Value |
|---|---|
| Application name | for example `Genkan (genkan-k3s)`; people see it on GitHub's consent page |
| Homepage URL | `https://genkan.example.test` |
| Authorization callback URL | `https://genkan.example.test/upstream/github/callback` |
| Enable Device Flow | off |

The callback URL only redirects the browser, so GitHub does not need to reach your cluster.
The other way round, Genkan's pod calls `github.com` and `api.github.com`, so the cluster needs
outbound HTTPS to both.

After registering, note the **Client ID** and generate a **client secret**.

## 2. Store the client secret

Genkan reads secrets from files in a Kubernetes Secret, mounted at `/etc/genkan`. Create it
like this, so the secret stays out of your shell history and the process list:

```sh
read -rs GITHUB_SECRET     # paste the client secret, then Enter
printf %s "$GITHUB_SECRET" | kubectl -n genkan-system create secret generic genkan-config \
  --from-file=github-client-secret=/dev/stdin
unset GITHUB_SECRET
```

If `genkan-config` already exists (for example with the [Google](google-sign-in.md) secret),
add the new key to it with `kubectl -n genkan-system edit secret genkan-config` instead, so the
other keys stay.

## 3. Enable the provider

Regenerate the deployment with the Secret and the client ID. `genkanctl manifests` does not
remember earlier options, so pass everything you installed with (image, namespace, other
`--serve-arg`s) plus the new ones. The command below matches [Get started](get-started.md),
including `--invitations`, which step 4 needs.

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

The sign-in page now shows **Continue with GitHub**.

## 4. Link GitHub accounts to users

People link their GitHub account with the same one-time link they would use for a passkey:

- for a new person, [invite them](managing-users.md#add-someone);
- for an existing user, [invite the same username again](managing-users.md#add-another-passkey-or-device).

On the link, they choose **Continue with GitHub** instead of creating a passkey, and sign in to
the GitHub account they want to use. Each link adds one passkey or one account; send another
link to add more.

### Advanced: link an account without a link

If you know the person's GitHub login, you can create the `Credential` yourself. The object has
to be exactly right:

- its **name** is derived from GitHub's numeric account ID, because Genkan looks the account up
  by name;
- the **user label** lets the commands in [Managing users](managing-users.md) find it;
- the **owner reference** ties it to the `User`, so it is cleaned up when the user is deleted.

> [!WARNING]
> Without the owner reference, the credential outlives the `User`. Anyone later given the same
> username would be signed in by this GitHub account. Even with it, cleanup is not immediate;
> follow the [removal order](managing-users.md#suspend-or-remove-someone).

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

Check `$GH_ID` before applying: a wrong ID links someone else's account.

## 5. Try it

On your computer, sign out of the cached session first so that kubelogin opens the browser again:

```sh
rm -rf ~/.kube/cache/oidc-login
export KUBECONFIG=~/.kube/genkan-k3s.yaml
kubectl auth whoami          # choose "Continue with GitHub"; the user is genkan:<username>
```

You can tell the two apart in `kubectl auth whoami`: after a passkey sign-in,
`genkan.engawahq.dev/amr` lists `swk` and `mfa`; after a GitHub sign-in, it is empty. The admin
context still asks for a passkey:

```sh
kubectl --context genkan-k3s-admin auth whoami
```

## Removing access

A linked GitHub account is a `Credential`, like a passkey, so the steps in Managing users
apply:

- [remove the linked account](managing-users.md#remove-a-passkey-or-linked-account) to stop
  new sign-ins with it;
- [sign the person out](managing-users.md#sign-someone-out) to end sessions it already started;
- [suspend or remove the user](managing-users.md#suspend-or-remove-someone) to take away all
  access.

To turn GitHub sign-in off, regenerate the deployment without the two `--github-*` options
(keep all the others), and delete the OAuth app on GitHub. Linked accounts and running
sessions stay until you remove them as above.

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

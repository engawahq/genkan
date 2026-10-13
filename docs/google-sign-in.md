# Sign in with Google

Genkan can show **Continue with Google** next to the passkey button on its sign-in page, so
people can sign in with their Google account for everyday access. This guide assumes Genkan is
installed in the `genkan-system` namespace and that you run `genkanctl` and `kubectl` with the
cluster admin's kubeconfig.

## Before you start

**You need a real domain.** Google accepts only redirect URIs on a public domain
([rules][redirect-rules]), so the local `genkan.example.test` name from
[Get started](get-started.md) does not work here. The examples use `https://genkan.example.com`;
replace it with your issuer throughout. The issuer is fixed when you install Genkan: the same
name has to appear in Genkan's deployment, its TLS certificate and kube-apiserver's
configuration. Changing `GENKAN_ISSUER` in your shell later does not move an existing
installation.

```sh
export GENKAN_ISSUER=https://genkan.example.com
```

**Network access.** Browsers must reach Genkan at that name and trust its certificate. Genkan's
pod needs outbound HTTPS to `oauth2.googleapis.com` and `www.googleapis.com`.

## What to expect

- **You decide who can sign in.** A Google account works only after it has been linked to a
  Genkan user (step 3). Genkan never creates users on first sign-in, and never matches accounts
  by email address, name or Workspace domain. Groups and display names come from the `User`.
- **Genkan remembers Google's stable account ID** (`sub`), and asks Google for nothing else: no
  email address, no profile.
- **Not for admin rights.** Even if the Google account uses two-factor authentication, admin
  sign-ins always need a passkey.

## 1. Register a Google OAuth client

Follow Google's [OpenID Connect setup][google-oidc] and [consent-screen guide][google-consent]:

1. Select or create a project in Google Cloud Console. Under **Google Auth platform →
   Branding**, configure the app name, support email and contact details.
2. Under **Audience**, choose **Internal** to allow only your Google Workspace organization,
   or **External** for any Google account. People still need a linked Genkan user either way.
   Google's [publishing rules][google-audience] limit apps in testing mode, but not apps that
   ask only for `openid`, as Genkan does.
3. Under **Data Access**, declare only the `openid` scope; no Google API data access is needed.
4. Under **Clients → Create Client**, choose **Web application**. Give it a name and add this
   **Authorized redirect URI**, substituting your issuer:

   ```text
   https://genkan.example.com/upstream/google/callback
   ```

   It must be exactly `<issuer>/upstream/google/callback`. Leave **Authorized JavaScript
   origins** empty.
5. Note the **Client ID** and the **client secret**. Genkan needs the secret itself, not the
   JSON file Google offers to download.

## 2. Store the secret and enable Google

Genkan reads secrets from files in a Kubernetes Secret, mounted at `/etc/genkan`. Create it
like this, so the secret stays out of your shell history and the process list:

```sh
read -rs GOOGLE_SECRET     # paste the client secret, then Enter
printf %s "$GOOGLE_SECRET" | kubectl -n genkan-system create secret generic genkan-config \
  --from-file=google-client-secret=/dev/stdin
unset GOOGLE_SECRET
```

If `genkan-config` already exists (for example with the
[GitHub secret](github-sign-in.md#2-store-the-client-secret)), add the `google-client-secret`
key to it instead, with `kubectl -n genkan-system edit secret genkan-config` (values are
base64-encoded) or your secret-management tool.

Then regenerate the deployment with the Secret and the two Google options. `genkanctl
manifests` does not remember earlier options, so pass everything you installed with (image,
namespace, other `--serve-arg`s) plus the new ones. Keep `--invitations`: step 3 needs it.

```sh
GOOGLE_CLIENT_ID=1234567890-example.apps.googleusercontent.com   # replace with your client ID
genkanctl manifests --image docker.io/library/genkan:dev \
  --config-secret genkan-config \
  --serve-arg=--invitations \
  --serve-arg=--google-client-id=$GOOGLE_CLIENT_ID \
  --serve-arg=--google-client-secret-file=/etc/genkan/google-client-secret \
  | kubectl apply --server-side -f -
kubectl -n genkan-system rollout status deploy/genkan
```

The sign-in page now shows **Continue with Google**.

## 3. Link an account and sign in

People link their Google account with the same one-time link they would use for a passkey:

- for a new person, [invite them](managing-users.md#add-someone);
- for an existing user, [invite the same username again](managing-users.md#add-another-passkey-or-device).

On the link, they choose **Continue with Google** and pick the Google account they want to use.
Whoever opens the link controls that Genkan user, so make sure it reaches the right person.
Each link adds one passkey or one account; send another link to add more. A Google account can
be linked to only one user at a time.

To try it with the `kubectl` setup from Get started, clear the cached session so kubelogin
opens the browser again:

```sh
rm -rf ~/.kube/cache/oidc-login
kubectl auth whoami          # choose "Continue with Google"
```

The admin context still asks for a passkey.

## Later changes

- **Remove someone's access.** A linked Google account is a `Credential`, like a passkey.
  [Remove it](managing-users.md#remove-a-passkey-or-linked-account) to stop new sign-ins, and
  [sign the person out](managing-users.md#sign-someone-out) to end running sessions. To take
  away all access, [suspend or remove the user](managing-users.md#suspend-or-remove-someone).
- **Replace the client secret.** Genkan reads it only at startup. After updating the Secret,
  restart Genkan:

  ```sh
  kubectl -n genkan-system rollout restart deploy/genkan
  kubectl -n genkan-system rollout status deploy/genkan
  ```

- **Turn Google sign-in off.** Regenerate the deployment without the two `--google-*` options
  (keep all the others), and delete the OAuth client in Google Cloud Console if you no longer
  need it. Linked accounts and running sessions stay until you remove them as above.

## Troubleshooting

- **`redirect_uri_mismatch`:** check the client ID and the exact authorized redirect URI,
  including scheme, hostname and `/upstream/google/callback`. A local name such as
  `genkan.example.test` does not meet Google's domain rules.
- **`org_internal` or a Google access-policy error:** check the app's Audience and the account's
  organization policies; see [Google's audience rules][google-audience].
- **"This account is not linked to any user here":** use an invitation to link the selected
  Google account; a matching email address or name does not suffice.
- **"This sign-in needs a passkey":** the client requested elevation; use a passkey.
- **No Google button, or the pod cannot read the secret:** check both `--google-*` options,
  `--config-secret genkan-config`, the Secret's `google-client-secret` key and the file path. If
  you customised the pod's security context, keep the generated `fsGroup`.
- **Sign-in fails after Google returns:** inspect `kubectl -n genkan-system logs deploy/genkan`
  and check pod egress to the token and signing-key hosts listed above.

[google-oidc]: https://developers.google.com/identity/openid-connect/openid-connect
[google-consent]: https://developers.google.com/workspace/guides/configure-oauth-consent
[google-audience]: https://support.google.com/cloud/answer/15549945
[redirect-rules]: https://developers.google.com/identity/protocols/oauth2/web-server#uri-validation

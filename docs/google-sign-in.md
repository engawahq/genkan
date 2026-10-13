# Sign in with Google

Genkan can offer **Continue with Google** next to the passkey on its sign-in page. This guide
assumes an installed cluster, namespace `genkan-system`, and `genkanctl` and `kubectl` running
with the cluster admin's kubeconfig.

## Before you start

Use an HTTPS issuer on a domain you control, such as `https://genkan.example.com` (replace it
with your actual issuer throughout this guide). Google's [redirect URI rules][redirect-rules]
require a hostname under a public suffix, so the local `genkan-k3s.shared` hostname from
[Get started](get-started.md) cannot be used for this provider. Choose the hostname before
installing, and use it consistently for Genkan, its TLS certificate, kube-apiserver and client
configuration. Changing only the shell variable on an existing installation does not change
its issuer.

```sh
export GENKAN_ISSUER=https://genkan.example.com
```

`genkanctl` reads `GENKAN_ISSUER`, so its commands below omit the issuer argument. When following
links to Managing users, keep your actual issuer rather than copying that guide's local example.
The browser must reach Genkan at this hostname and trust its TLS certificate. The pod needs
outbound HTTPS to `oauth2.googleapis.com` (code exchange) and `www.googleapis.com` (signing keys);
the browser visits `accounts.google.com` to sign in.

## What it does and does not do

- **Only a linked account can sign in.** Genkan does not create a user on first sign-in or match
  an account by email, display name or Workspace domain. Groups and display names come from the
  `User`, not Google.
- **The identity is Google's stable `sub`, with issuer `https://accounts.google.com`.** Genkan
  requests only `openid`, not `email` or `profile`. It validates the ID token's signature,
  issuer, client audience, expiry and nonce. It does not read or require `email_verified`;
  even a verified email address is not an account-linking rule.
- **Ordinary access only.** Google sign-in never grants elevated groups, even when the Google
  account uses MFA. Elevation requires a passkey.

## 1. Register a Google OAuth client

Follow Google's [OpenID Connect setup][google-oidc] and [consent-screen guide][google-consent]:

1. Select or create a project in Google Cloud Console. Under **Google Auth platform →
   Branding**, configure the app name, support email and contact details.
2. Under **Audience**, choose **Internal** for members of the project's Google Cloud
   organization, or **External** for other Google accounts. Google controls this restriction;
   it does not replace Genkan's account-linking requirement. Review Google's
   [audience and publishing rules][google-audience]. Its testing-mode test-user and seven-day
   authorization limits have an exception for `openid`-only sign-in, which Genkan uses.
3. Under **Data Access**, declare only the `openid` scope; no Google API data access is needed.
4. Under **Clients → Create Client**, choose **Web application**. Give it a name and add this
   **Authorized redirect URI**, substituting your issuer:

   ```text
   https://genkan.example.com/upstream/google/callback
   ```

   It must match `<issuer>/upstream/google/callback` exactly. Genkan uses a server-side code
   exchange, not a JavaScript SDK, so no authorized JavaScript origin is needed.
5. Save the **Client ID** and **client secret** securely. Genkan needs the secret string, not
   the downloaded client JSON file.

## 2. Store the secret and enable Google

For a new `genkan-config` Secret, run this in Bash to keep the secret out of shell history and
command arguments:

```sh
read -rs GOOGLE_SECRET     # paste the client secret, then Enter
printf %s "$GOOGLE_SECRET" | kubectl -n genkan-system create secret generic genkan-config \
  --from-file=google-client-secret=/dev/stdin
unset GOOGLE_SECRET
```

If the Secret already exists, add `google-client-secret` with your secret-management tool or
`kubectl -n genkan-system edit secret genkan-config` (Secret `data` values are base64-encoded).
Do not replace its other keys, such as the [GitHub secret](github-sign-in.md#2-store-the-client-secret).

Regenerate the manifests with both Google flags and the Secret mount. Invitation links need
`--invitations`, included here for linking accounts. **Keep your deployed image, namespace,
`--config-secret` and every existing `--serve-arg`**; omitted options are not preserved. The
image below is the local walkthrough's image, so substitute yours if different:

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

The Secret is mounted read-only at `/etc/genkan`; its key becomes the file named by
`--google-client-secret-file`. Both the client ID and secret-file flags are required. The
sign-in page now offers **Continue with Google**.

## 3. Link an account and sign in

Use [Add someone](managing-users.md#add-someone) for a new user, or
[Add another passkey or device](managing-users.md#add-another-passkey-or-device) to invite an
existing username. On the link, choose **Continue with Google**, then select the intended
Google account. Verify the person's identity before giving them a link: whoever redeems it
controls that Genkan user. Each link adds one credential, so issue a separate link for a
passkey or another account.

Genkan creates an immutable `Credential` of type `Google`, with the account's issuer and `sub`,
a user label and an owner reference to the current `User`. An account already linked here
cannot be linked again while that credential exists.

To try ordinary sign-in with the kubelogin setup from Get started, select your Genkan
kubeconfig, remove the client's cached session and start a fresh sign-in:

```sh
rm -rf ~/.kube/cache/oidc-login
kubectl auth whoami          # choose "Continue with Google"
```

Requests for the `elevate` scope still require a passkey.

## Credentials, sessions and provider changes

- To unlink an account, [delete its credential](managing-users.md#see-and-revoke-credentials).
  This stops new sign-ins but does not end existing Genkan sessions;
  [delete its grants too](managing-users.md#sign-someone-out). For complete offboarding, follow
  [Suspend or remove someone](managing-users.md#suspend-or-remove-someone).
- Genkan reads the client secret at startup. After replacing the Secret key, run
  `kubectl -n genkan-system rollout restart deploy/genkan` and wait for
  `kubectl -n genkan-system rollout status deploy/genkan`. Updating the mounted Secret alone
  does not reload the secret into the running server.
- To disable Google sign-in, regenerate the manifests without both `--google-*` arguments,
  keeping all other options, and remove the OAuth client in Google Cloud Console if it is no
  longer needed. Stored Genkan credentials and sessions remain; revoke them using the shared
  management flows when required.

## Troubleshooting

- **`redirect_uri_mismatch`:** check the client ID and the exact authorized redirect URI,
  including scheme, hostname and `/upstream/google/callback`. The local `.shared` hostname
  does not meet Google's domain rules.
- **`org_internal` or a Google access-policy error:** check the app's Audience and the account's
  organization policies; see [Google's audience rules][google-audience].
- **"This account is not linked to any user here":** use an invitation to link the selected
  Google account; a matching email address or name does not suffice.
- **"This sign-in needs a passkey":** the client requested elevation; use a passkey.
- **The provider is absent or the pod cannot read the secret:** check both Google flags,
  `--config-secret`, the Secret key and the file path. Custom pod security settings must retain
  the generated `fsGroup` and read permissions.
- **Sign-in fails after Google returns:** inspect `kubectl -n genkan-system logs deploy/genkan`
  and check pod egress to the token and signing-key hosts listed above.

[google-oidc]: https://developers.google.com/identity/openid-connect/openid-connect
[google-consent]: https://developers.google.com/workspace/guides/configure-oauth-consent
[google-audience]: https://support.google.com/cloud/answer/15549945
[redirect-rules]: https://developers.google.com/identity/protocols/oauth2/web-server#uri-validation

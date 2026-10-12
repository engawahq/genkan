# genkanctl

The Genkan admin CLI. It runs on an administrator's machine with the administrator's own
kubeconfig, never inside the cluster, and is not part of the server image. Work that needs more
rights than Genkan's service account has (installing RBAC, creating users and the setup
Secret, issuing the internal certificate) therefore happens here, with a human's credentials.

## Commands

- `genkanctl crds`: the custom resource definitions as a Kubernetes `List`, for
  `kubectl apply -f -`.
- `genkanctl rbac [--scim --scim-group <g>…]`: the namespace, service account, `Role`,
  `RoleBinding`, the admin bindings and the empty key Secret; with `--scim`, also SCIM's rules and
  admission policy.
- `genkanctl manifests --issuer <url> --image <ref>`: everything `rbac` prints plus the Service
  and the single-replica Deployment.
- `genkanctl kube-config --issuer <url> --distro <k3s|k0s|kubeadm|kubesolo|generic>`: issues the
  internal listener's certificate if needed (the CA key is discarded), prints the kube-apiserver
  `AuthenticationConfiguration` on stdout and how to install it on stderr.
- `genkanctl setup-link --issuer <url> [--username admin] [--reset]`: a one-time link that
  enrols a passkey for the first admin (group `admins`, elevated group `admins`), or recovers
  the account with `--reset`. It expires after 60 minutes by default.
- `genkanctl invite --issuer <url> --username <name> [--email <addr>]`: creates the `User` if
  needed and a one-time enrolment link (7 days by default), printed, or mailed by the server.

Results (JSON, YAML or a link) go to stdout and messages to stderr, so commands compose with
`kubectl apply -f -`.

## Upgrading to UID-pinned authentication

This is a destructive cutover, not a transparent migration. Stop the old server and mailer,
then apply the updated CRDs and use the upgraded CLI. `Credential`, `Grant`, and `Invitation`
records require the original `spec.userUid`; the setup Secret requires `data.user-uid`.
Never copy a current User UID into a legacy record: the same name may now identify someone else.

Before starting the upgraded mailer, administrators **must remove every unverifiable legacy
Invitation, Grant, and `genkan-setup` Secret**, purge legacy credentials, and arrange passkey
re-enrollment or upstream-account re-linking. One legacy Invitation lacking `userUid` causes
the typed invitation LIST to fail, blocking the mailer for all invitations, not just that one.
Neither the mailer nor authentication backfills ownership.

Use `setup-link --reset` to purge a User's labeled credentials and grants and issue a fresh
UID-bound setup link; counting and deletion do not decode legacy specs. Delete obsolete
invitations and setup Secrets explicitly with administrator credentials. For re-enrollment,
run the upgraded server without SMTP configured (omit both `--smtp-url`/`GENKAN_SMTP_URL` and
`--mail-from`/`GENKAN_MAIL_FROM`), keep `--invitations` enabled if invitations are needed, and
deliver new links directly. Complete re-enrollment and re-linking before enabling the mailer.
Existing signed access and ID tokens expire normally; this cleanup does not revoke them.


## Place in the workspace

Depends on `genkan-core` and `genkan-k8s`. Nothing depends on it.

## Key properties

- **Least privilege by default.** The installed bindings give `genkan:admins` the built-in
  `view` role and `cluster-admin` only to `genkan:elevated:admins`, which appears only in short
  tokens issued right after a passkey sign-in.
- **Secrets stay hashed.** Setup and invitation tokens are 256-bit random values; only their
  SHA-256 is written to the cluster, and the link carries the token in the URL fragment.
- **Single use.** Redeeming a setup link or invitation deletes its object with `uid` and
  `resourceVersion` preconditions, so only one redemption can succeed; a new setup link
  invalidates the previous one.

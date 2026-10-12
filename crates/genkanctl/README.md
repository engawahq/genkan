# genkanctl

The Genkan admin CLI. It runs on an administrator's machine with the administrator's own
kubeconfig, never inside the cluster, and is not part of the server image. Work that needs more
rights than Genkan's service account has (installing RBAC, creating users and the setup
Secret, issuing the internal certificate) therefore happens here, with a human's credentials.

## Commands

- `genkanctl crds`: the custom resource definitions as a Kubernetes `List`, for
  `kubectl apply -f -`.
- `genkanctl rbac`: the namespace, service account, `Role`, `RoleBinding`, the admin bindings and
  the empty key Secret.
- `genkanctl manifests --issuer <url> --image <ref>`: everything `rbac` prints plus the Service
  and the single-replica Deployment.
- `genkanctl kube-config --issuer <url> --distro <k3s|k0s|kubeadm|kubesolo|generic>`: issues the
  internal listener's certificate if needed (the CA key is discarded), prints the kube-apiserver
  `AuthenticationConfiguration` on stdout and how to install it on stderr.
- `genkanctl setup-link --issuer <url> [--username admin] [--reset]`: a one-time link that
  enrols a passkey for the first admin (group `admins`, elevated group `admins`), or recovers
  the account with `--reset`. It expires after 60 minutes by default.
- `genkanctl invite --issuer <url> --username <name>`: creates the `User` if needed and a
  one-time enrolment link (7 days by default), printed for you to send.

Results (JSON, YAML or a link) go to stdout and messages to stderr, so commands compose with
`kubectl apply -f -`.

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

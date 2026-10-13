# genkanctl

The Genkan admin CLI. It runs on an administrator's machine with the administrator's own
kubeconfig, never inside the cluster, and is not part of the server image. Work that needs more
rights than Genkan's service account has (installing RBAC, creating users and the setup
Secret, issuing the internal certificate) therefore happens here, with a human's credentials.

## Commands

Set the public issuer URL before running commands that need it:

```sh
export GENKAN_ISSUER=https://auth.example.com
```

Replace the example URL with your own issuer. `genkanctl` reads `GENKAN_ISSUER` for
`manifests`, `kube-config`, `setup-link` and `invite`, so those commands need no issuer flag.

- `genkanctl crds`: the custom resource definitions as a Kubernetes `List`, for
  `kubectl apply --server-side -f -`.
- `genkanctl rbac`: the namespace, service account, `Role`, `RoleBinding`, the admin bindings and
  the empty key Secret.
- `genkanctl manifests --image <ref>`: everything `rbac` prints plus the Service
  and the single-replica Deployment.
- `genkanctl kube-config --distro <k3s|k0s|kubeadm|generic>`: issues the
  internal listener's certificate if needed (the CA key is discarded), prints the kube-apiserver
  `AuthenticationConfiguration` on stdout and how to install it on stderr.
  The `kubesolo` choice is recognized but currently unsupported.
- `genkanctl setup-link [--username admin] [--reset]`: a one-time link that
  enrols a passkey for the first admin (group `admins`, elevated group `admins`), or recovers
  the account with `--reset`, which first deletes the user's pending invitations, passkeys and
  sessions. It expires after 60 minutes by default.
- `genkanctl invite --username <name>`: creates the `User` if needed and a
  one-time enrolment link (7 days by default), printed for you to send.
- `genkanctl client create <client-id> --type <public|confidential> --redirect-uri <uri>`:
  prints an `OAuthClient` after checking it against the same rules as the CRD schema. A
  confidential client gets a generated 256-bit secret, printed once on stderr; the object holds
  only its hash. See [Registering clients](../../docs/clients.md).

Results (JSON, YAML or a link) go to stdout and messages to stderr, so commands compose with
`kubectl apply -f -`.

### Invite users

The server must accept invitations: enable `genkan --invitations` or set
`GENKAN_INVITATIONS=true` in its Deployment. When generating the Deployment, pass
`--serve-arg=--invitations` to `genkanctl manifests`.

```sh
genkanctl invite --username alice --display-name 'Alice' \
  --group developers --elevated-group operators --valid-for 1d
```

`--group` and `--elevated-group` are repeatable. Together with `--display-name`, they apply
**only when creating a new user**; inviting an existing user does not change their name or
groups. Edit that user's `User` resource to change those fields. Ordinary groups appear to
Kubernetes as `genkan:<group>`; elevated groups appear as `genkan:elevated:<group>` only
after a passkey sign-in requesting the `elevate` scope. `--valid-for` controls how long the
link can be redeemed (default `7d`). Send the printed link privately.

### Configure token limits and certificates

`kube-config` generates a maximum accepted token lifetime of `1h` and an elevated-token
maximum of `5m`. If the server's `--elevated-token-lifetime` is raised above its `5m` default,
set `--max-elevated-token-lifetime` to match when generating the configuration, then install
the updated configuration on kube-apiserver. For example, for a server issuing 10-minute
elevated tokens:

```sh
genkanctl kube-config --distro k3s --max-elevated-token-lifetime 10m
```

For the default internal discovery mode, newly issued certificates are valid for `365d`.
Use `--certificate-validity` to change that lifetime. A usable existing certificate is
reused; changing the lifetime alone does not replace it. To force a new certificate:

```sh
genkanctl kube-config --distro k3s --renew-certificate --certificate-validity 365d
```

Renewal creates a new CA as well as a serving certificate. Install the newly printed
`AuthenticationConfiguration` on kube-apiserver so it trusts the new CA. Certificate flags
do not issue a certificate when using `--discovery public`. See the
[deployment guide](../../docs/get-started.md) for installation steps.

## Place in the workspace

Depends on `genkan-core` and `genkan-k8s`. Nothing depends on it.

## Key properties

- **Least privilege by default.** The installed bindings give `genkan:admins` the built-in
  `view` role and `cluster-admin` only to `genkan:elevated:admins`, which appears only in short
  tokens issued right after a passkey sign-in.
- **Secrets stay hashed.** Setup and invitation tokens and client secrets are 256-bit random
  values; only their SHA-256 is written to the cluster, and a link carries its token in the URL
  fragment.
- **Single use.** Redeeming a setup link or invitation deletes its object with `uid` and
  `resourceVersion` preconditions, so only one redemption can succeed; a new setup link
  invalidates the previous one.

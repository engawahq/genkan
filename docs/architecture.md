# Architecture

Genkan (玄関, the entrance of a Japanese house) is a passkey-first OpenID Connect issuer for
self-managed Kubernetes clusters (k3s, k0s, kubeadm). kube-apiserver verifies Genkan's tokens
itself through [Structured Authentication Configuration][kep-3331], so people sign in with a
passkey instead of carrying a long-lived admin kubeconfig that cannot be revoked. Any OpenID
Connect client (Argo CD, Grafana, Headlamp, …) can use the same issuer.

## Security properties

- **No passwords.** Passkeys (WebAuthn, user verification required) are the primary credential;
  GitHub and Google accounts can be linked as alternatives for ordinary access.
- **Least privilege by default.** A normal token carries ordinary groups. Administrative groups
  (`genkan:elevated:<group>`) exist only in a non-refreshable token of at most five minutes,
  issued right after a passkey sign-in that asks for elevation, and kube-apiserver's own
  configuration rejects any other token that carries them.
- **No standing secrets in the issuer's hands.** Tokens are short-lived and audience-bound; only
  hashes of codes, refresh tokens and links are stored; signing keys rotate on a schedule. The
  service account cannot create Secrets, bindings or users of its own choosing; SCIM writes are
  bounded by an admission policy.
- **State in Kubernetes.** Users, passkeys, clients, sessions and invitations are custom
  resources; there is no database.
- **Small.** One static binary in an otherwise empty image (about 20 MB), a few MiB of memory at
  rest; sign-in pages are server-rendered with about 1 KB of script each.

[conformance.md](conformance.md) maps every specification requirement Genkan implements to the
code and the test that proves it.

### User deletion and dependent cleanup

New Credentials (passkeys and upstream account links), Grants, Invitations and the setup
Secret carry a same-namespace User `ownerReference`, including its Kubernetes UID. Normal
cascading deletion eventually removes these objects even if a User with the same name is
recreated. Genkan uses ordinary, non-controller references without `blockOwnerDeletion`;
the server does not need permission to delete Users.

This is lifecycle cleanup, **not immediate authentication revocation**. Credential and Grant
reads do not compare owner UIDs. Until Kubernetes GC completes, an old record can still be
used against a same-name replacement User. An unhealthy GC controller can extend that window;
orphan deletion deliberately preserves dependents. Sealed authorization codes, flow cookies
and WebAuthn ceremony state are not Kubernetes objects and are outside this cleanup mechanism.
Already-issued JWTs remain usable until expiry. Do not use `--cascade=orphan` when retiring
an account, or rely on a particular GC latency as a security boundary.

See Kubernetes [Owners and Dependents](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/).
The cluster test `user_recreation_collects_only_the_original_users_dependents` verifies
eventual collection after same-name recreation and survival of the replacement's dependents.

#### Upgrading an existing alpha installation

No CRD schema change or automatic backfill is required. Old records lack owner references and
will not acquire this cleanup behavior automatically. For this unreleased alpha, use a clean
authentication-state cutover rather than assigning an old record to the current same-name User:

1. Stop Genkan (including its invitation mailer) and other authentication-state writers.
   Keep the cluster-admin kubeconfig available; this procedure removes every user's credentials,
   refresh families and outstanding enrollment links.
2. In the Genkan namespace, delete the old authentication records:

   ```sh
   kubectl -n "$GENKAN_NAMESPACE" delete credentials.genkan.engawahq.dev \
     grants.genkan.engawahq.dev invitations.genkan.engawahq.dev --all
   kubectl -n "$GENKAN_NAMESPACE" delete secret genkan-setup --ignore-not-found
   ```

3. Deploy the new image and restore the previous replica count. Restarting also invalidates
   the process-local sealed flows. Keep Users, OAuthClients, signing keys and TLS Secrets.
4. Issue fresh setup/invitation links, re-enroll passkeys and re-link upstream accounts.
   Previously issued JWTs are not revoked by deleting these records; wait for their expiry
   before treating the cutover as fully effective.


## How it fits together

```text
browser ──passkey──▶ genkan (in the cluster) ──tokens──▶ kubectl / OIDC clients
                        │  ▲                                     │
                 custom resources                       bearer token
                        ▼  │                                     ▼
                  kube-apiserver ◀──discovery + keys (internal TLS)── verifies tokens itself
```

The admin tool `genkanctl` runs on an administrator's machine with their own kubeconfig. It
prints the install manifests, writes kube-apiserver's `AuthenticationConfiguration` for the
distribution, and issues the one-time links people use to enrol a passkey.

`deploy/crds.json` and `deploy/rbac.json` are the committed outputs of `genkanctl crds` and
`genkanctl rbac`, for review in pull requests.

## Crates

The workspace is a flat `crates/` directory of small crates whose dependencies only point
downwards ([Kladov][matklad-workspaces]; acyclic, levelled dependencies after Lakos [4] and Martin
[5]). Each crate hides one design decision behind a narrow interface
([Parnas][parnas]); storage is a set of traits (ports) with in-memory and Kubernetes adapters
([Cockburn][cockburn]). The in-cluster server and the administrator's CLI are separate binaries,
as in Kanidm (`kanidmd`/`kanidm`), etcd (`etcd`/`etcdctl`) and cert-manager (`cmctl`), so code
that only an administrator should run never ships in the server image. Every crate has a README
that is also its crate-level documentation (`cargo doc --open`).

| Crate | What it holds | Depends on |
|---|---|---|
| [`genkan-core`](../crates/genkan-core) | time, cryptographic helpers, validated config values, protocol names | — |
| [`genkan-keys`](../crates/genkan-keys) | signing keys, JWK publication, JWS signing and verification, rotation | core |
| [`genkan-store`](../crates/genkan-store) | storage ports (traits, records) and in-memory adapters | core, keys |
| [`genkan-tls`](../crates/genkan-tls) | trust roots, certificate issuance, a reloadable TLS listener | core |
| [`genkan-ui`](../crates/genkan-ui) | server-rendered pages, embedded assets, translations, security headers | core |
| [`genkan-oauth`](../crates/genkan-oauth) | the OAuth 2.0 / OpenID Connect authorization server | core, keys, store, ui |
| [`genkan-signin`](../crates/genkan-signin) | passkey enrolment and sign-in, upstream providers, page routes | core, keys, store, oauth, ui |
| [`genkan-mail`](../crates/genkan-mail) | a minimal SMTP submission client for invitation links | core |
| [`genkan-scim`](../crates/genkan-scim) | SCIM 2.0 provisioning endpoints | core, store |
| [`genkan-k8s`](../crates/genkan-k8s) | custom resources, Kubernetes adapters, GC, manifests, kube-apiserver config | core, keys, store, tls |
| [`genkan`](../crates/genkan) | **binary**: the in-cluster server | all of the above |
| [`genkanctl`](../crates/genkanctl) | **binary**: the administrator's CLI | core, k8s |
| [`genkan-test-support`](../crates/genkan-test-support), [`genkan-e2e`](../crates/genkan-e2e) | test helpers; end-to-end tests on a cluster | — |

The sign-in pages' TypeScript and Tailwind sources live in [`ui/`](../ui); their built output is
committed to `crates/genkan-ui/assets` and embedded in the binary, so building Genkan needs only
Cargo.

## Development

With Nix: `nix develop` (or `direnv allow`). Without Nix: install rustup; `rust-toolchain.toml`
selects the same compiler. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the checks CI runs, the
dependency policy and how to run the cluster tests.

```sh
cargo lint                   # clippy with CI's settings
cargo nextest run --workspace
cargo doc --workspace --open # design notes and references live in the rustdoc
```

## References

1. The Kubernetes Authors, "KEP-3331: Structured Authentication Configuration."
   <https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/3331-structured-authentication-configuration>
2. A. Kladov, "Large Rust Workspaces," Aug. 22, 2021.
   <https://matklad.github.io/2021/08/22/large-rust-workspaces.html>
3. D. L. Parnas, "On the criteria to be used in decomposing systems into modules," *Commun.
   ACM*, vol. 15, no. 12, pp. 1053–1058, Dec. 1972, doi:
   [10.1145/361598.361623](https://doi.org/10.1145/361598.361623).
4. J. Lakos, *Large-Scale C++ Software Design*. Addison-Wesley, 1996.
5. R. C. Martin, *Agile Software Development, Principles, Patterns, and Practices*. Prentice
   Hall, 2002 (the Acyclic and Stable Dependencies Principles).
6. A. Cockburn, "The Hexagonal (Ports & Adapters) Architecture," 2005.
   <https://alistair.cockburn.us/hexagonal-architecture/>

[kep-3331]: https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/3331-structured-authentication-configuration
[matklad-workspaces]: https://matklad.github.io/2021/08/22/large-rust-workspaces.html
[parnas]: https://doi.org/10.1145/361598.361623
[cockburn]: https://alistair.cockburn.us/hexagonal-architecture/

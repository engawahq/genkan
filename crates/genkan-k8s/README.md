# genkan-k8s

Genkan's Kubernetes side: the custom resources that hold its state, storage adapters on them,
garbage collection of expired objects, the install manifests, and the kube-apiserver
`AuthenticationConfiguration` that makes a cluster accept Genkan's tokens.

## Contents

- [`crd`](crate::crd): `User`, `Credential`, `OAuthClient`, `Grant` and `Invitation`
  (`genkan.engawahq.dev/v1alpha1`), and why each one is a custom resource.
- [`objects`](crate::objects): the three single-use primitives behind every security-relevant
  write.
- [`keys`](crate::keys), [`directory`](crate::directory), [`credentials`](crate::credentials),
  [`grants`](crate::grants), [`setup`](crate::setup), [`users`](crate::users): the
  `genkan-keys` and `genkan-store` traits implemented on Kubernetes objects.
- [`gc`](crate::gc): deletes expired grants and invitations, driven by a metadata-only watch.
- [`rbac`](crate::rbac), [`deployment`](crate::deployment): the install manifests, generated
  from code; tests check `deploy/crds.json` and `deploy/rbac.json` against them.
- [`kube_config`](crate::kube_config), [`internal_tls`](crate::internal_tls): the
  kube-apiserver configuration and the in-cluster discovery certificate.
- [`invitations`](crate::invitations), [`setup`](crate::setup): the admin's side of
  `genkanctl invite` and `genkanctl setup-link`.

## Place in the workspace

Depends on `genkan-core`, `genkan-keys`, `genkan-store` and `genkan-tls`. Used by the `genkan`
server, the `genkanctl` admin CLI and the `genkan-e2e` tests.

## Key properties

- **No write before authentication.** Pre-login flows, WebAuthn challenges and authorization
  codes stay in sealed cookies and process memory. The API server sees one write per code
  redemption, one per refresh and one when a grant ends, so anonymous traffic cannot fill etcd
  (the failure mode of storing a request object per unauthenticated `/authorize`, seen in
  [Dex]).
- **Current authorization data, bounded misses.** The directory reads users and known clients
  directly by object name on every request; it does not cache permissions or backend errors.
  Clones share up to 1024 absent client names for five seconds of monotonic time, evicting
  oldest misses first. A newly created client can therefore take at most five seconds after a
  cached miss to appear. Each actual directory API GET emits `kubernetes_directory_lookup`
  with `resource`, `operation`, `outcome` and `latency_ms`, never raw client or user names.
- **Single use is decided by the API server.** Create with a deterministic name, update with
  `resourceVersion`, delete with `uid` and `resourceVersion` preconditions ([API concepts],
  [DeleteOptions]). Ambiguous answers fail closed. The integration tests race 64 concurrent
  requests per primitive against a real k3s API server: exactly one wins.
- **Least privilege for the server.** Genkan's service account reaches Secrets only by name
  (`get`/`update` on the key Secret, `get`/`delete` on the setup Secret, `get` on the internal
  certificate) and has no `list`, `watch` or `create` on Secrets, since `create` cannot be
  limited to a name ([RBAC]). It has nothing outside its namespace, no RBAC objects and no
  `impersonate`. A compromised Genkan can change Genkan's own state (it holds
  the signing key anyway) but cannot reach other workloads or grant itself cluster rights.
- **Least privilege for admins.** Installation binds `genkan:admins` to the built-in `view` role
  and only `genkan:elevated:admins` to `cluster-admin`. Elevated groups appear only in
  short tokens issued right after a passkey sign-in, and the generated kube-apiserver
  configuration ([KEP-3331]) rejects any other token that carries them.
- **Hashes only.** Grants, invitations, the setup token and client secrets are stored as
  SHA-256 hashes of high-entropy values; credentials hold public keys.

## References

- [API concepts] The Kubernetes Authors, "Kubernetes API Concepts: Resource versions,"
  Kubernetes documentation.
- [DeleteOptions] The Kubernetes Authors, "`DeleteOptions`," Kubernetes API reference.
- [RBAC] The Kubernetes Authors, "Using RBAC Authorization," Kubernetes documentation.
- [KEP-3331] The Kubernetes Authors, "KEP-3331: Structured Authentication Configuration,"
  kubernetes/enhancements.
- [Dex] Dex project, `storage/kubernetes/`, commit 05a2750, and issues #1091, #1292, #1969.

[API concepts]: https://kubernetes.io/docs/reference/using-api/api-concepts/
[DeleteOptions]: https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/delete-options/
[RBAC]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
[KEP-3331]: https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/3331-structured-authentication-configuration
[Dex]: https://github.com/dexidp/dex/tree/05a275057112ba93e17db21f600b756f000f1c21/storage/kubernetes

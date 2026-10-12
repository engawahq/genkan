# genkan

The Genkan server: a passkey-first OpenID Connect issuer that runs as one pod in the cluster
whose kube-apiserver accepts its tokens. This crate is the `genkan` binary plus a small library
(used by its tests) that wires configuration, storage, keys and HTTP together.

## Contents

- [`cli`](crate::cli): the flags. Every flag also has a `GENKAN_*` environment variable, which is
  what a Deployment sets most easily; a configuration file is not needed for this few values.
- [`config`](crate::config): the validated configuration, checked before the runtime starts
  (exit code 2 on error).
- [`serve`](crate::serve): starts the background tasks and the public listener.
- [`internal`](crate::internal): the in-cluster TLS listener that kube-apiserver fetches
  discovery and keys from.
- [`output`](crate::output): the only code that writes to stdout or stderr outside the logger.

## Two binaries

`genkan` is only the in-cluster server; the container image holds nothing else. Everything an
administrator does (printing the install manifests, issuing setup links and invitations,
issuing the internal certificate and printing the kube-apiserver configuration) lives in
`genkanctl`, which runs with the administrator's own kubeconfig. The server's service account
could not do those things anyway: it cannot create Secrets, users or RBAC bindings.

## Place in the workspace

Depends on every library crate: `genkan-core`, `genkan-keys`, `genkan-store`, `genkan-tls`,
`genkan-ui`, `genkan-oauth`, `genkan-signin` and `genkan-k8s`.
Nothing depends on it.

## Key properties

- **Fails closed at startup.** Signing keys are loaded or created before the port is bound; the
  Kubernetes directory's metadata watches must also publish their initial snapshots within
  30 s. Startup failure stops background watchers rather than exposing a partially initialized
  server. `/healthz` answers once the process runs, `/readyz` once keys are published.
- **Small and bounded.** A Tokio runtime with two worker threads (one would work; two keep a
  slow request from stalling the key rotator) and axum on HTTP/1.1. Every request body is at most
  16 KiB, handled within 10 s. Each business route/method service independently permits 64
  concurrent handlers, including page assets; metadata and probes use no business slots.
  Saturated services fail immediately with `503`, `Retry-After: 1` and `Cache-Control: no-store`;
  they never queue outside the timeout or borrow another route's slots. Structured
  `request_overload` logs carry cumulative rejection counts for each business subrouter.
  Per-source-IP rate limiting belongs at the ingress; see [the deployment guide].
  The end-to-end test requires the pod's working set after a sign-in to stay within 30 MiB.
- **TLS ends in front of the public listener** (ingress or gateway). The issuer is an `https`
  URL ([OIDC Discovery] §3, [RFC 8414] §2) without a path, so the OpenID and OAuth metadata
  locations coincide at the root ([RFC 8414] §3), and it must match kube-apiserver's
  `issuer.url` byte for byte.
- **Short tokens.** Access tokens live 1 minute to 1 hour ([RFC 6750] §5.3), because
  kube-apiserver cannot revoke them; elevated tokens at most 15 minutes. Signing keys stay
  published longer than the longest token, and the JWK set's `max-age` is shorter than the
  publish-ahead time.
- **Logs** are JSON on stderr; `GENKAN_LOG` takes `target=level` directives. SIGTERM drains
  in-flight requests and stops background tasks before exit.

## References

- [OIDC Discovery] N. Sakimura, J. Bradley, M. Jones, and E. Jay, "OpenID Connect Discovery 1.0
  incorporating errata set 2," OpenID Foundation, Dec. 2023.
- [RFC 8414] M. Jones, N. Sakimura, and J. Bradley, "OAuth 2.0 Authorization Server Metadata,"
  RFC 8414, IETF, Jun. 2018.
- [RFC 6750] M. Jones and D. Hardt, "The OAuth 2.0 Authorization Framework: Bearer Token
  Usage," RFC 6750, IETF, Oct. 2012.

[OIDC Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
[RFC 6750]: https://www.rfc-editor.org/rfc/rfc6750

[the deployment guide]: ../../docs/get-started.md#limit-unauthenticated-traffic-at-the-ingress

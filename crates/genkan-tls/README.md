# genkan-tls

TLS for Genkan's own connections, all on rustls with the aws-lc-rs provider.

## Contents

- [`trust`](crate::trust): the certificate authorities trusted for outgoing TLS (upstream
  identity providers): the system bundle plus an optional extra PEM file.
- [`certificate`](crate::certificate): issues a private CA and a serving certificate, and loads
  a PEM chain and key for rustls.
- [`listener`](crate::listener): a TLS listener for axum whose certificate can be replaced while
  it runs, with bounded, time-limited handshakes.

## Place in the workspace

Depends on `genkan-core`. Used by `genkan-k8s` (stores the internal certificate in a Secret and
prints the CA for kube-apiserver) and by the `genkan` server, which runs the internal listener
and builds its outgoing trust roots here.

## Why Genkan issues its own certificate

kube-apiserver must fetch Genkan's discovery document and JWK set to verify tokens. Going
through the public issuer URL makes the control plane depend on public DNS, the ingress and a
publicly trusted certificate. Instead, `issuer.discoveryURL` can point kube-apiserver at an
in-cluster address ([KEP-3331], [Kubernetes authentication]). That address must use `https`
([apiserver validation]), and kube-apiserver resolves names with the host's resolver, so cluster
DNS names such as `*.svc.cluster.local` do not resolve ([kube-apiserver OIDC], [Kubernetes DNS]).
The internal address is therefore a fixed ClusterIP (or loopback on a single node), and the
serving certificate names it as an IP SAN.

The certificate chains to a private CA that goes into kube-apiserver's
`issuer.certificateAuthority`. kube-apiserver is pinned to that CA rather than the system roots,
because anyone able to serve the internal address could otherwise hand it their own signing
keys. A CA certificate is needed even though nothing else trusts it, because Go's TLS stack
requires the chain to end in a certificate with `CA:TRUE`.

## Security properties

- The CA has path length 0 and its private key is dropped as soon as the serving certificate is
  signed, so nothing can issue another certificate under it. Replacing the certificate means a
  new CA.
- The serving certificate is ECDSA P-256, `serverAuth` only, and names exactly the given IP
  address and DNS names.
- Outgoing connections trust the system CA bundle, not a compiled-in root list:
  `webpki-roots` is licensed CDLA-Permissive-2.0, which is not OSI-approved. Connections to
  kube-apiserver do not use [`trust`](crate::trust); they trust the service account's CA only.

## References

- [KEP-3331] The Kubernetes Authors, "KEP-3331: Structured Authentication Configuration,"
  kubernetes/enhancements.
- [Kubernetes authentication] The Kubernetes Authors, "Authenticating: Using authentication
  configuration," Kubernetes documentation.
- [apiserver validation] The Kubernetes Authors,
  `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go`, tag v1.37.1.
- [kube-apiserver OIDC] The Kubernetes Authors,
  `staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go`.
- [Kubernetes DNS] The Kubernetes Authors, "DNS for Services and Pods," Kubernetes documentation.

[KEP-3331]: https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/3331-structured-authentication-configuration
[Kubernetes authentication]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
[apiserver validation]: https://github.com/kubernetes/kubernetes/blob/v1.37.1/staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go
[kube-apiserver OIDC]: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go
[Kubernetes DNS]: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/

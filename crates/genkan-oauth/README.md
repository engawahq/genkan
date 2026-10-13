# genkan-oauth

The OAuth 2.0 / OpenID Connect authorization server of Genkan: the authorization endpoint,
codes with PKCE, the token endpoint, refresh-token families, pushed authorization requests
(PAR), revocation, UserInfo and provider metadata. Its access tokens are meant to be verified
offline by kube-apiserver's structured authentication configuration.

## Entry points

- `endpoints::router`: `/authorize`, `/token`, `/par`, `/revoke` and `/userinfo`.
  `endpoints::complete_authorization` is how a sign-in method hands an authenticated user back.
- `discovery::ProviderMetadata` (the discovery document) and `metadata::router` (serves it,
  the JWK set and the health endpoints).
- `AuthorizationServer`: shared state; `Lifetimes::DEFAULT` holds the default lifetimes.
- `authorize`, `code`, `pkce`, `refresh`, `tokens`, `client_auth`, `userinfo`: the protocol
  pieces, each documented with the rules it implements.

## Workspace dependencies

Depends on `genkan-core` (clock, issuer URL, sealing and hashing), `genkan-keys` (signing keys
and JWS), `genkan-store` (the `Directory` and `GrantStore` ports) and `genkan-ui` (the error
page). Used by `genkan` (the server), `genkan-signin` (which calls `complete_authorization`),
`genkan-k8s` and the end-to-end tests.

## Security properties

- No request writes to storage before the user has authenticated. The validated request and
  the code are sealed under a key that exists only in the process; a restart fails closed.
- PKCE S256 is required for every client; `plain` is rejected (RFC 9700 §2.1.1, RFC 7636).
- Codes live 60 seconds and are single-use; a replayed code revokes what it issued
  (RFC 6749 §4.1.2).
- Refresh tokens rotate; a replayed one revokes its whole family (RFC 9700 §4.14.2). Only
  SHA-256 hashes of refresh secrets are stored.
- Access tokens (RFC 9068) and ID tokens differ in their claims, not only in `typ`, because
  kube-apiserver does not check `typ`. Each access token has exactly one audience from the
  client's allowlist.
- UserInfo resolves the immutable `sub` UID through directory metadata, then directly reads
  the user and checks the UID and disabled state. Stale index entries and recreated objects
  cannot substitute another identity. Access-token claims are unchanged; existing tokens
  remain usable without refresh.
- Elevated groups exist only in short, non-refreshable tokens issued right after a passkey
  sign-in, and only to clients registered with `allowElevation`; others get `invalid_scope`.
- Every redirect is `303 See Other` and carries `iss` (RFC 9207).

## References

- [RFC 6749] OAuth 2.0; [RFC 7636] PKCE; [RFC 9700] OAuth 2.0 Security BCP; [RFC 9068] JWT
  access tokens; [RFC 9126] PAR; [RFC 7009] revocation; [RFC 9207] issuer identification.
- [OpenID Connect Core 1.0] and [OpenID Connect Discovery 1.0]; [RFC 8414] server metadata.

[RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749
[RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636
[RFC 9700]: https://www.rfc-editor.org/rfc/rfc9700
[RFC 9068]: https://www.rfc-editor.org/rfc/rfc9068
[RFC 9126]: https://www.rfc-editor.org/rfc/rfc9126
[RFC 7009]: https://www.rfc-editor.org/rfc/rfc7009
[RFC 9207]: https://www.rfc-editor.org/rfc/rfc9207
[RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
[OpenID Connect Core 1.0]: https://openid.net/specs/openid-connect-core-1_0.html
[OpenID Connect Discovery 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html

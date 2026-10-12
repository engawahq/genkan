# genkan-signin

How a person proves who they are to Genkan: passkey enrolment with a one-time link, passkey
sign-in, sign-in with an upstream identity provider (GitHub, Google), and the routes in front of
the sign-in pages.

## Entry points

| Router | Routes |
|---|---|
| `router` | `POST /setup/options`, `POST /setup` (enrol), `POST /login/options`, `POST /login` |
| `upstream::router` | `POST /upstream/{provider}/start`, `GET /upstream/{provider}/callback` |
| `pages::router` | `GET /login`, `GET /setup`, `GET /assets/{name}` |

`passkeys` wraps webauthn-rs as the relying party, `upstream::provider` talks to GitHub and
Google, and `problem` renders errors as RFC 9457 problem details ([RFC 9457 §3][rfc9457]).

Depends on `genkan-core`, `genkan-keys` (Google ID token signatures), `genkan-store` (users,
credentials, enrolment tokens), `genkan-oauth` (the pending authorization request a sign-in
completes) and `genkan-ui` (page rendering). Used by the `genkan` server and the end-to-end
tests; `genkan-test-support` provides the software authenticator for the tests.

## Design

- **Enrolment links.** A link is `https://<issuer>/setup#token=…`: the cluster admin's setup token,
  or an invitation token `<invitation>.<secret>`. The token sits in the URL fragment, so it never
  reaches the server or proxy logs; the page script posts it. Only its SHA-256 is stored. Genkan
  never creates users or tokens; an admin does, with their own Kubernetes credentials.
- **Single use.** The token is checked (constant-time hash comparison and expiry) when the
  ceremony starts and again when it finishes. It is consumed only after the registration
  verifies, so an abandoned attempt does not burn the link, and before the credential is stored,
  through a conditional write in the store that exactly one concurrent redemption wins. A racing
  first-admin endpoint is a known failure (Pocket ID advisory [GHSA-x6w5-6mr5-mxrx][pocketid]).
- **Passkeys.** Discoverable credentials with user verification required at registration and at
  every assertion ([WebAuthn Level 3 §5.4.6, §7.1, §7.2][webauthn]), attestation `none`, and
  relying party ID equal to the issuer's host, so a passkey cannot be used on another origin.
  The assertion's user handle must be the credential owner's, but it is unsigned and is not
  itself proof of ownership: the stored credential must also name the original User object's
  Kubernetes UID, so replacing that object under the same name does not inherit the passkey. A
  passkey sign-in asserts
  `amr = ["swk", "mfa"]` ([RFC 8176 §2][rfc8176]); synced passkeys reach AAL2 in
  [NIST SP 800-63B-4][nist] terms. Every sign-in failure returns the same `passkey-failed`
  problem, so responses do not reveal which users or credentials exist.
- **Ceremony state without a write.** webauthn-rs state is sealed with a process key into the
  `__Host-genkan-webauthn` cookie (`SameSite=Strict`, five minutes), bound to its purpose; the
  ceremony ID is recorded once it verifies, so a captured response cannot be replayed.
- **Cross-site requests.** Every JSON endpoint requires `Sec-Fetch-Site: same-origin`
  ([Fetch Metadata][fetchmeta]) or, failing that header, an `Origin` equal to the issuer, plus an
  `application/json` body, as the [OWASP CSRF guidance][owasp] recommends. Cookies use the
  `__Host-` prefix ([RFC 6265bis][rfc6265bis]) because cookies lack integrity against
  related-domain attackers ([Zheng et al.][zheng], [Squarcina et al.][squarcina]).
- **Upstream providers.** An upstream account signs in only if it was linked to a user, either
  by redeeming an enrolment link with it or by an admin creating the `Credential`; nothing is
  created on first sign-in. Accounts are keyed by the provider's stable identifier (GitHub's
  numeric ID, Google's `sub`), never a login name or email. `state`, `nonce` and the PKCE
  verifier ([RFC 7636][rfc7636]) travel in a sealed `__Host-` cookie with `SameSite=Lax`, the
  strictest setting that survives the provider's redirect back. Google ID tokens are validated
  as [OpenID Connect Core 1.0 §3.1.3.7][oidc] requires.
- **Elevation is passkey-only.** Upstream sign-ins carry no `amr` value and give no evidence of
  user verification, so a request for elevated access offers no providers and refuses to start
  one (`needs-passkey`).

## References

- W3C, "Web Authentication: An API for accessing Public Key Credentials, Level 3," W3C
  Recommendation, Aug. 2026. <https://www.w3.org/TR/webauthn-3/>
- M. Jones, P. Hunt, and A. Nadalin, "Authentication Method Reference Values," RFC 8176, IETF,
  Jun. 2017. <https://www.rfc-editor.org/rfc/rfc8176>
- M. Nottingham, E. Wilde, and S. Dalal, "Problem Details for HTTP APIs," RFC 9457, IETF,
  Jul. 2023. <https://www.rfc-editor.org/rfc/rfc9457>
- N. Sakimura, J. Bradley, and N. Agarwal, "Proof Key for Code Exchange by OAuth Public
  Clients," RFC 7636, IETF, Sep. 2015. <https://www.rfc-editor.org/rfc/rfc7636>
- S. Bingler, M. West, and J. Wilander, Eds., "Cookies: HTTP State Management Mechanism,"
  Internet-Draft draft-ietf-httpbis-rfc6265bis, IETF, work in progress.
  <https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/>
- NIST, "Digital Identity Guidelines: Authentication and Authenticator Management,"
  SP 800-63B-4, Jul. 2025. <https://pages.nist.gov/800-63-4/sp800-63b.html>
- W3C, "Fetch Metadata Request Headers," W3C Working Draft.
  <https://www.w3.org/TR/fetch-metadata/>
- OWASP Foundation, "Cross-Site Request Forgery Prevention Cheat Sheet."
  <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- N. Sakimura, J. Bradley, M. Jones, B. de Medeiros, and C. Mortimore, "OpenID Connect Core 1.0
  incorporating errata set 2," OpenID Foundation, Dec. 2023.
  <https://openid.net/specs/openid-connect-core-1_0.html>
- X. Zheng, J. Jiang, J. Liang, H. Duan, S. Chen, T. Wan, and N. Weaver, "Cookies Lack
  Integrity: Real-World Implications," in *Proc. 24th USENIX Security Symp.*, 2015,
  pp. 707–721. <https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/zheng>
- M. Squarcina, P. Adão, L. Veronese, and M. Maffei, "Cookie Crumbles: Breaking and Fixing Web
  Session Integrity," in *Proc. 32nd USENIX Security Symp.*, 2023, pp. 5539–5556.
  <https://www.usenix.org/conference/usenixsecurity23/presentation/squarcina>
- Pocket ID, "Concurrent initial setup requests create multiple unauthenticated
  administrators," GitHub security advisory GHSA-x6w5-6mr5-mxrx.
  <https://github.com/pocket-id/pocket-id/security/advisories/GHSA-x6w5-6mr5-mxrx>

[webauthn]: https://www.w3.org/TR/webauthn-3/
[rfc8176]: https://www.rfc-editor.org/rfc/rfc8176
[rfc9457]: https://www.rfc-editor.org/rfc/rfc9457
[rfc7636]: https://www.rfc-editor.org/rfc/rfc7636
[rfc6265bis]: https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/
[nist]: https://pages.nist.gov/800-63-4/sp800-63b.html
[fetchmeta]: https://www.w3.org/TR/fetch-metadata/
[owasp]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
[oidc]: https://openid.net/specs/openid-connect-core-1_0.html
[pocketid]: https://github.com/pocket-id/pocket-id/security/advisories/GHSA-x6w5-6mr5-mxrx
[zheng]: https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/zheng
[squarcina]: https://www.usenix.org/conference/usenixsecurity23/presentation/squarcina

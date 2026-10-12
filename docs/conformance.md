# Conformance

This file maps every MUST and SHOULD that Genkan implements to the code that implements it and
the test that proves it. Normative words follow RFC 2119 and RFC 8174. The design reasons and the
full citations are in each crate's documentation (`cargo doc --workspace --open`).

Status values: **Met** (code and test), **Partial** (explained in the row), **Not implemented**,
**N/A** (with the reason).

Code paths are relative to `crates/`. Tests are given as `crate: module::tests::name` for unit
tests and `crate/tests/file.rs: name` for integration tests. Tests marked *(cluster)* run against
k3s v1.36.5 (`--run-ignored only`); *(e2e)* is `genkan-e2e/tests/e2e.rs`, which runs Genkan from
its container image.

## Summary by specification

| Specification | Version / status (2026-10) | Status |
|---|---|---|
| OpenID Connect Discovery 1.0 | Final (errata set 2) | Met |
| RFC 8414 OAuth 2.0 Authorization Server Metadata | RFC | Met |
| RFC 7515 JWS, RFC 7517 JWK, RFC 7518 JWA, RFC 7638 thumbprints | RFC | Met |
| RFC 7519 JWT, RFC 8725 JWT BCP, RFC 9068 JWT access tokens | RFC | Met |
| KEP-3331 Structured Authentication Configuration (`apiserver.config.k8s.io/v1`) | GA in Kubernetes 1.34 | Met (k3s, k0s with a worker on each controller, kubeadm; KubeSolo cannot pass the flag) |
| RFC 6749 OAuth 2.0 (authorization code, refresh) | RFC | Met |
| RFC 7636 PKCE | RFC | Met (S256 only) |
| RFC 9700 OAuth 2.0 Security BCP | BCP 240 | Partial: sender-constrained tokens (DPoP) not implemented |
| RFC 6750 Bearer token usage | RFC | Met for UserInfo |
| RFC 8707 Resource Indicators | RFC | Met (one resource per request) |
| RFC 7009 Token Revocation | RFC | Met (refresh tokens; access tokens answered with `unsupported_token_type`) |
| RFC 9126 PAR | RFC | Met |
| RFC 9207 Authorization server issuer identification | RFC | Met |
| OpenID Connect Core 1.0 | Final (errata set 2) | Partial: no single sign-on sessions, so every authorization request asks for a sign-in |
| W3C WebAuthn Level 3 | Recommendation | Met for registration, discoverable sign-in and conditional mediation; a server-side test with a forged UV flag is open |
| NIST SP 800-63B-4 | Final, Jul. 2025 | Partial: user-verified passkeys (AAL2-capable); no sessions to time out yet |
| Cookies (draft-ietf-httpbis-rfc6265bis) | Draft | Met for the `__Host-` cookies used |
| RFC 9457 Problem Details | RFC | Met for the sign-in endpoints |
| RFC 8176 Authentication Method Reference values | RFC | Met (`swk`, `mfa` for passkeys) |
| WCAG 2.2 AA | W3C Recommendation | Partial: contrast computed and met for every colour pair used; no automated browser audit or screen-reader pass yet |
| RFC 7643 / RFC 7644 SCIM 2.0 | RFC | Partial: Users and Groups with GET/POST/PUT/PATCH/DELETE and `eq` filters; no bulk, sorting or ETags (advertised as unsupported) |
| RFC 6409, RFC 8314, RFC 3207, RFC 4616 mail submission | RFC | Met for what the invitation mailer uses |
| OpenID Connect RP-Initiated Logout 1.0 | Final | Not implemented (no sessions) |
| OpenID Connect Back-Channel Logout 1.0 | Final | Not implemented |
| RFC 9449 DPoP | RFC | Not implemented: kube-apiserver accepts only bearer tokens |
| RFC 9396 Rich Authorization Requests | RFC | N/A: kube-apiserver cannot evaluate `authorization_details`; not advertised |
| RFC 9470 Step-up Authentication Challenge | RFC | N/A: kube-apiserver never sends the challenge. Elevation uses short-lived elevated groups instead |
| OAuth 2.1 (draft-ietf-oauth-v2-1) | Draft | Followed where it tightens OAuth 2.0 (PKCE always, S256 only) |
| OpenID Foundation conformance suite, `oidcc-basic-certification-test-plan` | — | Not run: the suite's browser automation cannot perform a passkey ceremony, and Genkan has no password login to give it |

## Repository requirements

| Requirement | Code | Check | Status |
|---|---|---|---|
| `unsafe_code = "forbid"` | `Cargo.toml [workspace.lints.rust]`; `#![forbid(unsafe_code)]` in both binaries | CI `clippy`, `unsafe-report` | Met |
| Only OSI-approved licences | `deny.toml [licenses]` | CI `cargo-deny` | Met |
| Known vulnerabilities rejected | `deny.toml [advisories]` | CI `cargo-deny` | Met |
| Dependency `unsafe`/native code listed for approval | `scripts/unsafe-report.sh`, `supply-chain/unsafe-allowlist.toml` | CI `unsafe-report` | Met |
| clippy pedantic + restriction set, rustfmt | `Cargo.toml [workspace.lints]`, `clippy.toml`, `rustfmt.toml` | CI `clippy`, `format`, `docs` | Met |
| DCO sign-off | `CONTRIBUTING.md`, `scripts/check-dco.sh` | CI `dco` | Met |
| One toolchain source for rustup and Nix | `rust-toolchain.toml`, `flake.nix` | `nix develop` hash check | Met |
| Image: static binary, non-root, no shell | `Containerfile`, `genkan-k8s/src/deployment.rs` | `genkan-k8s: deployment::tests::deployment_is_locked_down`; *(e2e)* | Met |
| Image size and idle memory measured in CI | `scripts/build-image.sh`, e2e measurement | CI `kubernetes` job summary | Met (about 20 MB; pod working set within the 30 MiB budget) |
| Image signing (Sigstore) and SBOM | — | — | Not implemented (no release pipeline yet) |

## OpenID Connect Discovery 1.0 and RFC 8414

| § | Requirement | Level | Code | Test | Status |
|---|---|---|---|---|---|
| Disc. 3 | `issuer`: https, no query or fragment | REQUIRED | `genkan-core/src/config.rs` `BaseUrl::parse` | `genkan-core: config::tests::rejects_everything_else` | Met |
| Disc. 3 | `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri` (https) | REQUIRED | `genkan-oauth/src/discovery.rs` | `genkan-oauth: discovery::tests::required_members_are_present` | Met |
| Disc. 3 | `id_token_signing_alg_values_supported` includes RS256 | MUST | `discovery.rs`, `genkan-keys` `Algorithm::ALL` | same | Met |
| Disc. 3 | `scopes_supported` includes `openid` | MUST | `discovery.rs` | same | Met |
| Disc. 3 | Defaults that would over-claim set explicitly | — | `discovery.rs` | `genkan-oauth: discovery::tests::does_not_inherit_misleading_defaults` | Met |
| Disc. 4, 4.3 | Document at `/.well-known/openid-configuration`; `issuer` identical | MUST | `genkan-oauth/src/metadata.rs` | `genkan-oauth: metadata::tests::both_metadata_locations_serve_the_same_document` | Met |
| 8414 §3, §3.3 | Well-known location; identical `issuer`; RFC 9068 §4 consistency | MUST | one document at both paths | same | Met |
| Disc. 7.1 | TLS for discovery | MUST | TLS at the ingress; the internal listener for kube-apiserver uses Genkan's own CA | `genkan: internal::tests::serves_metadata_with_the_issued_certificate_and_renews_in_place` | Met |

## JOSE: RFC 7515, 7517, 7518, 7638, 8725

| § | Requirement | Level | Code | Test | Status |
|---|---|---|---|---|---|
| 7515 §4.1.1, §4.1.4 | `alg` present; `kid` identifies the key | MUST | `genkan-keys/src/jws.rs` | `genkan-keys: jws::tests::independent_library_verifies_with_published_jwk` | Met |
| 7515 §4.1.11 | Unknown critical extensions rejected | MUST | `genkan-keys/src/verify.rs` | `genkan-keys: verify::tests::rejects_tampering_wrong_keys_and_algorithms` | Met |
| 7517 §4.5, §4.3, §5 | Distinct `kid`s; not `use` with `key_ops`; set format | SHOULD | `genkan-keys/src/jwk.rs` | `genkan-keys: jwk::tests::*`, `rotation::tests::schedule_invariants` | Met |
| 7518 §3.3, §3.4, §3.6 | RSA ≥ 2048 bits (3072 generated); fixed-width ES256; no `none` | MUST | `genkan-keys/src/signing.rs`, `verify.rs` | `genkan-keys: signing::tests::*`, `verify::tests::*` | Met |
| 7638 §3 | Thumbprint canonical form | MUST | `jwk.rs` | `genkan-keys: jwk::tests::rfc7638_example_thumbprint` | Met |
| 8725 §3.1 | One algorithm per key | MUST | `signing.rs`, `verify.rs` | `genkan-keys: signing::tests::rejects_key_for_the_wrong_algorithm`, `verify::tests::an_rsa_key_never_verifies_an_es256_header` | Met |
| 8725 §3.10, §3.11 | No `jku`/`x5u`/`jwk` headers; explicit `typ` | — / RECOMMENDED | `jws.rs` (`at+jwt`, `JWT`) | `genkan-oauth/tests/oauth.rs: code_flow_issues_tokens_kubernetes_can_use` | Met |
| OIDC Core §10.1.1 | Keep decommissioned keys published for a while | SHOULD | `genkan-keys/src/rotation.rs` | `genkan-keys: rotation::tests::*` | Met |

## kube-apiserver integration (KEP-3331)

| Source | Requirement | Code | Test | Status |
|---|---|---|---|---|
| `oidc.go` | RS/ES/PS algorithms only | ES256 default, RS256 | — | Met |
| go-oidc v2 key cache | A new key is visible before it signs | `genkan-keys/src/rotation.rs` publish-ahead; max-age below it | `genkan-keys: rotation::tests::schedule_invariants`, `genkan: cli::tests::rejects_bad_issuers_and_inconsistent_timings` | Met |
| `validation.go` | `discoveryURL` https and different from `url` | internal TLS listener at the Service's ClusterIP | *(e2e)* | Met |
| `oidc.go` | Internal discovery keeps `issuer`; `jwks_uri` from that document | `genkan-oauth/src/discovery.rs` | `genkan-oauth: discovery::tests::internal_variant_changes_only_the_jwks_uri`; *(e2e)* | Met |
| AuthenticationConfiguration | Prefixed usernames and groups; no `system:`; access tokens only (`has(claims.client_id)`); lifetime bound; elevated groups only in short, fresh tokens | `genkan-k8s/src/kube_config.rs` | `genkan-k8s: kube_config::tests::*`; *(e2e)* `passkey_sign_in_then_kubectl_auth_whoami` | Met |
| Distributions | `anonymous` per distribution; install steps for k3s, k0s, kubeadm; KubeSolo refused | `kube_config.rs` | `genkan-k8s: kube_config::tests::anonymous_section_follows_the_distribution` | Met |
| Project requirement | `kubectl auth whoami` on k3s | — | *(e2e)* | Met |

## Kubernetes storage

| Source | Requirement | Code | Test | Status |
|---|---|---|---|---|
| API concepts | Update with `resourceVersion` is compare-and-swap; delete preconditions; create of an existing name fails | `genkan-k8s/src/objects.rs` | `genkan-k8s/tests/kubernetes.rs: exactly_one_racer_wins_each_primitive` *(cluster)* | Met |
| CRD validation | CEL within the cost budget | `genkan-k8s/src/crd/*.rs` | `admission_rejects_invalid_objects` *(cluster)* | Met |
| RBAC | Least privilege: Secrets only by name, no `create` on Secrets, no RBAC verbs | `genkan-k8s/src/rbac.rs` | `service_account_has_least_privilege` *(cluster)*, `genkan-k8s: rbac::tests::*` | Met |
| Project requirement | Expired objects are cleaned up | `genkan-k8s/src/gc.rs` | `garbage_collector_deletes_expired_objects_only` *(cluster)* | Met |
| Project requirement | Signing keys in a Secret, rotation with overlap | `genkan-k8s/src/keys.rs` | `signing_keys_persist_and_only_one_writer_wins` *(cluster)* | Met |
| WebAuthn Level 3 §7.1 | A known credential ID fails registration | `genkan-store` `passkey_credential_name`, create-once | `genkan-signin/tests/signin.rs`; `setup_link_is_single_use_and_replaceable` *(cluster)* | Met |
| RFC 9700 §4.14.2 | Refresh rotation with reuse detection | `genkan-k8s/src/grants.rs`, `genkan-store` `classify` | `grant_rotation_is_linearizable` *(cluster: 1 of 64 rotates)* | Met |
| Project account-recovery policy; RFC 9700 §4.14.2 (security-event revocation, MAY) | Reset deletes credentials and refresh-token families before writing a setup link, including zero-credential retries after partial failure | `genkan-k8s/src/setup.rs` | `genkan-k8s/tests/setup_reset.rs: reset_retries_grant_deletion_after_credentials_are_gone`, `reset_revokes_old_grants_without_credentials` (mock Kubernetes HTTP API, real OAuth router); `genkan-e2e/tests/e2e.rs: passkey_sign_in_then_kubectl_auth_whoami` *(cluster: refresh succeeds before reset and fails afterward)* | Met |

## OAuth 2.0 and OpenID Connect

Tests are in `genkan-oauth/tests/oauth.rs` unless noted.

| Spec § | Requirement | Level | Code (`genkan-oauth/src/`) | Test | Status |
|---|---|---|---|---|---|
| 6749 §3.1, §3.2 | Parameters not repeated | MUST | `params.rs` | `authorization_endpoint_errors` | Met |
| 6749 §3.1.2.3; 9700 §2.1 | Exact redirect URI match (loopback port excepted) | MUST | `authorize.rs` | `genkan-oauth: authorize::tests::redirect_uri_rules` | Met |
| 6749 §4.1.2.1 | No redirect for an invalid client or redirect URI | MUST NOT | `endpoints.rs` (HTML error page) | `authorization_endpoint_errors`; `genkan-signin/tests/pages.rs: untrusted_authorization_requests_show_an_error_page` | Met |
| 6749 §4.1.2 | Codes short-lived and single use; reuse revokes issued tokens | MUST | `code.rs`, `endpoints.rs` | `code_is_single_use_and_reuse_revokes_what_it_issued`, `exactly_one_concurrent_redemption_succeeds` | Met |
| 6749 §4.1.3 | Code bound to client and `redirect_uri` | MUST | `endpoints.rs` | `pkce_and_code_binding_are_enforced` | Met |
| 6749 §2.3.1, §5.2 | Client authentication; `WWW-Authenticate` for Basic | MUST | `client_auth.rs` | `confidential_client_gets_rs256_id_tokens_and_must_authenticate` | Met |
| 6749 §5.1 | `Cache-Control: no-store` | MUST | `error.rs` `no_store` | `code_flow_issues_tokens_kubernetes_can_use` | Met |
| 6749 §10.10 | Token guessing ≤ 2^-128 | MUST | 256-bit secrets; sealed codes | — | Met |
| 6749 §10.12 | CSRF protection for the authorization endpoint | MUST | approval is a same-origin JSON sign-in bound to the browser's sealed flow cookie | `genkan-signin/tests/signin.rs: requests_from_other_sites_are_refused`, `sign_in_needs_a_pending_authorization_request` | Met |
| 7636 §4.1, §4.4.1, §4.6 | Verifier format; challenge required; S256 compare | MUST | `pkce.rs`, `authorize.rs` | `genkan-oauth: pkce::tests::*`, `authorize::tests::*` | Met |
| 9700 §2.1.1, §2.2.2 | PKCE required; public-client refresh tokens rotated | MUST | `authorize.rs`, `endpoints.rs` | `pkce_and_code_binding_are_enforced`, `refresh_rotates_and_reuse_revokes_the_family` | Met |
| 9700 §4.11.2 | 303, never 307 | MUST NOT | `endpoints.rs` | `code_flow_issues_tokens_kubernetes_can_use` | Met |
| 9068 §2.1, §2.2, §5 | `at+jwt`; required claims; distinct `aud` per resource | MUST | `tokens.rs`, `authorize.rs` | `code_flow_issues_tokens_kubernetes_can_use`, `authorization_endpoint_errors` | Met |
| 8707 §2 | `invalid_target` for disallowed resources | — | `authorize.rs` | `genkan-oauth: authorize::tests::*` | Met |
| 9126 §2.1, §2.2, §4 | Authenticated PAR; one-time, client-bound, expiring request URI | MUST | `endpoints.rs` | `pushed_authorization_requests` | Met |
| 7009 §2.1, §2.2 | Revocation by the owning client with constant-time proof of a current or previous refresh secret; 200 for invalid tokens without deleting a grant | MUST | `endpoints.rs`, `refresh.rs` | `revocation`, `guessed_refresh_secrets_cannot_revoke_a_known_grant`, `current_and_previous_refresh_secrets_authorize_family_revocation`; `genkan-e2e: passkey_sign_in_then_kubectl_auth_whoami` (forged-secret smoke) | Met |
| 6749 §6 | Validate refresh token and client binding; wrong-client family deletion requires constant-time proof of a current or previous secret, never a grant name alone | MUST; deletion policy | `endpoints.rs`, `refresh.rs` | `guessed_refresh_secrets_cannot_revoke_a_known_grant`, `current_and_previous_refresh_secrets_authorize_family_revocation`; `genkan-e2e: passkey_sign_in_then_kubectl_auth_whoami` (second public-client forged-secret smoke) | Met |
| 9207 §2 | `iss` in authorization responses | MUST | `authorize.rs` | `code_flow_issues_tokens_kubernetes_can_use` | Met |
| OIDC Core §2, §3.1.3.6 | ID token claims; `aud` is the client; `azp` | REQUIRED | `tokens.rs` | `code_flow_issues_tokens_kubernetes_can_use` | Met |
| OIDC Core §3.1.2.1 | GET and POST; `prompt=none` without a session fails | MUST | `endpoints.rs`, `authorize.rs` | `authorization_endpoint_accepts_post`, `authorization_endpoint_errors` | Met |
| OIDC Core §3.1.2.1 | `ui_locales` | OPTIONAL | error page | `genkan-signin/tests/pages.rs: untrusted_authorization_requests_show_an_error_page` | Partial: the sign-in page does not use it |
| OIDC Core §5.3; RFC 6750 §2.1, §3 | UserInfo with bearer access tokens; challenges with error codes; current claims by scope | MUST | `userinfo.rs` | `userinfo_returns_current_claims_for_access_tokens_only` | Met |
| OIDC Core §5.3.2 | Always return the grant's `sub`; resolve metadata by UID and verify the directly read user's UID and enabled state | MUST; binding policy | `userinfo.rs`, `genkan-k8s/src/directory.rs` | `userinfo_returns_current_claims_for_access_tokens_only`, `userinfo_rejects_deleted_and_recreated_users`, `userinfo_rejects_unknown_and_ambiguous_subjects` | Met (client-side ID token subject comparison remains the client's responsibility) |
| OIDC Core §12.2 | Refreshed ID token keeps `auth_time`, no nonce | MUST | `endpoints.rs` | `refresh_rotates_and_reuse_revokes_the_family` | Met |
| OIDC Core §15.1 | `max_age`, `prompt=login` | MUST | every sign-in is a fresh ceremony (no sessions) | `genkan-signin/tests/signin.rs: setup_link_then_passkey_sign_in_issues_tokens` | Met while there are no sessions |

## Elevation

| Requirement | Code | Test | Status |
|---|---|---|---|
| Elevated groups only after a passkey sign-in (`amr` contains `swk`) | `genkan-oauth/src/endpoints.rs` | `elevation_needs_the_feature_a_passkey_and_eligible_groups`; `genkan-signin/tests/upstream.rs: start_requires_a_pending_request_and_refuses_elevation` | Met |
| Short, non-refreshable elevated tokens; refresh never yields elevated groups | `endpoints.rs` | `elevation_issues_short_lived_tokens_without_refresh` | Met |
| Elevated codes single use under concurrency | `endpoints.rs` | `an_elevated_code_is_redeemed_at_most_once_under_concurrency` | Met |
| kube-apiserver rejects elevated groups in long or stale tokens | `genkan-k8s/src/kube_config.rs` | *(e2e)* | Met |
| First admin: read-only base group, cluster admin only when elevated | `genkan-k8s/src/rbac.rs`, `setup.rs` | *(e2e)* `passkey_sign_in_then_kubectl_auth_whoami` | Met |

## Sign-in: passkeys, enrolment links, invitations

Tests are in `genkan-signin/tests/signin.rs` unless noted.

| Source | Requirement | Level | Code (`genkan-signin/src/`) | Test | Status |
|---|---|---|---|---|---|
| Project requirement | Setup link works once and expires; no first-visitor admin | MUST | `lib.rs` (consume before storing), `genkan-k8s/src/setup.rs` | `setup_token_is_single_use`, `concurrent_enrolments_with_one_token_add_one_passkey`, `setup_token_expires_and_must_match`, `setup_link_is_single_use_and_replaceable` *(cluster, 64 concurrent)* | Met |
| Project requirement | Invitations work once, only for the invited user; the service account cannot create them | MUST | `lib.rs`, `genkan-k8s/src/setup.rs`, `invitations.rs` | `invitation_enrols_the_invited_user_once`, `invitations_are_single_use_and_admin_only` *(cluster)* | Met |
| WebAuthn §5.4.4, §5.4.6 | Discoverable credential, user verification required | — | `passkeys.rs` | `genkan-signin: passkeys::tests::registration_requires_resident_keys_and_uv` | Met |
| WebAuthn §7.1, §7.2 | UV verified; user handle is the owner's; challenge single use | MUST | `passkeys.rs`, `lib.rs` | `passkeys_without_user_verification_are_refused` (client side), `unknown_passkeys_and_disabled_users_cannot_sign_in`, `assertions_cannot_be_replayed` | Partial: no server-side forged-UV test |
| WebAuthn conditional mediation | Autofill (`autocomplete="username webauthn"`) | — | `passkeys.rs`, `ui/src/login.ts` | `genkan-signin/tests/pages.rs: login_offers_passkey_autofill_for_a_pending_request` | Met |
| RFC 9457 §3 | Problem details | — | `problem.rs` | `requests_from_other_sites_are_refused` | Met |
| Fetch Metadata | Cross-site state-changing requests refused | — | `lib.rs` `check_request` | `requests_from_other_sites_are_refused`, `genkan-signin: tests::same_origin_checks` | Met |
| RFC 6265bis | `__Host-` cookies: Secure, `Path=/`, no Domain | MUST | `lib.rs`, `upstream.rs` | `code_flow_issues_tokens_kubernetes_can_use` | Met |
| RFC 6409, 8314, 3207, 4616 | Mail only over TLS; STARTTLS required on 587; injected pre-TLS replies refused; AUTH only inside TLS | MUST | `genkan-mail/src/lib.rs` | `genkan-mail: tests::*`; `genkan/tests/kubernetes.rs: mailed_invitations_are_claimed_once_and_sent` *(cluster)* | Met |

## Upstream sign-in (GitHub, Google)

Tests are in `genkan-signin/tests/upstream.rs`.

| Source | Requirement | Code (`genkan-signin/src/`) | Test | Status |
|---|---|---|---|---|
| RFC 6749 §10.12; RFC 9700 §2.1 | `state` bound to the browser, compared in constant time, used once | `upstream.rs` | `unlinked_disabled_and_replayed_sign_ins_fail` | Met |
| RFC 7636 | PKCE towards the provider | `upstream/provider.rs` | `a_linked_github_account_signs_in_and_gets_a_code` (fake provider checks the verifier) | Met |
| OIDC Core §3.1.3.7 | ID token: signature from the provider's JWK set, `iss`, `aud`/`azp`, `exp`, `iat`, `nonce` | `upstream/provider.rs` | `google_id_tokens_are_validated` | Met |
| Project requirement | Only linked accounts sign in; linking only through an enrolment link, once | `upstream.rs` | `an_invitation_links_an_account_once`, `unlinked_disabled_and_replayed_sign_ins_fail` | Met |

## SCIM 2.0 (RFC 7643, RFC 7644)

Tests are in `genkan-scim/tests/scim.rs` unless noted.

| § | Requirement | Code | Test | Status |
|---|---|---|---|---|
| 7644 §2 | Authenticated requests (bearer token) | `genkan-scim/src/lib.rs` | `requires_the_bearer_token` | Met |
| 7644 §3.3, §3.4.1, §3.5.1, §3.6 | Create, retrieve, replace, delete Users; `userName` unique | `lib.rs` | `user_lifecycle` | Met |
| 7644 §3.4.2 | List with `filter` (`eq` only) and pagination | `lib.rs`, `model.rs` | `user_lifecycle`, `genkan-scim: model::tests::*` | Partial: `eq` on `userName`, `externalId`, `id`, `displayName` |
| 7644 §3.5.2 | PATCH add/remove/replace | `model.rs` | `genkan-scim: model::tests::*`, `groups_are_allowlisted_and_map_to_user_groups` | Met |
| 7644 §3.12 | Error responses with `scimType` | `model.rs` | `user_lifecycle` | Met |
| 7643 §5–7 | `ServiceProviderConfig`, `ResourceTypes`, `Schemas` | `model.rs` | `requires_the_bearer_token` | Met |
| Project requirement | SCIM cannot touch users it did not create, assign non-allowlisted or elevated groups, even if Genkan is compromised | `lib.rs`, `genkan-k8s/src/users.rs`, `rbac.rs` `scim_policy` | `groups_are_allowlisted_and_map_to_user_groups`, `scim_writes_are_bounded_by_the_admission_policy` *(cluster)* | Met |

## Sign-in pages

Tests are in `genkan-signin/tests/pages.rs`; every page test checks headers and that the markup
needs nothing the CSP forbids.

| Source | Requirement | Level | Code | Test | Status |
|---|---|---|---|---|---|
| RFC 9700 §4.16 | Prevent clickjacking (CSP `frame-ancestors`, `X-Frame-Options`) | MUST | `genkan-ui/src/lib.rs` `harden` | all page tests | Met |
| CSP Level 3, Trusted Types | No inline script, style or handlers; no string-to-HTML sinks | — | `genkan-ui`, `ui/src/*.ts` | all page tests | Met |
| RFC 9110 §12.5.4, §12.4.2 | `Accept-Language` with quality values | — | `genkan-ui/src/i18n.rs` | `genkan-ui: i18n::tests::*`, `language_follows_parameter_then_header` | Met |
| Project requirement | Assets embedded, no CDN; built output checked against source; size measured | MUST | `genkan-ui/src/assets.rs`, `scripts/build-ui.sh`, `scripts/ui-budget.sh` | `assets_are_embedded_versioned_and_immutable`; CI `ui` | Met |
| Project requirement | No tokens in browser storage; cookies `HttpOnly`, `Secure`, `SameSite` | MUST | `ui/src/*.ts`, `genkan-signin` | `tsc -p ui`, review | Met |
| Project requirement | Fallback without passkey support or script; provider buttons only when configured and not for elevation | MUST | templates | `login_offers_passkey_autofill_for_a_pending_request`, `provider_buttons_appear_only_when_configured_and_not_for_elevation` | Met |
| Project requirement | Dark mode; en, zh-TW, zh-CN | MUST | `ui/styles/app.css`, `genkan-ui/src/i18n.rs` | `language_follows_parameter_then_header` | Met |
| Escaping | User-influenced text cannot inject markup | — | askama auto-escaping | `user_controlled_text_is_escaped` | Met |
| WCAG 2.2 1.4.3, 1.4.11 | Text ≥ 4.5:1; boundaries and focus ≥ 3:1 | AA | `ui/styles/app.css` (`A11Y` overrides) | computed table in the `genkan-ui` docs | Met for every pair used |
| WCAG 2.2 2.4.7, 2.5.8, 3.1.1, 3.1.2, 3.3.1, 4.1.3 | Focus, target size, language, errors, status messages | A / AA | templates | `language_follows_parameter_then_header`; review | Met by inspection |
| WCAG 2.2 | Automated audit and assistive-technology pass | — | — | — | Not done |

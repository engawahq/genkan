//! HTTP handlers: `/authorize`, `/token`, `/par`, `/revoke` (and `/userinfo`, see
//! [`crate::userinfo`]).
//!
//! Storage writes per event: none for `/authorize`, `/par` and failed token requests; one
//! `Grant` create per code redemption; one compare-and-swap per refresh; one delete per
//! revocation or detected reuse. Storage errors become `server_error`, never a token. Every
//! token, PAR, revocation and error response carries `Cache-Control: no-store`
//! (RFC 6749 §5.1), and error descriptions are fixed strings that never echo input.
//!
//! # Elevation
//!
//! Privileged Kubernetes access is not part of normal tokens. A client asks for the `elevate`
//! scope; after a passkey sign-in, the token endpoint returns an access token whose groups add
//! `elevated:<group>` for each of the user's elevated groups, valid for
//! [`crate::Lifetimes::elevated_token`] (5 minutes by default), with no refresh token and no
//! stored grant. Privilege therefore ends when the token does, and only another passkey sign-in
//! renews it. kube-apiserver understands groups natively, so RBAC binds powerful roles only to
//! the `elevated:` names; the installed bindings give the first admin's base group the read-only
//! `view` role and `cluster-admin` only to its elevated group. The generated
//! `AuthenticationConfiguration` also rejects a token with an `elevated:` group unless it is
//! short-lived and was issued right after sign-in (`exp - iat` and `iat - auth_time` are
//! bounded), so an issuer bug cannot hand out lasting privilege.
//!
//! RFC 9470 step-up does not fit Kubernetes: kube-apiserver never sends its
//! `insufficient_user_authentication` challenge and RBAC cannot see `acr` or `auth_time`. A
//! short, separately requested privileged identity is the shape Teleport's per-session MFA
//! takes, whose check "remains valid for up to 5 minutes" ([Teleport]).
//!
//! Refresh never yields elevated groups: elevated tokens come without a refresh token,
//! refreshed tokens carry the user's current base groups, and the `elevate` scope is dropped on
//! refresh as a second guard.
//!
//! [Teleport]: https://goteleport.com/docs/zero-trust-access/authentication/per-session-mfa/

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use genkan_core::clock::{Clock, UnixTime};
use genkan_store::{Client, CreateGrant, Directory, GrantStore, NewGrant, Rotation, User};
use genkan_ui::i18n::Lang;
use genkan_ui::pages::{accept_language, error_page};
use serde::{Deserialize, Serialize};

use super::authorize::{self, Authentication, Flow, Rejection, response_location};
use super::client_auth::{AuthFailure, authenticate};
use super::code::{self, CodeClaims};
use super::error::{ErrorCode, OAuthError, no_store};
use super::params::Params;
use super::refresh::RefreshToken;
use super::tokens::{self, Subject};
use super::{AuthorizationServer, Use};
use crate::discovery::{AUTHORIZATION_PATH, PAR_PATH, REVOCATION_PATH, TOKEN_PATH, USERINFO_PATH};

/// Prefix of the group names elevation adds; regular group names cannot contain `:`, so no
/// ordinary group can spell an elevated name.
pub const ELEVATED_GROUP_PREFIX: &str = "elevated:";

/// Cookie holding the sealed pending sign-in. `__Host-` pins it to this origin, path `/`, Secure.
/// It is `SameSite=Lax` because the client sends the browser here with a cross-site top-level
/// navigation.
pub const FLOW_COOKIE: &str = "__Host-genkan-flow";
/// Associated data for sealed flows.
pub const FLOW_PURPOSE: &str = "genkan/flow/v1";
/// Associated data for sealed PAR requests.
pub const PAR_PURPOSE: &str = "genkan/par/v1";
/// RFC 9126 §2.2 request URI prefix.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
/// Where the user signs in.
pub const LOGIN_PATH: &str = "/login";

type Shared<D, G, C> = Arc<AuthorizationServer<D, G, C>>;

/// The authorization server's routes.
pub fn router<D: Directory, G: GrantStore, C: Clock>(server: Shared<D, G, C>) -> Router {
    Router::new()
        .route(
            AUTHORIZATION_PATH,
            get(authorize_get::<D, G, C>).post(authorize_post::<D, G, C>),
        )
        .route(TOKEN_PATH, post(token::<D, G, C>))
        .route(PAR_PATH, post(par::<D, G, C>))
        .route(REVOCATION_PATH, post(revoke::<D, G, C>))
        .route(
            USERINFO_PATH,
            get(super::userinfo::userinfo::<D, G, C>).post(super::userinfo::userinfo::<D, G, C>),
        )
        .with_state(server)
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::try_from(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    no_store(&mut response);
    response
}

/// The error page for requests whose client or redirect URI cannot be trusted
/// (RFC 6749 §4.1.2.1): shown to the user, never redirected.
fn local_error(lang: Lang, error: &OAuthError) -> Response {
    let detail = format!("{} ({})", error.error_description, error.error.as_str());
    error_page(lang, &detail)
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

const NOT_FORM: OAuthError = OAuthError::new(
    ErrorCode::InvalidRequest,
    "the body must be application/x-www-form-urlencoded",
);

async fn authorize_get<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let lang = Lang::negotiate(None, accept_language(&headers));
    authorize(&server, lang, query.unwrap_or_default().as_bytes()).await
}

async fn authorize_post<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = Lang::negotiate(None, accept_language(&headers));
    if !is_form(&headers) {
        return local_error(lang, &NOT_FORM);
    }
    authorize(&server, lang, &body).await
}

/// A pushed authorization request, sealed into its request URI.
#[derive(Debug, Serialize, Deserialize)]
struct Pushed {
    id: String,
    client_id: String,
    query: String,
    expires_at: UnixTime,
}

async fn authorize<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    lang: Lang,
    input: &[u8],
) -> Response {
    let params = match Params::parse(input) {
        Ok(params) => params,
        Err(error) => return local_error(lang, &error),
    };
    // OIDC Core §3.1.2.1 `ui_locales`: the client's preference wins over the browser's.
    let lang = params
        .get("ui_locales")
        .and_then(|locales| locales.split(' ').find_map(Lang::from_range))
        .unwrap_or(lang);
    let params = match params.get("request_uri") {
        None => params,
        Some(uri) => match resolve_pushed(server, &params, uri) {
            Ok(params) => params,
            Err(error) => return local_error(lang, &error),
        },
    };
    let client = match params.get("client_id") {
        None => None,
        Some(id) => match server.directory.client(id).await {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(%error, "client lookup failed");
                return local_error(lang, &OAuthError::server());
            }
        },
    };
    let elevation = server.lifetimes.elevated_token.is_some();
    let request = match authorize::validate(&params, client.as_ref(), elevation) {
        Ok(request) => request,
        Err(Rejection::Local(error)) => return local_error(lang, &error),
        Err(Rejection::Redirect {
            redirect_uri,
            state,
            error,
        }) => {
            let location = response_location(
                &redirect_uri,
                &[
                    ("error", error.error.as_str()),
                    ("error_description", error.error_description),
                ],
                state.as_deref(),
                server.issuer.as_str(),
            );
            return redirect(&location);
        }
    };

    let now = server.now();
    let flow = Flow {
        request,
        expires_at: now.saturating_add(server.lifetimes.flow),
    };
    let sealed = serde_json::to_vec(&flow)
        .ok()
        .and_then(|json| server.sealer.seal(FLOW_PURPOSE, &json).ok());
    let Some(sealed) = sealed else {
        return local_error(lang, &OAuthError::server());
    };
    let mut response = redirect(LOGIN_PATH);
    let cookie = format!(
        "{FLOW_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        server.lifetimes.flow.as_secs()
    );
    if let Ok(value) = HeaderValue::try_from(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn resolve_pushed<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    outer: &Params,
    uri: &str,
) -> Result<Params, OAuthError> {
    let invalid = OAuthError::new(
        ErrorCode::InvalidRequestUri,
        "the request_uri is invalid, expired or already used",
    );
    let pushed: Pushed = uri
        .strip_prefix(REQUEST_URI_PREFIX)
        .and_then(|sealed| server.sealer.open(PAR_PURPOSE, sealed))
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or(invalid)?;
    let now = server.now();
    // RFC 9126 §4: client_id must be sent and match; expired URIs are invalid; one-time use.
    if outer.get("client_id") != Some(pushed.client_id.as_str()) || pushed.expires_at <= now {
        return Err(invalid);
    }
    if server
        .used_request_uris
        .first_use(&pushed.id, pushed.expires_at, "", now)
        != Use::First
    {
        return Err(invalid);
    }
    Params::parse(pushed.query.as_bytes())
}

/// Opens a pending sign-in from its cookie value, if it is genuine and not expired. Used by the
/// sign-in page to show which application the user is signing in to.
#[must_use]
pub fn open_flow<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    sealed_flow: &str,
) -> Option<Flow> {
    let flow: Flow = server
        .sealer
        .open(FLOW_PURPOSE, sealed_flow)
        .and_then(|json| serde_json::from_slice(&json).ok())?;
    (flow.expires_at > server.now()).then_some(flow)
}

/// Finishes a sign-in: called by a sign-in method once the user has authenticated. Returns where
/// to send the browser (the client's redirect URI with `code`, `state` and `iss`).
///
/// # Errors
///
/// `invalid_request` if the flow is missing, forged or expired.
pub fn complete_authorization<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    sealed_flow: &str,
    authentication: Authentication,
) -> Result<String, OAuthError> {
    let flow: Flow = server
        .sealer
        .open(FLOW_PURPOSE, sealed_flow)
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or(OAuthError::new(
            ErrorCode::InvalidRequest,
            "the sign-in request is missing or invalid",
        ))?;
    let now = server.now();
    if flow.expires_at <= now {
        return Err(OAuthError::new(
            ErrorCode::InvalidRequest,
            "the sign-in request expired; start again",
        ));
    }
    // Elevated groups need proof of key possession from a passkey (`amr` contains `swk`, set
    // only by the passkey sign-in), never an upstream account.
    if flow.request.is_elevated() && !authentication.amr.iter().any(|m| m == "swk") {
        return Err(OAuthError::new(
            ErrorCode::AccessDenied,
            "elevation requires signing in with a passkey",
        ));
    }
    let (redirect_uri, state) = (
        flow.request.redirect_uri.clone(),
        flow.request.state.clone(),
    );
    let code = code::issue(
        &server.sealer,
        flow.request,
        authentication,
        now.saturating_add(server.lifetimes.code),
    )
    .map_err(|_crypto| OAuthError::server())?;
    Ok(response_location(
        &redirect_uri,
        &[("code", &code)],
        state.as_deref(),
        server.issuer.as_str(),
    ))
}

/// RFC 6749 §5.1 token response.
#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    scope: String,
}

fn auth_failure(failure: AuthFailure) -> Response {
    let mut response = failure.error.into_response();
    if failure.basic && failure.error.error == ErrorCode::InvalidClient {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Basic realm="genkan""#),
        );
    }
    response
}

async fn token<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        return NOT_FORM.into_response();
    }
    let params = match Params::parse(&body) {
        Ok(params) => params,
        Err(error) => return error.into_response(),
    };
    let client = match authenticate(&server.directory, &headers, &params).await {
        Ok(client) => client,
        Err(failure) => return auth_failure(failure),
    };
    let result = match params.get("grant_type") {
        Some("authorization_code") => exchange_code(&server, &client, &params).await,
        Some("refresh_token") => refresh(&server, &client, &params).await,
        Some(_) => Err(OAuthError::new(
            ErrorCode::UnsupportedGrantType,
            "unsupported grant_type",
        )),
        None => Err(OAuthError::new(
            ErrorCode::InvalidRequest,
            "grant_type is required",
        )),
    };
    match result {
        Ok(tokens) => {
            let mut response = axum::Json(tokens).into_response();
            no_store(&mut response);
            response
        }
        Err(error) => error.into_response(),
    }
}

const INVALID_GRANT: OAuthError = OAuthError::new(
    ErrorCode::InvalidGrant,
    "the grant is invalid, expired, revoked or was issued to another client",
);

fn store_error(error: impl std::fmt::Display) -> OAuthError {
    tracing::error!(%error, "storage failed");
    OAuthError::server()
}

async fn exchange_code<D: Directory, G: GrantStore, C: Clock>(
    server: &Shared<D, G, C>,
    client: &Client,
    params: &Params,
) -> Result<TokenResponse, OAuthError> {
    let now = server.now();
    let code = params.get("code").ok_or(OAuthError::new(
        ErrorCode::InvalidRequest,
        "code is required",
    ))?;
    let claims: CodeClaims = code::open(&server.sealer, code).ok_or(INVALID_GRANT)?;
    // RFC 6749 §4.1.3: the code was issued to this client; redirect_uri, if sent, is identical.
    if claims.expires_at <= now || claims.request.client_id != client.id {
        return Err(INVALID_GRANT);
    }
    if params
        .get("redirect_uri")
        .is_some_and(|uri| uri != claims.request.redirect_uri)
    {
        return Err(INVALID_GRANT);
    }
    // RFC 7636 §4.6. Checked before the single-use gate, so someone holding a stolen code without
    // the verifier cannot burn it for the legitimate client. A missing verifier is refused, so a
    // request cannot downgrade out of PKCE (RFC 9700 §2.1.1).
    let verifier = params.get("code_verifier").ok_or(INVALID_GRANT)?;
    if !super::pkce::verify(verifier, &claims.request.code_challenge) {
        return Err(INVALID_GRANT);
    }

    let entry = server.used_codes.entry(&claims.id, claims.expires_at, now);
    let server = Arc::clone(server);
    let client = client.clone();
    // Keep the operation and its per-code lock alive if the HTTP request is cancelled. In
    // particular, a replay cannot revoke a missing grant while its first create is pending.
    tokio::spawn(async move {
        let mut redeemed = entry.lock().await;
        let result = if *redeemed {
            tracing::warn!(client = %client.id, "authorization code reused; revoking its grant");
            server
                .grants
                .revoke(&code::grant_name(&claims.id))
                .await
                .map_err(store_error)
                .and(Err(INVALID_GRANT))
        } else {
            *redeemed = true;
            redeem_code(&server, &client, &claims, now).await
        };
        drop(redeemed);
        result
    })
    .await
    .map_err(store_error)?
}

async fn redeem_code<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    client: &Client,
    claims: &CodeClaims,
    now: UnixTime,
) -> Result<TokenResponse, OAuthError> {
    let grant_name = code::grant_name(&claims.id);

    let user = active_user(server, &claims.user)
        .await?
        .ok_or(INVALID_GRANT)?;
    if claims.request.is_elevated() {
        return elevated_tokens(server, client, &user, claims, now);
    }
    let refresh_token =
        RefreshToken::generate(&grant_name).map_err(|_crypto| OAuthError::server())?;
    let absolute = now.saturating_add(server.lifetimes.refresh_absolute);
    let grant = NewGrant {
        name: grant_name,
        user: user.name.clone(),
        client: client.id.clone(),
        audience: claims.request.audience.clone(),
        scopes: claims.request.scopes.clone(),
        auth_time: claims.auth_time,
        amr: claims.amr.clone(),
        expires_at: absolute,
        initial_hash: refresh_token.hash(),
    };
    let idle = now
        .saturating_add(server.lifetimes.refresh_idle)
        .min(absolute);
    match server
        .grants
        .create(&grant, idle)
        .await
        .map_err(store_error)?
    {
        CreateGrant::Created => {}
        // Another process redeemed the same code first.
        CreateGrant::AlreadyExists => {
            server
                .grants
                .revoke(&grant.name)
                .await
                .map_err(store_error)?;
            return Err(INVALID_GRANT);
        }
    }
    issue_tokens(
        server,
        client,
        &user,
        &grant,
        claims.request.nonce.as_deref(),
        Some(&refresh_token),
        server.lifetimes.access_token,
        now,
    )
}

/// Tokens for an `elevate` request: the user's groups plus `elevated:<group>` for each elevated
/// group, valid for the elevated lifetime only, and no refresh token, so the privilege ends when
/// the token does and only another passkey sign-in renews it. Nothing is stored, so there is no
/// family to refresh. Each issuance is logged.
fn elevated_tokens<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    client: &Client,
    user: &User,
    claims: &CodeClaims,
    now: UnixTime,
) -> Result<TokenResponse, OAuthError> {
    // Elevation was switched off after this code was issued.
    let lifetime = server.lifetimes.elevated_token.ok_or(INVALID_GRANT)?;
    if user.elevated_groups.is_empty() {
        return Err(OAuthError::new(
            ErrorCode::InvalidScope,
            "the user has no elevated groups",
        ));
    }
    let mut elevated = user.clone();
    elevated.groups.extend(
        user.elevated_groups
            .iter()
            .map(|group| format!("{ELEVATED_GROUP_PREFIX}{group}")),
    );
    let grant = NewGrant {
        name: String::new(),
        user: user.name.clone(),
        client: client.id.clone(),
        audience: claims.request.audience.clone(),
        scopes: claims.request.scopes.clone(),
        auth_time: claims.auth_time,
        amr: claims.amr.clone(),
        expires_at: now.saturating_add(lifetime),
        initial_hash: String::new(),
    };
    tracing::info!(
        user = %user.name,
        client = %client.id,
        groups = ?user.elevated_groups,
        lifetime_seconds = lifetime.as_secs(),
        "elevated token issued"
    );
    issue_tokens(
        server,
        client,
        &elevated,
        &grant,
        claims.request.nonce.as_deref(),
        None,
        lifetime,
        now,
    )
}

async fn active_user<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    name: &str,
) -> Result<Option<User>, OAuthError> {
    let user = server.directory.user(name).await.map_err(store_error)?;
    Ok(user.filter(|user| !user.disabled))
}

#[expect(
    clippy::too_many_arguments,
    reason = "every argument is a distinct input of the token response"
)]
fn issue_tokens<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    client: &Client,
    user: &User,
    grant: &NewGrant,
    nonce: Option<&str>,
    refresh_token: Option<&RefreshToken>,
    lifetime: Duration,
    now: UnixTime,
) -> Result<TokenResponse, OAuthError> {
    let keys = server.keys.borrow().clone().ok_or_else(|| {
        tracing::error!("token requested before signing keys were published");
        OAuthError::new(
            ErrorCode::TemporarilyUnavailable,
            "signing keys are not ready",
        )
    })?;
    let subject = Subject {
        issuer: server.issuer.as_str(),
        user,
        client,
        audience: &grant.audience,
        scopes: &grant.scopes,
        auth_time: grant.auth_time,
        amr: &grant.amr,
    };
    let access_token = tokens::access_token(&keys, &subject, now, now.saturating_add(lifetime))?;
    let id_token = if grant.scopes.iter().any(|s| s == "openid") {
        let expires = now.saturating_add(server.lifetimes.id_token.min(lifetime));
        Some(tokens::id_token(&keys, &subject, nonce, now, expires)?)
    } else {
        None
    };
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: lifetime.as_secs(),
        refresh_token: refresh_token.map(RefreshToken::encode),
        id_token,
        scope: grant.scopes.join(" "),
    })
}

async fn refresh<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    client: &Client,
    params: &Params,
) -> Result<TokenResponse, OAuthError> {
    let now = server.now();
    let presented = params.get("refresh_token").ok_or(OAuthError::new(
        ErrorCode::InvalidRequest,
        "refresh_token is required",
    ))?;
    let presented = RefreshToken::parse(presented).ok_or(INVALID_GRANT)?;
    let stored = server
        .grants
        .get(presented.grant())
        .await
        .map_err(store_error)?
        .ok_or(INVALID_GRANT)?;
    if stored.spec.client != client.id {
        // A token in the wrong hands: end the family.
        tracing::warn!(client = %client.id, "refresh token presented by another client; revoking");
        server
            .grants
            .revoke(presented.grant())
            .await
            .map_err(store_error)?;
        return Err(INVALID_GRANT);
    }
    let scopes = match params.get("scope") {
        None => stored.spec.scopes.clone(),
        Some(requested) => {
            let requested: Vec<String> = requested
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            if !requested.iter().all(|s| stored.spec.scopes.contains(s)) {
                return Err(OAuthError::new(
                    ErrorCode::InvalidScope,
                    "refresh can only narrow the granted scope",
                ));
            }
            requested
        }
    };

    let next = RefreshToken::generate(presented.grant()).map_err(|_crypto| OAuthError::server())?;
    let idle = now
        .saturating_add(server.lifetimes.refresh_idle)
        .min(stored.spec.expires_at);
    let rotated = server
        .grants
        .rotate(
            presented.grant(),
            &presented.hash(),
            &next.hash(),
            now,
            idle,
        )
        .await
        .map_err(store_error)?;
    let grant = match rotated {
        Rotation::Rotated(grant) => grant,
        Rotation::Replay => {
            // RFC 9700 §4.14.2: a rotated token was used again; revoke the whole family.
            tracing::warn!(client = %client.id, "refresh token reuse detected; revoking the family");
            server
                .grants
                .revoke(presented.grant())
                .await
                .map_err(store_error)?;
            return Err(INVALID_GRANT);
        }
        // The idle or absolute lifetime has passed; delete the family now rather than waiting
        // for garbage collection.
        Rotation::Expired => {
            server
                .grants
                .revoke(presented.grant())
                .await
                .map_err(store_error)?;
            return Err(INVALID_GRANT);
        }
        // Unknown secret: refuse without revoking, or anyone who can read grant names could end
        // other users' sessions.
        Rotation::Invalid | Rotation::NotFound => return Err(INVALID_GRANT),
    };
    // Re-check the user on every refresh: disabled or deleted users get nothing more, and groups
    // come from the user as it is now, not as it was at sign-in.
    let Some(user) = active_user(server, &grant.spec.user).await? else {
        server
            .grants
            .revoke(presented.grant())
            .await
            .map_err(store_error)?;
        return Err(INVALID_GRANT);
    };
    let narrowed = NewGrant {
        scopes: without_elevation(scopes),
        ..grant.spec
    };
    issue_tokens(
        server,
        client,
        &user,
        &narrowed,
        None,
        Some(&next),
        server.lifetimes.access_token,
        now,
    )
}

/// Refresh never yields elevated groups. Elevated grants are never stored, so this only guards
/// against a mistake elsewhere (RFC 6749 §6 already forbids widening scope on refresh).
fn without_elevation(scopes: Vec<String>) -> Vec<String> {
    scopes
        .into_iter()
        .filter(|s| s != authorize::ELEVATE_SCOPE)
        .collect()
}

/// RFC 9126 §2.2 response. The `request_uri` is the sealed request itself, so pushing writes
/// nothing; it is bound to the client, expires after [`crate::Lifetimes::par`] and is single-use
/// (RFC 9126 §4).
#[derive(Debug, Serialize)]
struct PushedResponse {
    request_uri: String,
    expires_in: u64,
}

async fn par<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        return NOT_FORM.into_response();
    }
    let params = match Params::parse(&body) {
        Ok(params) => params,
        Err(error) => return error.into_response(),
    };
    // RFC 9126 §2.1: authenticate the client as at the token endpoint, then validate exactly as
    // `/authorize` would.
    let client = match authenticate(&server.directory, &headers, &params).await {
        Ok(client) => client,
        Err(failure) => return auth_failure(failure),
    };
    if params.get("request_uri").is_some() {
        return OAuthError::new(ErrorCode::InvalidRequest, "request_uri cannot be pushed")
            .into_response();
    }
    let elevation = server.lifetimes.elevated_token.is_some();
    if let Err(rejection) = authorize::validate(&params, Some(&client), elevation) {
        let error = match rejection {
            Rejection::Local(error) | Rejection::Redirect { error, .. } => error,
        };
        return error.into_response();
    }
    // Keep the authorization parameters, never the client's credentials.
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form_urlencoded::parse(&body).filter(|(k, _)| k != "client_secret"))
        .finish();
    let now = server.now();
    let lifetime = server.lifetimes.par;
    let sealed = genkan_core::crypto::random::<16>().ok().and_then(|id| {
        let pushed = Pushed {
            id: genkan_core::crypto::hex(&id),
            client_id: client.id.clone(),
            query,
            expires_at: now.saturating_add(lifetime),
        };
        serde_json::to_vec(&pushed)
            .ok()
            .and_then(|json| server.sealer.seal(PAR_PURPOSE, &json).ok())
    });
    let Some(sealed) = sealed else {
        return OAuthError::server().into_response();
    };
    let mut response = (
        StatusCode::CREATED,
        axum::Json(PushedResponse {
            request_uri: format!("{REQUEST_URI_PREFIX}{sealed}"),
            expires_in: lifetime.as_secs(),
        }),
    )
        .into_response();
    no_store(&mut response);
    response
}

async fn revoke<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        return NOT_FORM.into_response();
    }
    let params = match Params::parse(&body) {
        Ok(params) => params,
        Err(error) => return error.into_response(),
    };
    let client = match authenticate(&server.directory, &headers, &params).await {
        Ok(client) => client,
        Err(failure) => return auth_failure(failure),
    };
    let Some(token) = params.get("token") else {
        return OAuthError::new(ErrorCode::InvalidRequest, "token is required").into_response();
    };
    if let Some(refresh) = RefreshToken::parse(token) {
        match server.grants.get(refresh.grant()).await {
            // Only the client the token was issued to may revoke it (RFC 7009 §2.1).
            Ok(Some(grant)) if grant.spec.client == client.id => {
                if let Err(error) = server.grants.revoke(refresh.grant()).await {
                    return store_error(error).into_response();
                }
            }
            Ok(_) => {}
            Err(error) => return store_error(error).into_response(),
        }
    } else if token.split('.').count() == 3 {
        // Access and ID tokens are verified offline (kube-apiserver among others) and cannot be
        // revoked; say so instead of pretending (RFC 7009 §2.2.1).
        return OAuthError::new(
            ErrorCode::UnsupportedTokenType,
            "access tokens cannot be revoked; they expire within minutes",
        )
        .into_response();
    }
    // RFC 7009 §2.2: 200 for revoked and for invalid tokens alike.
    let mut response = StatusCode::OK.into_response();
    no_store(&mut response);
    response
}

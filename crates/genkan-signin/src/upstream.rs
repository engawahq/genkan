//! Signing in with an upstream identity provider (GitHub, Google), and linking such an account
//! to a user with an enrolment link.
//!
//! | Route | Purpose |
//! |---|---|
//! | `POST /upstream/{provider}/start` | JSON: begin sign-in, or linking with `token` |
//! | `GET /upstream/{provider}/callback` | the provider's redirect: finish |
//!
//! An account signs in as a user only if it was linked to that user: by redeeming an
//! invitation or setup link with it, or by an admin creating the `Credential`. Nothing is
//! created on first sign-in. Upstream sign-ins carry no `amr` value (RFC 8176 defines none for
//! federation) and therefore never satisfy elevation, which needs a passkey.
//!
//! The pending request (`state`, `nonce`, PKCE verifier and purpose) is sealed into a `__Host-`
//! cookie with `SameSite=Lax`, the strictest setting that still accompanies the provider's
//! top-level redirect back. `state` is compared in constant time and accepted once
//! (RFC 6749 §10.12, RFC 9700 §2.1). The callback answers with HTML; errors never echo the
//! provider's text.

pub mod http;
pub mod provider;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use genkan_core::clock::{Clock, UnixTime};
use genkan_core::crypto::{ct_eq, hex, random, sha256};
use genkan_oauth::authorize::Authentication;
use genkan_oauth::endpoints::{FLOW_COOKIE, complete_authorization, open_flow};
use genkan_oauth::{OneTimeIds, Use};
use genkan_store::{
    Consume, CreateCredential, CredentialStore, Directory, GrantStore, NewExternal, SetupStore,
    external_credential_name,
};
use genkan_ui::i18n::Lang;
use genkan_ui::pages::{accept_language, error_page, notice_page};
use serde::{Deserialize, Serialize};

use self::http::HttpClient;
use self::provider::{Exchange, Kind, Provider};
use crate::problem::Problem;
use crate::{
    NO_REQUEST, SignIn, check_request, clear_cookie, cookie, internal, json, parse,
    valid_setup_token,
};

/// Cookie holding the sealed pending upstream request.
pub const UPSTREAM_COOKIE: &str = "__Host-genkan-upstream";
const PURPOSE: &str = "genkan/upstream/v1";
/// How long the user may spend at the provider.
const LIFETIME: Duration = Duration::from_mins(10);

const UNKNOWN_PROVIDER: Problem = Problem::new(
    StatusCode::NOT_FOUND,
    "unknown-provider",
    "This provider is not enabled.",
);
const NEEDS_PASSKEY: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "needs-passkey",
    "This sign-in needs a passkey.",
);

/// Upstream sign-in state shared by the handlers.
pub struct Upstream<D, G, C, K, S, H> {
    /// Passkey sign-in (its authorization server, credentials and enrolment tokens).
    pub sign_in: Arc<SignIn<D, G, C, K, S>>,
    /// The enabled providers.
    pub providers: Vec<Provider>,
    /// Outgoing HTTPS.
    pub http: H,
    /// `state` values already returned by a provider.
    pub used_states: OneTimeIds,
}

impl<D, G, C, K, S, H> std::fmt::Debug for Upstream<D, G, C, K, S, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("providers", &self.providers)
            .finish_non_exhaustive()
    }
}

type Shared<D, G, C, K, S, H> = Arc<Upstream<D, G, C, K, S, H>>;

/// The upstream routes.
pub fn router<D, G, C, K, S, H>(service: Shared<D, G, C, K, S, H>) -> Router
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
    H: HttpClient,
{
    Router::new()
        .route(
            "/upstream/{provider}/start",
            post(start::<D, G, C, K, S, H>),
        )
        .route(
            "/upstream/{provider}/callback",
            get(callback::<D, G, C, K, S, H>),
        )
        .with_state(service)
}

/// Sealed into [`UPSTREAM_COOKIE`].
#[derive(Debug, Serialize, Deserialize)]
struct Pending {
    id: String,
    provider: String,
    state: String,
    nonce: String,
    verifier: String,
    /// The enrolment token, when linking.
    link: Option<Enrollment>,
    expires_at: UnixTime,
}

/// Pins an in-flight linking ceremony to the token's original user incarnation.
#[derive(Debug, Serialize, Deserialize)]
struct Enrollment {
    token: String,
    user: genkan_store::UserReference,
}

#[derive(Debug, Deserialize)]
struct StartRequest {
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Serialize)]
struct StartResponse {
    redirect_to: String,
}

fn redirect_uri(issuer: &str, kind: Kind) -> String {
    format!("{issuer}/upstream/{}/callback", kind.id())
}

fn random_text<const N: usize>() -> Result<String, Problem> {
    Ok(URL_SAFE_NO_PAD.encode(random::<N>().map_err(internal)?))
}

async fn start<D, G, C, K, S, H>(
    State(service): State<Shared<D, G, C, K, S, H>>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
    H: HttpClient,
{
    let result: Result<Response, Problem> = async {
        let sign_in = &service.sign_in;
        check_request(&headers, sign_in.oauth.issuer.as_str())?;
        let provider = Kind::from_id(&provider)
            .and_then(|kind| service.providers.iter().find(|p| p.kind() == kind))
            .ok_or(UNKNOWN_PROVIDER)?;
        let request: StartRequest = parse(&body)?;
        let now = sign_in.oauth.now();
        let link = if let Some(token) = &request.token {
            // Linking: capture ownership before leaving for the provider.
            let (stored, _) =
                valid_setup_token(&sign_in.setup, &sign_in.oauth.directory, token, now).await?;
            Some(Enrollment {
                token: token.clone(),
                user: stored.user,
            })
        } else {
            // Signing in: there must be a pending request, and it must not ask for elevation.
            let flow = cookie(&headers, FLOW_COOKIE)
                .and_then(|sealed| open_flow(&sign_in.oauth, sealed))
                .ok_or(NO_REQUEST)?;
            if flow.request.is_elevated() {
                return Err(NEEDS_PASSKEY);
            }
            None
        };
        let pending = Pending {
            id: hex(&random::<16>().map_err(internal)?),
            provider: provider.kind().id().to_owned(),
            state: random_text::<32>()?,
            nonce: random_text::<32>()?,
            verifier: random_text::<32>()?,
            link,
            expires_at: now.saturating_add(LIFETIME),
        };
        let challenge = URL_SAFE_NO_PAD.encode(sha256(pending.verifier.as_bytes()));
        let url = provider.authorize_url(
            &redirect_uri(sign_in.oauth.issuer.as_str(), provider.kind()),
            &pending.state,
            &pending.nonce,
            &challenge,
        );
        let sealed = serde_json::to_vec(&pending)
            .map_err(internal)
            .and_then(|json| sign_in.oauth.sealer.seal(PURPOSE, &json).map_err(internal))?;
        let mut response = json(StatusCode::OK, &StartResponse { redirect_to: url });
        let cookie = format!(
            "{UPSTREAM_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
            LIFETIME.as_secs()
        );
        if let Ok(value) = HeaderValue::try_from(cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        Ok(response)
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

/// A failed callback: an HTML page in the user's language, never the provider's text.
fn failure(lang: Lang, detail: &str) -> Response {
    let mut response = error_page(lang, detail);
    clear_cookie(&mut response, UPSTREAM_COOKIE, "Lax");
    response
}

#[expect(
    clippy::too_many_lines,
    reason = "the callback's checks run in protocol order; splitting them would hide the order"
)]
async fn callback<D, G, C, K, S, H>(
    State(service): State<Shared<D, G, C, K, S, H>>,
    Path(provider): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
    H: HttpClient,
{
    let lang = Lang::negotiate(None, accept_language(&headers));
    let m = lang.messages();
    let sign_in = &service.sign_in;
    let oauth = &sign_in.oauth;
    let now = oauth.now();
    let params: Vec<(String, String)> =
        form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let param = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    let pending: Option<Pending> = cookie(&headers, UPSTREAM_COOKIE)
        .and_then(|sealed| oauth.sealer.open(PURPOSE, sealed))
        .and_then(|json| serde_json::from_slice(&json).ok());
    let Some(pending) = pending.filter(|p| p.expires_at > now && p.provider == provider) else {
        return failure(lang, m.upstream_failed);
    };
    let Some(provider) = Kind::from_id(&pending.provider)
        .and_then(|kind| service.providers.iter().find(|p| p.kind() == kind))
    else {
        return failure(lang, m.upstream_failed);
    };
    // The provider refused, or the user cancelled (RFC 6749 §4.1.2.1).
    let (Some(code), Some(state)) = (param("code"), param("state")) else {
        return failure(lang, m.upstream_failed);
    };
    if !ct_eq(state.as_bytes(), pending.state.as_bytes())
        || service
            .used_states
            .first_use(&pending.id, pending.expires_at, "", now)
            != Use::First
    {
        return failure(lang, m.upstream_failed);
    }
    let exchange = Exchange {
        code,
        verifier: &pending.verifier,
        redirect_uri: &redirect_uri(oauth.issuer.as_str(), provider.kind()),
        nonce: &pending.nonce,
    };
    let subject = match provider.identify(&service.http, exchange, now).await {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(%error, provider = provider.kind().id(), "upstream sign-in failed");
            return failure(lang, m.upstream_failed);
        }
    };
    let issuer = provider.kind().issuer();
    let name = external_credential_name(issuer, &subject);
    let linked = match sign_in.credentials.linked_user(&name).await {
        Ok(linked) => linked,
        Err(error) => {
            tracing::error!(%error, "credential lookup failed");
            return failure(lang, m.generic_error);
        }
    };

    let Some(token) = pending.link else {
        // Signing in.
        let Some(user) = linked else {
            tracing::info!(
                provider = provider.kind().id(),
                "an unlinked account tried to sign in"
            );
            return failure(lang, m.upstream_not_linked);
        };
        let active =
            matches!(oauth.directory.user_by_reference(&user).await, Ok(Some(u)) if !u.disabled);
        let Some(flow) = cookie(&headers, FLOW_COOKIE).filter(|_| active) else {
            return failure(lang, m.upstream_failed);
        };
        let authentication = Authentication {
            user: user.clone(),
            auth_time: now,
            amr: Vec::new(),
        };
        return complete_authorization(oauth, flow, authentication).map_or_else(
            |_| failure(lang, m.upstream_failed),
            |location| {
                tracing::info!(user = %user.name, provider = provider.kind().id(), "signed in upstream");
                let mut response = StatusCode::SEE_OTHER.into_response();
                if let Ok(value) = HeaderValue::try_from(location) {
                    response.headers_mut().insert(header::LOCATION, value);
                }
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                clear_cookie(&mut response, UPSTREAM_COOKIE, "Lax");
                clear_cookie(&mut response, FLOW_COOKIE, "Lax");
                response
            },
        );
    };

    // Linking with an enrolment link: same single-use gate as enrolling a passkey.
    if linked.is_some() {
        return failure(lang, m.upstream_already_linked);
    }
    let Ok((stored, _)) =
        valid_setup_token(&sign_in.setup, &oauth.directory, &token.token, now).await
    else {
        return failure(lang, m.setup_invalid);
    };
    if stored.user != token.user {
        return failure(lang, m.setup_invalid);
    }
    match sign_in.setup.consume(&stored).await {
        Ok(Consume::Consumed) => {}
        Ok(Consume::AlreadyUsed) => return failure(lang, m.setup_invalid),
        Err(error) => {
            tracing::error!(%error, "consuming the enrolment token failed");
            return failure(lang, m.generic_error);
        }
    }
    let external = NewExternal {
        name,
        user: stored.user.clone(),
        kind: provider.kind().credential_type(),
        issuer: issuer.to_owned(),
        subject,
    };
    match sign_in.credentials.link(&external).await {
        Ok(CreateCredential::Created) => {
            tracing::info!(user = %stored.user.name, provider = provider.kind().id(), "upstream account linked");
            let mut response = notice_page(lang, m.upstream_linked_title, m.upstream_linked_body);
            clear_cookie(&mut response, UPSTREAM_COOKIE, "Lax");
            response
        }
        Ok(CreateCredential::AlreadyExists) => failure(lang, m.upstream_already_linked),
        Err(error) => {
            tracing::error!(%error, "linking the account failed");
            failure(lang, m.generic_error)
        }
    }
}

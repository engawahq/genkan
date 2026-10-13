#![doc = include_str!("../README.md")]

pub mod pages;
pub mod passkeys;
pub mod problem;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use genkan_core::clock::{Clock, UnixTime};
use genkan_core::crypto::{ct_eq, hash_secret, hex, random};
use genkan_oauth::authorize::Authentication;
use genkan_oauth::endpoints::{FLOW_COOKIE, complete_authorization};
use genkan_oauth::{AuthorizationServer, OneTimeIds, Use};
use genkan_store::{
    Consume, CreateCredential, CredentialStore, Directory, GrantStore, NewPasskey, SetupStore,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid,
};

use crate::passkeys::{Passkeys, credential_name};
use crate::problem::Problem;

/// Cookie holding the sealed WebAuthn ceremony state (`SameSite=Strict`).
///
/// webauthn-rs expects relying parties to keep ceremony state on the server. Sealing it with a
/// key that exists only in this process, bound to a purpose and an expiry, and recording each
/// ceremony ID once it has verified ([`SignIn::used_ceremonies`]) gives the same protection
/// against replay without a storage write before authentication.
pub const CEREMONY_COOKIE: &str = "__Host-genkan-webauthn";
const REGISTRATION_PURPOSE: &str = "genkan/registration/v1";
const SIGN_IN_PURPOSE: &str = "genkan/sign-in/v1";
/// How long a ceremony may take (WebAuthn Level 3 recommends 300 s for UV-required ceremonies).
const CEREMONY_LIFETIME: std::time::Duration = std::time::Duration::from_mins(5);
/// Authentication methods asserted by a passkey sign-in (RFC 8176).
///
/// `swk`: proof of possession of a key. Attestation is `none`, so a hardware-backed key cannot be
/// claimed and `hwk` is not used. `mfa`: the authenticator verified the user with a PIN or
/// biometric in addition to possession, a multi-factor cryptographic authenticator in NIST SP
/// 800-63B-4 terms.
pub const PASSKEY_AMR: [&str; 2] = ["swk", "mfa"];

/// Sign-in state shared by the handlers.
#[derive(Debug)]
pub struct SignIn<D, G, C, K, S> {
    /// The authorization server whose pending requests sign-ins complete.
    pub oauth: Arc<AuthorizationServer<D, G, C>>,
    /// The relying party.
    pub passkeys: Passkeys,
    /// Stored passkeys.
    pub credentials: K,
    /// The setup token.
    pub setup: S,
    /// Ceremony identifiers already used.
    pub used_ceremonies: OneTimeIds,
}

type Shared<D, G, C, K, S> = Arc<SignIn<D, G, C, K, S>>;

/// The sign-in routes.
pub fn router<D, G, C, K, S>(service: Shared<D, G, C, K, S>) -> Router
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    Router::new()
        .route("/setup/options", post(setup_options::<D, G, C, K, S>))
        .route("/setup", post(setup_finish::<D, G, C, K, S>))
        .route("/login/options", post(login_options::<D, G, C, K, S>))
        .route("/login", post(login_finish::<D, G, C, K, S>))
        .with_state(service)
}

const CROSS_SITE: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "cross-site",
    "This request must come from the sign-in page.",
);
const NOT_JSON: Problem =
    Problem::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "not-json", "Send JSON.");
const BAD_REQUEST: Problem = Problem::new(
    StatusCode::BAD_REQUEST,
    "bad-request",
    "The request is malformed.",
);
pub(crate) const SETUP_INVALID: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "setup-invalid",
    "This setup link is invalid, used or expired. Ask your cluster administrator for a new one.",
);
const CEREMONY_EXPIRED: Problem = Problem::new(
    StatusCode::BAD_REQUEST,
    "ceremony-expired",
    "This passkey prompt expired. Start again.",
);
const PASSKEY_FAILED: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "passkey-failed",
    "That passkey could not be verified.",
);
pub(crate) const NO_REQUEST: Problem = Problem::new(
    StatusCode::BAD_REQUEST,
    "no-request",
    "There is no sign-in in progress. Return to the application and start again.",
);

/// Cross-site request protection for the JSON endpoints: `Sec-Fetch-Site: same-origin`, or, for
/// browsers that do not send Fetch Metadata, an `Origin` equal to the issuer. Requests with
/// neither are refused. The JSON content type adds a CORS preflight for any cross-origin caller.
pub(crate) fn check_request(headers: &HeaderMap, issuer: &str) -> Result<(), Problem> {
    let header = |name| {
        headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
    };
    let allowed = match (header("sec-fetch-site"), header(header::ORIGIN.as_str())) {
        (Some(site), _) => site == "same-origin",
        (None, Some(origin)) => origin == issuer,
        (None, None) => false,
    };
    if !allowed {
        return Err(CROSS_SITE);
    }
    let json = header(header::CONTENT_TYPE.as_str())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
    if json { Ok(()) } else { Err(NOT_JSON) }
}

pub(crate) fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, Problem> {
    serde_json::from_slice(body).map_err(|_malformed| BAD_REQUEST)
}

/// Reads a cookie by name from the request.
#[must_use]
pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

fn set_cookie(response: &mut Response, name: &str, value: &str, max_age: u64) {
    let cookie =
        format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}");
    if let Ok(value) = HeaderValue::try_from(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub(crate) fn clear_cookie(response: &mut Response, name: &str, same_site: &str) {
    let cookie = format!("{name}=; Path=/; Secure; HttpOnly; SameSite={same_site}; Max-Age=0");
    if let Ok(value) = HeaderValue::try_from(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub(crate) fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(crate) fn internal(_error: impl std::fmt::Display) -> Problem {
    tracing::error!(reason = "internal_error", "sign-in failed");
    Problem::internal()
}

/// Sealed ceremony state.
#[derive(Debug, Serialize, Deserialize)]
struct Ceremony<T> {
    id: String,
    state: T,
    /// For registration: the user the setup token was for.
    user: Option<String>,
    expires_at: UnixTime,
}

fn seal<T: Serialize, D, G, C>(
    oauth: &AuthorizationServer<D, G, C>,
    purpose: &str,
    state: T,
    user: Option<String>,
    now: UnixTime,
) -> Result<String, Problem> {
    let ceremony = Ceremony {
        id: hex(&random::<16>().map_err(internal)?),
        state,
        user,
        expires_at: now.saturating_add(CEREMONY_LIFETIME),
    };
    let json = serde_json::to_vec(&ceremony).map_err(internal)?;
    oauth.sealer.seal(purpose, &json).map_err(internal)
}

fn open<T: DeserializeOwned, D, G, C>(
    oauth: &AuthorizationServer<D, G, C>,
    headers: &HeaderMap,
    purpose: &str,
    now: UnixTime,
) -> Result<Ceremony<T>, Problem> {
    let sealed = cookie(headers, CEREMONY_COOKIE).ok_or(CEREMONY_EXPIRED)?;
    let ceremony: Ceremony<T> = oauth
        .sealer
        .open(purpose, sealed)
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or(CEREMONY_EXPIRED)?;
    if ceremony.expires_at <= now {
        Err(CEREMONY_EXPIRED)
    } else {
        Ok(ceremony)
    }
}

#[derive(Deserialize)]
struct SetupOptionsRequest {
    token: String,
}

#[derive(Deserialize)]
struct SetupRequest {
    token: String,
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Serialize)]
struct SetupResponse<'a> {
    username: &'a str,
}

/// Checks a presented setup token against the stored one. Returns the stored token.
pub(crate) async fn valid_setup_token<S: SetupStore>(
    setup: &S,
    presented: &str,
    now: UnixTime,
) -> Result<genkan_store::SetupToken, Problem> {
    let stored = setup
        .load(presented)
        .await
        .map_err(internal)?
        .ok_or(SETUP_INVALID)?;
    let matches = ct_eq(
        hash_secret(presented.as_bytes()).as_bytes(),
        stored.token_hash.as_bytes(),
    );
    if !matches || stored.expires_at <= now {
        return Err(SETUP_INVALID);
    }
    Ok(stored)
}

async fn setup_options<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let mut identity = None;
    let result: Result<Response, Problem> = async {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let request: SetupOptionsRequest = parse(&body)?;
        let now = service.oauth.now();
        let token = valid_setup_token(&service.setup, &request.token, now).await?;
        let user = service
            .oauth
            .directory
            .user(&token.user)
            .await
            .map_err(internal)?
            .ok_or_else(|| {
                tracing::error!(
                    reason = "user_unavailable",
                    "the setup token names a user that does not exist"
                );
                SETUP_INVALID
            })?;
        identity = Some(user);
        let user = identity.as_ref().ok_or(SETUP_INVALID)?;
        let handle = Uuid::parse_str(&user.subject).map_err(internal)?;
        let display = user.display_name.as_deref().unwrap_or(&user.username);
        let (options, state) = service
            .passkeys
            .begin_registration(handle, &user.username, display)
            .map_err(internal)?;
        let sealed = seal::<PasskeyRegistration, _, _, _>(
            &service.oauth,
            REGISTRATION_PURPOSE,
            state,
            Some(user.name.clone()),
            now,
        )?;
        let mut response = json(StatusCode::OK, &options);
        set_cookie(
            &mut response,
            CEREMONY_COOKIE,
            &sealed,
            CEREMONY_LIFETIME.as_secs(),
        );
        Ok(response)
    }
    .await;
    match &result {
        Ok(_) => {
            tracing::info!(target: "genkan::audit", event = "auth.passkey_enrollment", phase = "start", outcome = "success", method = "passkey", user = identity.as_ref().map(|u| u.name.as_str()), subject = identity.as_ref().map(|u| u.subject.as_str()), "passkey enrollment started");
        }
        Err(problem) => {
            tracing::warn!(target: "genkan::audit", event = "auth.passkey_enrollment", phase = "start", outcome = "failure", method = "passkey", reason = problem.kind, user = identity.as_ref().map(|u| u.name.as_str()), subject = identity.as_ref().map(|u| u.subject.as_str()), "passkey enrollment failed");
        }
    }
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn setup_finish<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let mut user = None;
    let result: Result<Response, Problem> = async {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let request: SetupRequest = parse(&body)?;
        let now = service.oauth.now();
        let ceremony: Ceremony<PasskeyRegistration> =
            open(&service.oauth, &headers, REGISTRATION_PURPOSE, now)?;
        let token = valid_setup_token(&service.setup, &request.token, now).await?;
        user = Some(token.user.clone());
        // The ceremony must have been started with this token's user.
        if ceremony.user.as_deref() != Some(token.user.as_str()) {
            return Err(SETUP_INVALID);
        }
        let passkey: Passkey = service
            .passkeys
            .finish_registration(&request.credential, &ceremony.state)
            .map_err(|_error| PASSKEY_FAILED)?;
        if service
            .used_ceremonies
            .first_use(&ceremony.id, ceremony.expires_at, "", now)
            != Use::First
        {
            return Err(CEREMONY_EXPIRED);
        }
        // Consume the token before storing the passkey: if two registrations race, only the one
        // that consumed the token may add a credential.
        if service.setup.consume(&token).await.map_err(internal)? == Consume::AlreadyUsed {
            return Err(SETUP_INVALID);
        }
        let credential_id: Vec<u8> = AsRef::<[u8]>::as_ref(passkey.cred_id()).to_vec();
        let label = request
            .label
            .map(|l| l.chars().take(64).collect::<String>());
        let stored = NewPasskey {
            name: credential_name(&credential_id),
            user: token.user.clone(),
            credential_id: URL_SAFE_NO_PAD.encode(&credential_id),
            record: serde_json::to_string(&passkey).map_err(internal)?,
            label,
        };
        match service
            .credentials
            .create(&stored)
            .await
            .map_err(internal)?
        {
            CreateCredential::Created => {}
            CreateCredential::AlreadyExists => {
                return Err(Problem::new(
                    StatusCode::CONFLICT,
                    "passkey-exists",
                    "This passkey is already registered.",
                ));
            }
        }
        let mut response = json(
            StatusCode::CREATED,
            &SetupResponse {
                username: &token.user,
            },
        );
        clear_cookie(&mut response, CEREMONY_COOKIE, "Strict");
        Ok(response)
    }
    .await;
    match &result {
        Ok(_) => {
            tracing::info!(target: "genkan::audit", event = "auth.passkey_enrollment", phase = "finish", outcome = "success", method = "passkey", user = user.as_deref(), "passkey enrolled");
        }
        Err(problem) => {
            tracing::warn!(target: "genkan::audit", event = "auth.passkey_enrollment", phase = "finish", outcome = "failure", method = "passkey", reason = problem.kind, user = user.as_deref(), "passkey enrollment failed");
        }
    }
    result.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Deserialize)]
struct SignInRequest {
    credential: PublicKeyCredential,
}

#[derive(Serialize)]
struct SignInResponse {
    redirect_to: String,
}

async fn login_options<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let result: Result<Response, Problem> = (|| {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let now = service.oauth.now();
        let (options, state) = service.passkeys.begin_sign_in().map_err(internal)?;
        let sealed = seal::<DiscoverableAuthentication, _, _, _>(
            &service.oauth,
            SIGN_IN_PURPOSE,
            state,
            None,
            now,
        )?;
        let mut response = json(StatusCode::OK, &options);
        set_cookie(
            &mut response,
            CEREMONY_COOKIE,
            &sealed,
            CEREMONY_LIFETIME.as_secs(),
        );
        Ok(response)
    })();
    match &result {
        Ok(_) => {
            tracing::info!(target: "genkan::audit", event = "auth.passkey_options", outcome = "success", method = "passkey", "passkey options accepted");
        }
        Err(problem) => {
            tracing::warn!(target: "genkan::audit", event = "auth.passkey_options", outcome = "failure", method = "passkey", reason = problem.kind, "passkey options failed");
        }
    }
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn login_finish<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let mut identity = None;
    let result: Result<Response, Problem> = async {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let request: SignInRequest = parse(&body)?;
        let now = service.oauth.now();
        let flow = cookie(&headers, FLOW_COOKIE).ok_or(NO_REQUEST)?.to_owned();
        let ceremony: Ceremony<DiscoverableAuthentication> =
            open(&service.oauth, &headers, SIGN_IN_PURPOSE, now)?;

        // Same answer for every failure, so responses do not reveal which users or credentials
        // exist.
        let (handle, credential_id) = service
            .passkeys
            .identify(&request.credential)
            .map_err(|_unknown| PASSKEY_FAILED)?;
        let stored = service
            .credentials
            .get(&credential_name(&credential_id))
            .await
            .map_err(internal)?
            .ok_or(PASSKEY_FAILED)?;
        let user = service
            .oauth
            .directory
            .user(&stored.user)
            .await
            .map_err(internal)?
            .ok_or(PASSKEY_FAILED)?;
        identity = Some(user);
        let user = identity.as_ref().ok_or(PASSKEY_FAILED)?;
        // The user handle in the assertion must be the credential owner's (WebAuthn Level 3 §7.2).
        if user.disabled || user.subject != handle.to_string() {
            return Err(PASSKEY_FAILED);
        }
        let passkey: Passkey = serde_json::from_str(&stored.record).map_err(internal)?;
        service
            .passkeys
            .finish_sign_in(&request.credential, ceremony.state, &passkey)
            .map_err(|_error| PASSKEY_FAILED)?;
        // The challenge is single-use once it has produced a successful assertion.
        if service
            .used_ceremonies
            .first_use(&ceremony.id, ceremony.expires_at, "", now)
            != Use::First
        {
            return Err(CEREMONY_EXPIRED);
        }

        let authentication = Authentication {
            user: user.name.clone(),
            auth_time: now,
            amr: PASSKEY_AMR.iter().map(|m| (*m).to_owned()).collect(),
        };
        let location = complete_authorization(&service.oauth, &flow, authentication)
            .map_err(|_error| NO_REQUEST)?;
        let mut response = json(
            StatusCode::OK,
            &SignInResponse {
                redirect_to: location,
            },
        );
        clear_cookie(&mut response, CEREMONY_COOKIE, "Strict");
        clear_cookie(&mut response, FLOW_COOKIE, "Lax");
        Ok(response)
    }
    .await;
    match &result {
        Ok(_) => {
            tracing::info!(target: "genkan::audit", event = "auth.sign_in", outcome = "success", method = "passkey", user = identity.as_ref().map(|u| u.name.as_str()), subject = identity.as_ref().map(|u| u.subject.as_str()), "signed in with a passkey");
        }
        Err(problem) => {
            tracing::warn!(target: "genkan::audit", event = "auth.sign_in", outcome = "failure", method = "passkey", reason = problem.kind, user = identity.as_ref().map(|u| u.name.as_str()), subject = identity.as_ref().map(|u| u.subject.as_str()), "passkey sign-in failed");
        }
    }
    result.unwrap_or_else(IntoResponse::into_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn same_origin_checks() {
        let issuer = "https://login.example.com";
        let json = ("content-type", "application/json; charset=utf-8");
        assert!(
            check_request(&headers(&[("sec-fetch-site", "same-origin"), json]), issuer).is_ok()
        );
        assert!(check_request(&headers(&[("origin", issuer), json]), issuer).is_ok());
        assert_eq!(
            check_request(
                &headers(&[("sec-fetch-site", "cross-site"), ("origin", issuer), json]),
                issuer
            ),
            Err(CROSS_SITE)
        );
        assert_eq!(
            check_request(&headers(&[("sec-fetch-site", "same-site"), json]), issuer),
            Err(CROSS_SITE)
        );
        assert_eq!(
            check_request(
                &headers(&[("origin", "https://evil.example"), json]),
                issuer
            ),
            Err(CROSS_SITE)
        );
        assert_eq!(check_request(&headers(&[json]), issuer), Err(CROSS_SITE));
        assert_eq!(
            check_request(
                &headers(&[
                    ("sec-fetch-site", "same-origin"),
                    ("content-type", "text/plain")
                ]),
                issuer
            ),
            Err(NOT_JSON)
        );
    }

    #[test]
    fn reads_cookies() {
        let h = headers(&[("cookie", "a=1; __Host-genkan-flow=xyz"), ("cookie", "b=2")]);
        assert_eq!(cookie(&h, FLOW_COOKIE), Some("xyz"));
        assert_eq!(cookie(&h, "b"), Some("2"));
        assert_eq!(cookie(&h, "c"), None);
    }

    #[test]
    fn internal_diagnostics_do_not_format_secret_bearing_errors() {
        let capture = genkan_test_support::logging::Capture::new();
        let problem = tracing::dispatcher::with_default(&capture.dispatch(), || {
            internal("secret-bearing-signin-error-sentinel")
        });
        assert_eq!(problem, Problem::internal());
        let records = capture.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["target"], "genkan_signin");
        assert_eq!(records[0]["fields"]["reason"], "internal_error");
        assert!(
            !serde_json::to_string(&records)
                .unwrap()
                .contains("secret-bearing-signin-error-sentinel")
        );
    }
}

//! The authorization endpoint (RFC 6749 §4.1.1, OIDC Core §3.1.2): validating the request,
//! keeping it while the user signs in, and answering with a code.
//!
//! Nothing here writes to storage. A validated request is sealed (AEAD under the process key)
//! into the `__Host-genkan-flow` cookie (`Secure; HttpOnly; SameSite=Lax`) until the user has
//! authenticated, and the resulting code is sealed too. Storing a record per unauthenticated
//! request would let anyone fill the store; Dex's per-request `AuthRequest` objects caused
//! exactly that ([Dex]). Keeping pre-authentication state sealed on the client follows Hydra's
//! AEAD-encoded flows and Kanidm's encrypted codes ([Hydra], [Kanidm]).
//!
//! [`validate`] checks in the order RFC 6749 §4.1.2.1 implies: the client and redirect URI first,
//! whose failures are shown locally and never redirected, then everything else, whose failures
//! go back to the client:
//!
//! - redirect URIs match exactly, except the port of loopback URIs (RFC 9700 §2.1);
//! - request objects and `registration` are refused (OIDC Core §3.1.2.6);
//! - only `response_type=code` with `response_mode=query`;
//! - PKCE S256 is required for every client, confidential ones included (RFC 9700 §2.1.1); `plain`
//!   is refused, as in OAuth 2.1;
//! - unknown scopes are ignored; `elevate` from a client not allowed to elevate is `invalid_scope`;
//! - the access-token audience is one value from the client's allowlist: the RFC 8707 `resource` if
//!   sent, otherwise the client's only audience, otherwise the client ID; an ambiguous or
//!   disallowed resource is `invalid_target` (RFC 9068 §3);
//! - `prompt=none` is always `login_required`, because there is no single sign-on session that
//!   could satisfy it silently (OIDC Core §3.1.2.1).
//!
//! Responses are `303 See Other` redirects and carry `iss` (RFC 9207). These answer the 307
//! redirect credential leak and the mix-up attack found in the formal analysis of OAuth 2.0 by
//! Fett, Küsters and Schmitz [\[FKS16\]][FKS16]; RFC 9700 §4.11.2 now forbids 307.
//!
//! # References
//!
//! - [FKS16] D. Fett, R. Küsters, and G. Schmitz, "A Comprehensive Formal Security Analysis of
//!   OAuth 2.0," in *Proc. 2016 ACM SIGSAC Conf. Computer and Communications Security (CCS '16)*,
//!   Vienna, Austria, 2016, pp. 1204–1215, doi: 10.1145/2976749.2978385.
//! - [Dex project][Dex], `storage/kubernetes/` and issues #1091, #1292, #1969, commit `05a2750`.
//! - [Ory Hydra][Hydra], `flow/flow_encoding.go`, commit `4174065`.
//! - [Kanidm project][Kanidm], `server/lib/src/idm/oauth2.rs`, commit `3331b8e`.
//!
//! [FKS16]: https://doi.org/10.1145/2976749.2978385
//! [Dex]: https://github.com/dexidp/dex/tree/05a275057112ba93e17db21f600b756f000f1c21
//! [Hydra]: https://github.com/ory/hydra/tree/4174065ffb052799890f7480f5360a877a67ffc1
//! [Kanidm]: https://github.com/kanidm/kanidm/tree/3331b8ed7f1541901ffe0c722f2a04c82897809c

use axum::http::Uri;
use genkan_core::clock::UnixTime;
use genkan_store::Client;
use serde::{Deserialize, Serialize};

use super::error::{ErrorCode, OAuthError};
use super::params::Params;
use super::pkce;

/// Scopes this server understands. Others are ignored (OIDC Core §3.1.2.1: "Scope values used
/// that are not understood by an implementation SHOULD be ignored").
pub const SUPPORTED_SCOPES: [&str; 4] = ["openid", "profile", "groups", "offline_access"];

/// Asks for a short-lived token carrying the user's elevated groups; understood only when
/// elevation is enabled.
///
/// kube-apiserver never sends a step-up challenge (RFC 9470) and RBAC sees only users and
/// groups, so privilege is expressed as extra groups in a separate token, decided when the token
/// is minted. See [`crate::endpoints::ELEVATED_GROUP_PREFIX`].
pub const ELEVATE_SCOPE: &str = "elevate";

/// A validated authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// `client_id`.
    pub client_id: String,
    /// The redirect URI, exactly as sent (it must be used verbatim for the response).
    pub redirect_uri: String,
    /// Recognised scopes, in request order, without duplicates.
    pub scopes: Vec<String>,
    /// Opaque client state, echoed back.
    pub state: Option<String>,
    /// OIDC nonce, copied into the ID token.
    pub nonce: Option<String>,
    /// PKCE S256 challenge.
    pub code_challenge: String,
    /// Access-token audience (RFC 8707 resource).
    pub audience: String,
    /// `prompt=login`: the user must authenticate again even with a session.
    pub force_login: bool,
    /// OIDC `max_age`, in seconds.
    pub max_age: Option<u64>,
    /// OIDC `login_hint`.
    pub login_hint: Option<String>,
}

impl AuthorizationRequest {
    /// Whether the request asks for elevated groups.
    #[must_use]
    pub fn is_elevated(&self) -> bool {
        self.scopes.iter().any(|s| s == ELEVATE_SCOPE)
    }

    /// Whether an ID token is requested.
    #[must_use]
    pub fn is_openid(&self) -> bool {
        self.scopes.iter().any(|s| s == "openid")
    }
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// The client or redirect URI cannot be trusted; show an error page and never redirect
    /// (RFC 6749 §4.1.2.1).
    Local(OAuthError),
    /// Redirect the error to the client.
    Redirect {
        /// Where to send it.
        redirect_uri: String,
        /// The client's state.
        state: Option<String>,
        /// The error.
        error: OAuthError,
    },
}

/// Whether `requested` matches a registered redirect URI: exact string comparison, except that
/// the port of a loopback `http` URI may differ (RFC 9700 §2.1, RFC 8252 §7.3).
#[must_use]
pub fn redirect_uri_allowed(client: &Client, requested: &str) -> bool {
    client
        .redirect_uris
        .iter()
        .any(|registered| registered == requested || loopback_match(registered, requested))
}

fn loopback_match(registered: &str, requested: &str) -> bool {
    let (Ok(a), Ok(b)) = (registered.parse::<Uri>(), requested.parse::<Uri>()) else {
        return false;
    };
    let loopback = |uri: &Uri| {
        uri.scheme_str() == Some("http") && matches!(uri.host(), Some("127.0.0.1" | "[::1]"))
    };
    let no_credentials = |uri: &Uri| uri.authority().is_some_and(|a| !a.as_str().contains('@'));
    loopback(&a)
        && loopback(&b)
        && no_credentials(&b)
        && a.host() == b.host()
        && a.path_and_query() == b.path_and_query()
        && !requested.contains('#')
}

/// Validates an authorization request against its client.
///
/// `client` is `None` when the `client_id` is unknown. The `elevate` scope is understood only if
/// `elevation` is enabled, and ignored otherwise like any unknown scope; when it is understood,
/// a client without [`Client::allow_elevation`] gets `invalid_scope`.
///
/// # Errors
///
/// [`Rejection::Local`] when the client or redirect URI is missing, unknown or unregistered;
/// [`Rejection::Redirect`] for everything else.
#[expect(
    clippy::too_many_lines,
    reason = "the checks follow RFC 6749 §4.1.2.1 in order; splitting them would hide that order"
)]
pub fn validate(
    params: &Params,
    client: Option<&Client>,
    elevation: bool,
) -> Result<AuthorizationRequest, Rejection> {
    let local = |d| Rejection::Local(OAuthError::new(ErrorCode::InvalidRequest, d));
    let client = client.ok_or_else(|| local("unknown or missing client_id"))?;
    let redirect_uri = params
        .get("redirect_uri")
        .ok_or_else(|| local("redirect_uri is required"))?;
    if !redirect_uri_allowed(client, redirect_uri) {
        return Err(local("redirect_uri is not registered for this client"));
    }

    let state = params.get("state").map(str::to_owned);
    let reject = |error, description| Rejection::Redirect {
        redirect_uri: redirect_uri.to_owned(),
        state: state.clone(),
        error: OAuthError::new(error, description),
    };

    if params.get("request").is_some() {
        return Err(reject(
            ErrorCode::RequestNotSupported,
            "request objects are not supported",
        ));
    }
    if params.get("registration").is_some() {
        return Err(reject(
            ErrorCode::RegistrationNotSupported,
            "registration is not supported",
        ));
    }
    match params.get("response_type") {
        Some("code") => {}
        Some(_) => {
            return Err(reject(
                ErrorCode::UnsupportedResponseType,
                "only response_type=code is supported",
            ));
        }
        None => {
            return Err(reject(
                ErrorCode::InvalidRequest,
                "response_type is required",
            ));
        }
    }
    if params.get("response_mode").is_some_and(|m| m != "query") {
        return Err(reject(
            ErrorCode::InvalidRequest,
            "only response_mode=query is supported",
        ));
    }

    // PKCE is required for every client (RFC 9700 §2.1.1), S256 only (OAuth 2.1).
    let Some(code_challenge) = params.get("code_challenge") else {
        return Err(reject(
            ErrorCode::InvalidRequest,
            "code_challenge is required",
        ));
    };
    if params.get("code_challenge_method") != Some("S256") {
        return Err(reject(
            ErrorCode::InvalidRequest,
            "code_challenge_method must be S256",
        ));
    }
    if !pkce::valid_s256_challenge(code_challenge) {
        return Err(reject(
            ErrorCode::InvalidRequest,
            "code_challenge is not a valid S256 challenge",
        ));
    }

    let mut scopes: Vec<String> = Vec::new();
    for scope in params.get("scope").unwrap_or_default().split(' ') {
        let elevate = elevation && scope == ELEVATE_SCOPE;
        // Refused rather than ignored: a client that expects elevation would otherwise get an
        // ordinary token and fail later, far from the cause (RFC 6749 §4.1.2.1 `invalid_scope`).
        if elevate && !client.allow_elevation {
            return Err(reject(
                ErrorCode::InvalidScope,
                "this client may not request the elevate scope",
            ));
        }
        let known = SUPPORTED_SCOPES.contains(&scope) || elevate;
        if known && !scopes.iter().any(|s| s == scope) {
            scopes.push(scope.to_owned());
        }
    }

    let audience = match (params.resources(), client.audiences.as_slice()) {
        ([], []) => client.id.clone(),
        ([], [only]) => only.clone(),
        ([], _) => {
            return Err(reject(
                ErrorCode::InvalidTarget,
                "resource is required for this client",
            ));
        }
        ([resource], allowed) if allowed.contains(resource) => resource.clone(),
        ([_], _) => {
            return Err(reject(
                ErrorCode::InvalidTarget,
                "resource is not allowed for this client",
            ));
        }
        (..) => {
            return Err(reject(
                ErrorCode::InvalidTarget,
                "exactly one resource is supported",
            ));
        }
    };

    let prompts: Vec<&str> = params
        .get("prompt")
        .map_or_else(Vec::new, |p| p.split(' ').collect());
    if prompts.contains(&"none") {
        if prompts.len() > 1 {
            return Err(reject(
                ErrorCode::InvalidRequest,
                "prompt=none cannot be combined with other values",
            ));
        }
        // There is no single sign-on session that could satisfy a silent sign-in, so it always
        // needs interaction (OIDC Core §3.1.2.1).
        return Err(reject(ErrorCode::LoginRequired, "the user must sign in"));
    }

    let max_age = match params.get("max_age") {
        None => None,
        Some(value) => match value.parse::<u64>() {
            Ok(age) => Some(age),
            Err(_) => {
                return Err(reject(
                    ErrorCode::InvalidRequest,
                    "max_age must be a non-negative integer",
                ));
            }
        },
    };

    Ok(AuthorizationRequest {
        client_id: client.id.clone(),
        redirect_uri: redirect_uri.to_owned(),
        scopes,
        state,
        nonce: params.get("nonce").map(str::to_owned),
        code_challenge: code_challenge.to_owned(),
        audience,
        force_login: prompts.contains(&"login") || max_age == Some(0),
        max_age,
        login_hint: params.get("login_hint").map(str::to_owned),
    })
}

/// A pending sign-in, sealed into the flow cookie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    /// The validated request.
    pub request: AuthorizationRequest,
    /// When the flow expires.
    pub expires_at: UnixTime,
}

/// The authenticated user, as established by a sign-in method (a passkey or an upstream
/// account).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication {
    /// `User` object name.
    pub user: String,
    /// When the user authenticated.
    pub auth_time: UnixTime,
    /// Authentication methods (RFC 8176).
    pub amr: Vec<String>,
}

/// Builds the redirect for a successful or failed response, with `iss` (RFC 9207).
#[must_use]
pub fn response_location(
    redirect_uri: &str,
    pairs: &[(&str, &str)],
    state: Option<&str>,
    issuer: &str,
) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        query.append_pair(key, value);
    }
    if let Some(state) = state {
        query.append_pair("state", state);
    }
    query.append_pair("iss", issuer);
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{separator}{}", query.finish())
}

#[cfg(test)]
mod tests {
    use genkan_store::ClientType;

    use super::*;

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn client(audiences: &[&str]) -> Client {
        Client {
            id: "kubectl".into(),
            display_name: None,
            kind: ClientType::Public,
            redirect_uris: vec![
                "http://127.0.0.1:8000/".into(),
                "https://app.example.com/cb?x=1".into(),
            ],
            audiences: audiences.iter().map(|a| (*a).into()).collect(),
            secret_hash: None,
            id_token_alg: genkan_keys::Algorithm::Es256,
            allow_elevation: false,
        }
    }

    fn params(extra: &str) -> Params {
        let base = format!(
            "client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid%20groups%20unknown%20openid&state=s1&code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        Params::parse(format!("{base}{extra}").as_bytes()).unwrap()
    }

    fn redirected(result: Result<AuthorizationRequest, Rejection>) -> ErrorCode {
        match result {
            Err(Rejection::Redirect { error, state, .. }) => {
                assert_eq!(state.as_deref(), Some("s1"));
                error.error
            }
            other => panic!("expected a redirected error, got {other:?}"),
        }
    }

    #[test]
    fn accepts_a_valid_request() {
        let request = validate(&params(""), Some(&client(&["kubernetes"])), false).unwrap();
        assert_eq!(request.scopes, ["openid", "groups"]);
        assert_eq!(request.audience, "kubernetes");
        assert!(request.is_openid());
        assert!(!request.force_login);
    }

    #[test]
    fn redirect_uri_rules() {
        let c = client(&[]);
        assert!(redirect_uri_allowed(&c, "http://127.0.0.1:8000/"));
        assert!(
            redirect_uri_allowed(&c, "http://127.0.0.1:53211/"),
            "any loopback port"
        );
        assert!(!redirect_uri_allowed(&c, "http://127.0.0.1:53211/other"));
        assert!(!redirect_uri_allowed(&c, "http://localhost:8000/"));
        assert!(!redirect_uri_allowed(&c, "http://u@127.0.0.1:1/"));
        assert!(redirect_uri_allowed(&c, "https://app.example.com/cb?x=1"));
        assert!(!redirect_uri_allowed(&c, "https://app.example.com/cb?x=2"));
        assert!(!redirect_uri_allowed(
            &c,
            "https://app.example.com/cb?x=1#f"
        ));
        assert!(!redirect_uri_allowed(
            &c,
            "https://app.example.com:443/cb?x=1"
        ));
    }

    #[test]
    fn untrusted_client_or_redirect_is_never_redirected() {
        assert!(matches!(
            validate(&params(""), None, false),
            Err(Rejection::Local(_))
        ));
        let p =
            Params::parse(b"client_id=kubectl&redirect_uri=https%3A%2F%2Fevil.example%2F").unwrap();
        assert!(matches!(
            validate(&p, Some(&client(&[])), false),
            Err(Rejection::Local(_))
        ));
    }

    #[test]
    fn errors_are_redirected_with_state() {
        let c = client(&["kubernetes", "other"]);
        assert_eq!(
            redirected(validate(&params("&resource=nope"), Some(&c), false)),
            ErrorCode::InvalidTarget
        );
        assert_eq!(
            redirected(validate(&params(""), Some(&c), false)),
            ErrorCode::InvalidTarget,
            "ambiguous"
        );
        assert_eq!(
            redirected(validate(
                &params("&resource=kubernetes&resource=other"),
                Some(&c),
                false
            )),
            ErrorCode::InvalidTarget
        );
        let c = client(&[]);
        assert_eq!(
            redirected(validate(&params("&prompt=none"), Some(&c), false)),
            ErrorCode::LoginRequired
        );
        assert_eq!(
            redirected(validate(&params("&prompt=none%20login"), Some(&c), false)),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            redirected(validate(&params("&request=eyJ"), Some(&c), false)),
            ErrorCode::RequestNotSupported
        );
        assert_eq!(
            redirected(validate(&params("&max_age=-1"), Some(&c), false)),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            redirected(validate(
                &params("&response_mode=fragment"),
                Some(&c),
                false
            )),
            ErrorCode::InvalidRequest
        );
        let no_pkce = Params::parse(
            b"client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&state=s1",
        )
        .unwrap();
        assert_eq!(
            redirected(validate(&no_pkce, Some(&c), false)),
            ErrorCode::InvalidRequest
        );
        let plain = Params::parse(
            format!("client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&state=s1&code_challenge={CHALLENGE}&code_challenge_method=plain").as_bytes(),
        )
        .unwrap();
        assert_eq!(
            redirected(validate(&plain, Some(&c), false)),
            ErrorCode::InvalidRequest
        );
        let token = Params::parse(
            format!("client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=token&state=s1&code_challenge={CHALLENGE}&code_challenge_method=S256").as_bytes(),
        )
        .unwrap();
        assert_eq!(
            redirected(validate(&token, Some(&c), false)),
            ErrorCode::UnsupportedResponseType
        );
    }

    #[test]
    fn audience_defaults() {
        assert_eq!(
            validate(&params(""), Some(&client(&[])), false)
                .unwrap()
                .audience,
            "kubectl"
        );
        assert!(
            validate(&params("&max_age=0"), Some(&client(&[])), false)
                .unwrap()
                .force_login
        );
        assert!(
            validate(&params("&prompt=login"), Some(&client(&[])), false)
                .unwrap()
                .force_login
        );
    }

    #[test]
    fn elevate_needs_the_feature_and_the_client_opt_in() {
        let elevate = Params::parse(
            format!("client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid%20elevate&state=s1&code_challenge={CHALLENGE}&code_challenge_method=S256").as_bytes(),
        )
        .unwrap();
        let mut c = client(&[]);
        // Elevation off: ignored like any unknown scope, whatever the client allows.
        for allow in [false, true] {
            c.allow_elevation = allow;
            let request = validate(&elevate, Some(&c), false).unwrap();
            assert!(!request.is_elevated());
        }
        // Elevation on: only a client that opted in may ask.
        c.allow_elevation = false;
        assert_eq!(
            redirected(validate(&elevate, Some(&c), true)),
            ErrorCode::InvalidScope
        );
        assert!(
            validate(&params(""), Some(&c), true).is_ok(),
            "requests without elevate are unaffected"
        );
        c.allow_elevation = true;
        assert!(validate(&elevate, Some(&c), true).unwrap().is_elevated());
    }

    #[test]
    fn response_location_appends_iss_and_state() {
        let location = response_location(
            "https://app.example.com/cb?x=1",
            &[("code", "a b")],
            Some("s"),
            "https://idp",
        );
        assert_eq!(
            location,
            "https://app.example.com/cb?x=1&code=a+b&state=s&iss=https%3A%2F%2Fidp"
        );
    }
}

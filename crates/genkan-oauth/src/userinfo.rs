//! The UserInfo endpoint (OpenID Connect Core 1.0 §5.3).
//!
//! It accepts this issuer's own access tokens (`typ: at+jwt`, RFC 9068) as bearer tokens in the
//! `Authorization` header (RFC 6750 §2.1), verifies them offline against the published keys,
//! and answers with the user's current claims, so a user disabled since the token was issued
//! gets nothing. Claims follow the granted scopes: `sub` always, `preferred_username` and `name`
//! with `profile`, `groups` with `groups` (never elevated groups).
//!
//! - `GET` and `POST` are both served, as §5.3 requires. The token is read only from the header;
//!   form-body and query tokens are not accepted.
//! - Only ES256 tokens with `typ: at+jwt`, this issuer's `iss`, a `client_id` and an unexpired
//!   `exp` are accepted, so an ID token cannot be used here. Any audience is accepted.
//! - A token without the `openid` scope gets `403 insufficient_scope`; a missing token gets a bare
//!   `Bearer` challenge, and a bad one `invalid_token` (RFC 6750 §3).
//! - Responses carry `Cache-Control: no-store`.
//!
//! The directory resolves the immutable `sub` UID through metadata, then directly reads the
//! current user and verifies that UID before returning claims. Neither a renamed/recreated
//! object nor stale index metadata can substitute another identity. No additional access-token
//! claim is required, so previously issued tokens remain usable. The response subject follows
//! [OIDC Core §5.3.2]'s requirement and client-side substitution check.
//!
//! [OIDC Core §5.3.2]: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use genkan_core::clock::Clock;
use genkan_keys::Algorithm;
use genkan_keys::verify::verify_compact;
use genkan_store::{Directory, GrantStore};
use serde::{Deserialize, Serialize};

use super::AuthorizationServer;
use super::error::no_store;

/// The claims of an access token that matter here.
#[derive(Debug, Deserialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    exp: u64,
    client_id: String,
    #[serde(default)]
    scope: String,
}

#[derive(Debug, Serialize)]
struct UserInfo<'a> {
    sub: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<&'a [String]>,
}

/// RFC 6750 §3: a challenge, with an error code when a token was presented.
fn challenge(status: StatusCode, error: Option<&str>) -> Response {
    let value = error.map_or_else(
        || r#"Bearer realm="genkan""#.to_owned(),
        |error| format!(r#"Bearer realm="genkan", error="{error}""#),
    );
    let mut response = status.into_response();
    if let Ok(value) = HeaderValue::try_from(value) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    no_store(&mut response);
    response
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

/// `GET` and `POST /userinfo`.
pub async fn userinfo<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<std::sync::Arc<AuthorizationServer<D, G, C>>>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return challenge(StatusCode::UNAUTHORIZED, None);
    };
    let invalid = || challenge(StatusCode::UNAUTHORIZED, Some("invalid_token"));
    let Some(keys) = server.keys.borrow().clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok((header, payload)) =
        verify_compact(token, &keys.verification_keys(), &[Algorithm::Es256])
    else {
        return invalid();
    };
    let Ok(claims) = serde_json::from_slice::<AccessClaims>(&payload) else {
        return invalid();
    };
    // Only access tokens (RFC 9068 §2.1 `typ`), from this issuer, not expired.
    if header.typ.as_deref() != Some("at+jwt")
        || claims.iss != server.issuer.as_str()
        || claims.exp <= server.now().as_secs()
        || claims.client_id.is_empty()
    {
        return invalid();
    }
    let scopes: Vec<&str> = claims.scope.split(' ').collect();
    if !scopes.contains(&"openid") {
        return challenge(StatusCode::FORBIDDEN, Some("insufficient_scope"));
    }
    let user = match server.directory.user_by_subject(&claims.sub).await {
        Ok(Some(user)) if user.subject == claims.sub && !user.disabled => user,
        Ok(_) => return invalid(),
        Err(error) => {
            tracing::error!(%error, "user lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let profile = scopes.contains(&"profile");
    let body = UserInfo {
        sub: &user.subject,
        preferred_username: profile.then_some(user.username.as_str()),
        name: if profile {
            user.display_name.as_deref()
        } else {
            None
        },
        groups: scopes.contains(&"groups").then_some(user.groups.as_slice()),
    };
    let mut response = axum::Json(body).into_response();
    no_store(&mut response);
    response
}

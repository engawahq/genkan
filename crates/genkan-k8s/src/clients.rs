//! Client registration: the admin's side (`genkanctl client create`).
//!
//! A confidential client's secret is stored as an unsalted SHA-256 hash
//! ([`genkan_core::crypto::hash_secret`]), which anyone with `get` on `OAuthClient` objects, or
//! with the GitOps repository, can read. That is safe only for a high-entropy secret: a fast,
//! unsalted hash of a password falls to an offline dictionary attack, and the server cannot tell,
//! because it only ever sees the hash. So the secret is generated here, never chosen by a person:
//! 256 bits from the system CSPRNG, the same strength as every other secret Genkan hashes.
//!
//! The rules the `OAuthClient` schema enforces at admission are checked here too, so a mistake
//! fails before `kubectl apply`, with a message that names the bad value.

use genkan_core::crypto::{hash_secret, hex, random};
use genkan_keys::Algorithm;
use kube::api::ObjectMeta;
use thiserror::Error;

use crate::crd::client::{
    ClientType, MAX_AUDIENCE, MAX_AUDIENCES, MAX_DISPLAY_NAME, MAX_REDIRECT_URI, MAX_REDIRECT_URIS,
    OAuthClient, OAuthClientSpec,
};

/// Longest client ID. The client ID is the `OAuthClient` object name and also the
/// `genkan.engawahq.dev/client` label value on grants, which Kubernetes caps at 63 characters.
pub const MAX_CLIENT_ID: usize = 63;

/// Bytes of entropy in a generated client secret.
pub const SECRET_BYTES: usize = 32;

/// Why a client could not be registered.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientError {
    /// The client ID is not a lowercase DNS subdomain of at most 63 characters.
    #[error(
        "client ID {0:?} must be a lowercase DNS subdomain (a-z, 0-9, '-', '.') of at most {MAX_CLIENT_ID} characters"
    )]
    InvalidClientId(String),
    /// The display name is too long.
    #[error("display name must be at most {MAX_DISPLAY_NAME} characters")]
    DisplayNameTooLong,
    /// No redirect URI, or too many.
    #[error("give between 1 and {MAX_REDIRECT_URIS} redirect URIs")]
    RedirectUriCount,
    /// A redirect URI that RFC 9700 §2.1 or RFC 8252 §7.3 forbids.
    #[error(
        "redirect URI {0:?} must be https:// with a host, or http://127.0.0.1 or http://[::1] with a path; only ASCII URI characters, no fragment, at most {MAX_REDIRECT_URI} characters"
    )]
    InvalidRedirectUri(String),
    /// Too many audiences.
    #[error("give at most {MAX_AUDIENCES} audiences")]
    AudienceCount,
    /// An empty or overlong audience.
    #[error("audience {0:?} must be between 1 and {MAX_AUDIENCE} characters")]
    InvalidAudience(String),
    /// Randomness failed.
    #[error("generating the client secret failed")]
    Crypto,
}

/// The client to register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewClient {
    /// The client ID; also the object name.
    pub client_id: String,
    /// Whether the client can keep a secret.
    pub kind: ClientType,
    /// Name shown on the sign-in pages.
    pub display_name: Option<String>,
    /// Redirect URIs, compared by exact match (any port for loopback URIs).
    pub redirect_uris: Vec<String>,
    /// Audiences the client may request tokens for.
    pub audiences: Vec<String>,
    /// ID token signing algorithm, if not the default.
    pub id_token_signing_alg: Option<Algorithm>,
    /// Whether the client may request the `elevate` scope.
    pub allow_elevation: bool,
}

/// A registered client, ready for `kubectl apply`.
#[derive(Debug)]
pub struct Registration {
    /// The object; a confidential client's carries only the secret's hash.
    pub client: OAuthClient,
    /// A confidential client's secret: 64 lowercase hex digits. Shown once; it cannot be
    /// recovered from the object.
    pub secret: Option<String>,
}

/// Validates `new` and builds its `OAuthClient` in `namespace`, generating a secret for a
/// confidential client.
///
/// # Errors
///
/// Returns [`ClientError`] for a value the `OAuthClient` schema would reject, or when randomness
/// fails.
pub fn register(new: NewClient, namespace: &str) -> Result<Registration, ClientError> {
    validate(&new)?;
    let secret = match new.kind {
        ClientType::Public => None,
        ClientType::Confidential => Some(hex(
            &random::<SECRET_BYTES>().map_err(|_crypto| ClientError::Crypto)?
        )),
    };
    let client = OAuthClient {
        metadata: ObjectMeta {
            name: Some(new.client_id),
            namespace: Some(namespace.to_owned()),
            ..ObjectMeta::default()
        },
        spec: OAuthClientSpec {
            display_name: new.display_name,
            kind: new.kind,
            redirect_uris: new.redirect_uris,
            audiences: new.audiences,
            secret_hash: secret
                .as_deref()
                .map(|secret| hash_secret(secret.as_bytes())),
            id_token_signing_alg: new.id_token_signing_alg,
            allow_elevation: new.allow_elevation,
        },
    };
    Ok(Registration { client, secret })
}

fn validate(new: &NewClient) -> Result<(), ClientError> {
    if !is_client_id(&new.client_id) {
        return Err(ClientError::InvalidClientId(new.client_id.clone()));
    }
    if new
        .display_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > MAX_DISPLAY_NAME)
    {
        return Err(ClientError::DisplayNameTooLong);
    }
    if new.redirect_uris.is_empty() || new.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(ClientError::RedirectUriCount);
    }
    if let Some(uri) = new
        .redirect_uris
        .iter()
        .find(|uri| !redirect_uri_allowed(uri))
    {
        return Err(ClientError::InvalidRedirectUri(uri.clone()));
    }
    if new.audiences.len() > MAX_AUDIENCES {
        return Err(ClientError::AudienceCount);
    }
    if let Some(audience) = new
        .audiences
        .iter()
        .find(|audience| audience.is_empty() || audience.chars().count() > MAX_AUDIENCE)
    {
        return Err(ClientError::InvalidAudience(audience.clone()));
    }
    Ok(())
}

/// A lowercase RFC 1123 DNS subdomain of at most [`MAX_CLIENT_ID`] characters: dot-separated
/// labels of `a-z`, `0-9` and `-` that start and end with a letter or digit.
fn is_client_id(id: &str) -> bool {
    id.len() <= MAX_CLIENT_ID
        && id.split('.').all(|label| {
            let alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
            label.starts_with(alphanumeric)
                && label.ends_with(alphanumeric)
                && label.chars().all(|c| alphanumeric(c) || c == '-')
        })
}

/// Whether the `OAuthClient` schema accepts `uri` as a redirect URI.
///
/// The same rule as [`REDIRECT_URI_PATTERN`](crate::crd::client::REDIRECT_URI_PATTERN), without a
/// regex engine. Either `https://` with a non-empty authority (RFC 3986 §3.2: a host name or an
/// IPv6 literal, then an optional port), followed by nothing or by a path or query; or
/// `http://127.0.0.1` / `http://[::1]` with an optional port and a path (RFC 8252 §7.3). Only
/// RFC 3986 URI characters are allowed, so there is never a fragment (RFC 6749 §3.1.2),
/// whitespace or non-ASCII, and the URI always fits in the `Location` header of the redirect back
/// to the client.
#[must_use]
pub fn redirect_uri_allowed(uri: &str) -> bool {
    if uri.len() > MAX_REDIRECT_URI {
        return false;
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        let (authority, rest) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
        return https_authority_allowed(authority) && rest.chars().all(is_uri_char);
    }
    let Some(rest) = uri
        .strip_prefix("http://127.0.0.1")
        .or_else(|| uri.strip_prefix("http://[::1]"))
    else {
        return false;
    };
    let path = match rest.strip_prefix(':') {
        Some(port_and_path) => {
            let (port, path) =
                port_and_path.split_at(port_and_path.find('/').unwrap_or(port_and_path.len()));
            if !port_allowed(port) {
                return false;
            }
            path
        }
        None => rest,
    };
    path.starts_with('/') && path.chars().all(is_uri_char)
}

/// `host [":" port]`, where host is a non-empty DNS-style name or a bracketed IPv6 literal.
fn https_authority_allowed(authority: &str) -> bool {
    let (host_allowed, after_host) = if let Some(literal) = authority.strip_prefix('[') {
        let Some((address, after)) = literal.split_once(']') else {
            return false;
        };
        let ipv6 = |c: char| c.is_ascii_hexdigit() || c == ':' || c == '.';
        (!address.is_empty() && address.chars().all(ipv6), after)
    } else {
        let (host, after) = authority.split_at(authority.find(':').unwrap_or(authority.len()));
        (!host.is_empty() && host.chars().all(is_host_char), after)
    };
    host_allowed
        && (after_host.is_empty() || after_host.strip_prefix(':').is_some_and(port_allowed))
}

/// One to five digits.
fn port_allowed(port: &str) -> bool {
    (1..=5).contains(&port.len()) && port.chars().all(|c| c.is_ascii_digit())
}

/// The characters of a host name (letters, digits, `.`, `-`, `_`). RFC 3986 also allows
/// sub-delimiters and percent-encoding in a registered name, but no DNS name uses them and HTTP
/// libraries reject some of them.
fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._-".contains(c)
}

/// The characters of a path and query: RFC 3986 `pchar` (`unreserved`, `sub-delims`, `%`, `:`
/// and `@`), `/` and `?`. No `#`, so no fragment.
fn is_uri_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~!$&'()*+,;=%:@/?".contains(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_client(kind: ClientType) -> NewClient {
        NewClient {
            client_id: "dashboard".into(),
            kind,
            display_name: Some("Dashboard".into()),
            redirect_uris: vec!["https://dash.example.com/callback".into()],
            audiences: vec!["kubernetes".into()],
            id_token_signing_alg: None,
            allow_elevation: false,
        }
    }

    #[test]
    fn confidential_clients_get_a_fresh_random_secret_and_only_its_hash() {
        let first = register(new_client(ClientType::Confidential), "genkan-system").unwrap();
        let second = register(new_client(ClientType::Confidential), "genkan-system").unwrap();
        let secret = first.secret.unwrap();
        assert_eq!(secret.len(), SECRET_BYTES * 2);
        assert!(secret.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(Some(&secret), second.secret.as_ref());
        assert_eq!(
            first.client.spec.secret_hash,
            Some(hash_secret(secret.as_bytes()))
        );
        let json = serde_json::to_string(&first.client).unwrap();
        assert!(!json.contains(&secret));
    }

    #[test]
    fn emitted_objects_satisfy_the_schema_rules() {
        let confidential = register(new_client(ClientType::Confidential), "ns").unwrap();
        let value = serde_json::to_value(&confidential.client).unwrap();
        assert_eq!(value["apiVersion"], "genkan.engawahq.dev/v1alpha1");
        assert_eq!(value["kind"], "OAuthClient");
        assert_eq!(value["metadata"]["name"], "dashboard");
        assert_eq!(value["metadata"]["namespace"], "ns");
        assert_eq!(value["spec"]["type"], "Confidential");
        let hash = value["spec"]["secretHash"].as_str().unwrap();
        let digits = hash.strip_prefix("sha256:").unwrap();
        assert_eq!(digits.len(), 64);
        assert!(
            digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );

        let public = register(new_client(ClientType::Public), "ns").unwrap();
        assert!(public.secret.is_none());
        let value = serde_json::to_value(&public.client).unwrap();
        assert_eq!(value["spec"]["type"], "Public");
        assert!(value["spec"].get("secretHash").is_none());
    }

    #[test]
    fn redirect_uris_follow_the_schema_pattern() {
        for allowed in [
            "https://dash.example.com/callback",
            "https://dash.example.com",
            "https://dash.example.com:8443/cb?x=1",
            "https://dash.example.com?x=1",
            "https://[2001:db8::1]:8443/cb",
            "https://xn--bcher-kva.example/cb",
            "http://127.0.0.1/",
            "http://127.0.0.1:8000/",
            "http://[::1]:12345/cb",
            "http://[::1]/",
        ] {
            assert!(redirect_uri_allowed(allowed), "{allowed}");
        }
        for forbidden in [
            "http://example.com/",
            "http://localhost:8000/",
            "https://dash.example.com/cb#fragment",
            "https://dash.example.com/c b",
            "https://",
            "javascript:alert(1)",
            "http://127.0.0.1",
            "http://127.0.0.1:8000",
            "http://127.0.0.1:/",
            "http://127.0.0.1:123456/",
            "http://127.0.0.1.example.com/",
            "http://[::1]x/",
            "HTTPS://dash.example.com/",
            "https:///callback",
            "https://?x=1",
            "https://:443/",
            "https://dash.example.com:/",
            "https://dash.example.com:443:1/",
            "https://user@dash.example.com/",
            "https://[]/",
            "https://[2001:db8::1/",
            "https://bücher.example/",
            "https://dash.example.com/bücher",
            "https://dash.example.com/<script>",
            "http://127.0.0.1:8000?x=1",
        ] {
            assert!(!redirect_uri_allowed(forbidden), "{forbidden}");
        }
        assert!(!redirect_uri_allowed(&format!(
            "https://e.com/{}",
            "a".repeat(MAX_REDIRECT_URI)
        )));
    }

    proptest::proptest! {
        /// Whatever passes is usable as the redirect: a valid `Location` header value, and an
        /// absolute URI with a scheme and a non-empty host.
        #[test]
        fn allowed_redirect_uris_are_absolute_and_fit_a_location_header(
            uri in "(https://|http://127\\.0\\.0\\.1|http://\\[::1\\])[ -~\\u{80}-\\u{ff}]{0,24}"
        ) {
            if redirect_uri_allowed(&uri) {
                proptest::prop_assert!(axum::http::HeaderValue::try_from(uri.as_str()).is_ok());
                let parsed: axum::http::Uri = uri.parse().unwrap();
                proptest::prop_assert!(parsed.scheme().is_some());
                proptest::prop_assert!(parsed.host().is_some_and(|host| !host.is_empty()));
            }
        }
    }

    #[test]
    fn invalid_registrations_are_rejected_with_the_offending_value() {
        let with = |change: fn(&mut NewClient)| {
            let mut new = new_client(ClientType::Public);
            change(&mut new);
            register(new, "ns").unwrap_err()
        };
        assert_eq!(
            with(|new| new.redirect_uris = vec!["http://example.com/".into()]),
            ClientError::InvalidRedirectUri("http://example.com/".into())
        );
        assert_eq!(
            with(|new| new.redirect_uris = vec![]),
            ClientError::RedirectUriCount
        );
        assert_eq!(
            with(|new| new.redirect_uris = vec!["https://e.com/".into(); MAX_REDIRECT_URIS + 1]),
            ClientError::RedirectUriCount
        );
        assert_eq!(
            with(|new| new.audiences = vec![String::new()]),
            ClientError::InvalidAudience(String::new())
        );
        assert_eq!(
            with(|new| new.audiences = vec!["k".into(); MAX_AUDIENCES + 1]),
            ClientError::AudienceCount
        );
        assert_eq!(
            with(|new| new.display_name = Some("x".repeat(MAX_DISPLAY_NAME + 1))),
            ClientError::DisplayNameTooLong
        );
        for id in [
            "",
            "Dashboard",
            "-dash",
            "dash-",
            "dash..board",
            "dash_board",
        ] {
            let mut new = new_client(ClientType::Public);
            new.client_id = id.into();
            assert_eq!(
                register(new, "ns").unwrap_err(),
                ClientError::InvalidClientId(id.into())
            );
        }
        let mut new = new_client(ClientType::Public);
        new.client_id = "a".repeat(MAX_CLIENT_ID + 1);
        assert!(register(new, "ns").is_err());
    }
}

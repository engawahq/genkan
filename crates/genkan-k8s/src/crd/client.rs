//! `OAuthClient`: a registered relying party.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

pub use genkan_store::ClientType;
use kube::{CustomResource, KubeSchema};
use serde::{Deserialize, Serialize};

/// Longest display name.
pub const MAX_DISPLAY_NAME: usize = 128;
/// Most redirect URIs per client.
pub const MAX_REDIRECT_URIS: usize = 16;
/// Longest redirect URI.
pub const MAX_REDIRECT_URI: usize = 2048;
/// Most audiences per client.
pub const MAX_AUDIENCES: usize = 16;
/// Longest audience.
pub const MAX_AUDIENCE: usize = 256;
/// The admission rule for redirect URIs (RFC 9700 §2.1, RFC 8252 §7.3).
///
/// Each is a URL by Kubernetes' CEL `isURL()` (Go's `net/url`), and either `https` with a host or
/// loopback `http` (`127.0.0.1` or `[::1]`) with a path. Printable ASCII only, so the redirect's
/// `Location` header can carry it; no fragment (RFC 6749 §3.1.2) and no user information. This is
/// the floor that keeps a GitOps mistake from reaching the server, not a full URL grammar: Go
/// accepts some hosts and ports that browsers reject. [`crate::clients::redirect_uri_allowed`]
/// adds a browser's (WHATWG) parse on top, for tools that check before `kubectl apply`.
pub const REDIRECT_URI_RULE: &str = concat!(
    "self.all(u, u.matches('^[!-~]+$') && !u.contains('#') && isURL(u)",
    " && !u.matches('^[^/]*//[^/?]*@')",
    " && (url(u).getScheme() == 'https' ? url(u).getHostname() != ''",
    " : url(u).getScheme() == 'http' && url(u).getHostname() in ['127.0.0.1', '::1']",
    " && url(u).getEscapedPath() != ''))",
);
/// The stored secret: [`genkan_core::crypto::hash_secret`]'s output.
pub const SECRET_HASH_PATTERN: &str = r"^sha256:[0-9a-f]{64}$";

/// A registered OAuth 2.0 / OpenID Connect client. The object name is the `client_id`.
///
/// Admission rules reject redirect URIs that RFC 9700 §2.1 and OAuth 2.1 forbid, so a
/// mistake in a GitOps repository fails at `kubectl apply`, not at login.
#[derive(CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[kube(
    group = "genkan.engawahq.dev",
    version = "v1alpha1",
    kind = "OAuthClient",
    namespaced,
    shortname = "gkclient",
    category = "genkan",
    printcolumn(name = "Type", type_ = "string", json_path = ".spec.type"),
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    doc = "An OAuth 2.0 / OpenID Connect client registered with Genkan."
)]
#[x_kube(
    validation = Rule::new("(self.type == 'Confidential') == has(self.secretHash)")
        .message("secretHash is required for confidential clients and forbidden for public clients")
)]
#[serde(rename_all = "camelCase")]
pub struct OAuthClientSpec {
    /// Name shown on the consent and login pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = MAX_DISPLAY_NAME))]
    pub display_name: Option<String>,

    /// Public clients (kubectl, native apps) cannot keep a secret; confidential clients can.
    #[serde(rename = "type")]
    pub kind: ClientType,

    /// Redirect URIs, compared by exact string match. Each is `https://` with a host, or
    /// `http://127.0.0.1` / `http://[::1]` with a path for native apps (RFC 8252 §7.3); ASCII URI
    /// characters only, no fragment.
    #[schemars(
        length(min = 1, max = MAX_REDIRECT_URIS),
        inner(length(max = MAX_REDIRECT_URI))
    )]
    #[x_kube(validation = Rule::new(REDIRECT_URI_RULE).message(
        "each redirect URI must be https:// with a host, or http://127.0.0.1 or http://[::1] with a path; printable ASCII, no fragment or user information"
    ))]
    pub redirect_uris: Vec<String>,

    /// Audiences this client may request tokens for (RFC 8707 resource indicators), for example
    /// the `audiences` entry of the cluster's AuthenticationConfiguration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = MAX_AUDIENCES), inner(length(min = 1, max = MAX_AUDIENCE)))]
    pub audiences: Vec<String>,

    /// SHA-256 of the client secret, as `sha256:<64 hex digits>`. The secret itself is never
    /// stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = SECRET_HASH_PATTERN))]
    pub secret_hash: Option<String>,

    /// Algorithm for ID tokens: `ES256` (default) or `RS256` for clients that need it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_signing_alg: Option<genkan_keys::Algorithm>,

    /// Whether this client may request the `elevate` scope, which yields a short token carrying
    /// the user's `elevated:<group>` groups after a passkey sign-in. Off by default: turn it on
    /// only for clients meant for administration, such as an admin `kubectl` context.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_elevation: bool,
}

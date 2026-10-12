//! Validated configuration of `genkan`.

use std::net::SocketAddr;
use std::time::Duration;

use genkan_core::config::{BaseUrl, ConfigError};
use genkan_keys::rotation::RotationPolicy;

/// Where long-term state is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Store {
    /// Kubernetes objects: custom resources and Secrets in one namespace (`genkan_k8s`).
    Kubernetes {
        /// Namespace; defaults to the client's (in-cluster: the pod's).
        namespace: Option<String>,
        /// Name of the signing-key Secret.
        key_secret: String,
    },
    /// Process memory. Nothing survives a restart; for development only.
    Memory,
}

/// An upstream identity provider's client registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamConfig {
    /// Which provider.
    pub kind: genkan_signin::upstream::provider::Kind,
    /// OAuth client ID.
    pub client_id: String,
    /// File holding the client secret (a mounted Secret).
    pub client_secret_file: std::path::PathBuf,
}

/// How invitation mail is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailConfig {
    /// `smtps://` or `smtp://` URL of the submission server.
    pub url: String,
    /// File holding the password.
    pub password_file: Option<std::path::PathBuf>,
    /// Extra CA for the server.
    pub ca_file: Option<std::path::PathBuf>,
    /// Sender address.
    pub from: String,
}

/// Configuration for `genkan`.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// The issuer identifier, also the public base URL.
    pub issuer: BaseUrl,
    /// Where the public HTTP listener binds. TLS is terminated in front of it.
    pub listen: SocketAddr,
    /// Signing-key rotation timings.
    pub rotation: RotationPolicy,
    /// `Cache-Control: max-age` for the discovery documents and the JWK set.
    pub metadata_max_age: Duration,
    /// Whether invitations are accepted.
    pub invitations: bool,
    /// How invitation links are mailed, if they are.
    pub mail: Option<MailConfig>,
    /// Enabled upstream identity providers.
    pub upstream: Vec<UpstreamConfig>,
    /// Extra CA trusted for the providers (tests and private mirrors).
    pub upstream_ca_file: Option<std::path::PathBuf>,
    /// Where the internal TLS listener binds (Kubernetes store only).
    pub internal_listen: SocketAddr,
    /// Overrides the internal base URL recorded in the certificate Secret.
    pub internal_url: Option<BaseUrl>,
    /// Where state is kept.
    pub store: Store,
    /// Token and grant lifetimes.
    pub lifetimes: genkan_oauth::Lifetimes,
}

impl ServeConfig {
    /// Checks relations between fields.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BadRotationPolicy`] if verifiers could see a signing key later
    /// than it is used, or stop seeing it before its tokens expire.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.rotation.validate()?;
        if self.rotation.retain_after < self.lifetimes.longest_signed_token() {
            return Err(ConfigError::BadRotationPolicy(
                "keys must stay published at least as long as the longest token lifetime",
            ));
        }
        if self.lifetimes.access_token > Duration::from_hours(1)
            || self.lifetimes.access_token < Duration::from_mins(1)
        {
            // RFC 6750 §5.3: short-lived bearer tokens, one hour or less.
            return Err(ConfigError::BadRotationPolicy(
                "access token lifetime must be between 1m and 1h",
            ));
        }
        if self
            .lifetimes
            .elevated_token
            .is_some_and(|t| t > Duration::from_mins(15) || t < Duration::from_mins(1))
        {
            return Err(ConfigError::BadRotationPolicy(
                "elevated token lifetime must be between 1m and 15m",
            ));
        }
        if self.mail.is_some() && !self.invitations {
            return Err(ConfigError::Incomplete("--smtp-url needs --invitations"));
        }
        if self.lifetimes.refresh_idle > self.lifetimes.refresh_absolute {
            return Err(ConfigError::BadRotationPolicy(
                "refresh idle lifetime cannot exceed the absolute lifetime",
            ));
        }
        if self.metadata_max_age >= self.rotation.publish_ahead {
            return Err(ConfigError::BadRotationPolicy(
                "metadata max-age must be shorter than the publish-ahead time, or verifiers \
                 that cache the JWK set may not see a new key before it signs",
            ));
        }
        Ok(())
    }
}

//! Command-line flags of the `genkan` server.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use genkan_core::config::{BaseUrl, ConfigError, parse_duration};
use genkan_keys::rotation::RotationPolicy;
use genkan_signin::upstream::provider::Kind;

use crate::config::{MailConfig, ServeConfig, Store, UpstreamConfig};

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// One JSON object per line.
    Json,
    /// Human-readable text.
    Text,
}

/// Passkey-first OpenID Connect issuer for Kubernetes. Every flag can also be set through its
/// environment variable.
#[derive(Debug, Parser)]
#[command(name = "genkan", version, about)]
pub struct ServeArgs {
    /// Issuer identifier: an https URL with no path and no trailing slash. It must match
    /// kube-apiserver's `issuer.url` byte for byte.
    #[arg(long, env = "GENKAN_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,

    /// Address of the public HTTP listener. TLS is terminated in front of it.
    #[arg(long, env = "GENKAN_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// How long each signing key signs before its successor takes over.
    #[arg(long, env = "GENKAN_KEY_ROTATION_PERIOD", default_value = "7d", value_parser = parse_duration)]
    pub key_rotation_period: Duration,

    /// How long a new key is published before it signs. Must exceed every verifier's JWK set
    /// cache lifetime.
    #[arg(long, env = "GENKAN_KEY_PUBLISH_AHEAD", default_value = "24h", value_parser = parse_duration)]
    pub key_publish_ahead: Duration,

    /// How long a key stays published after it stops signing. Must exceed the longest token
    /// lifetime.
    #[arg(long, env = "GENKAN_KEY_RETAIN_AFTER", default_value = "24h", value_parser = parse_duration)]
    pub key_retain_after: Duration,

    /// `Cache-Control: max-age` for discovery documents and the JWK set.
    #[arg(long, env = "GENKAN_METADATA_MAX_AGE", default_value = "5m", value_parser = parse_duration)]
    pub metadata_max_age: Duration,

    /// Tokio worker threads. Two keep idle memory low.
    #[arg(long, env = "GENKAN_WORKER_THREADS", default_value_t = 2)]
    pub worker_threads: usize,

    /// Log format.
    #[arg(long, env = "GENKAN_LOG_FORMAT", value_enum, default_value_t = LogFormat::Json)]
    pub log_format: LogFormat,

    /// Where state is kept.
    #[arg(long, env = "GENKAN_STORE", value_enum, default_value_t = StoreKind::Kubernetes)]
    pub store: StoreKind,

    /// Kubernetes namespace for state; defaults to the pod's namespace (or the kubeconfig
    /// context's).
    #[arg(long, env = "GENKAN_NAMESPACE")]
    pub namespace: Option<String>,

    /// Lifetime of access and ID tokens. kube-apiserver cannot revoke them, so this is also how
    /// long a revoked session can still call the cluster.
    #[arg(long, env = "GENKAN_TOKEN_LIFETIME", default_value = "10m", value_parser = parse_duration)]
    pub token_lifetime: Duration,

    /// A refresh-token family ends if unused this long.
    #[arg(long, env = "GENKAN_REFRESH_IDLE", default_value = "4h", value_parser = parse_duration)]
    pub refresh_idle: Duration,

    /// A refresh-token family ends this long after sign-in.
    #[arg(long, env = "GENKAN_REFRESH_ABSOLUTE", default_value = "12h", value_parser = parse_duration)]
    pub refresh_absolute: Duration,

    /// Name of the Secret holding signing keys.
    #[arg(long, env = "GENKAN_KEY_SECRET", default_value = genkan_k8s::KEY_SECRET)]
    pub key_secret: String,

    /// Accept invitations (`genkanctl invite`) as enrolment links.
    #[arg(long, env = "GENKAN_INVITATIONS")]
    pub invitations: bool,

    /// Mail invitation links through this submission server: `smtps://[user@]host[:465]` (TLS)
    /// or `smtp://[user@]host[:587]` (STARTTLS, required). Needs --invitations.
    #[arg(long, env = "GENKAN_SMTP_URL")]
    pub smtp_url: Option<String>,

    /// File holding the SMTP password (a mounted Secret).
    #[arg(long, env = "GENKAN_SMTP_PASSWORD_FILE")]
    pub smtp_password_file: Option<PathBuf>,

    /// Enable "Continue with GitHub": the OAuth app's client ID. Register
    /// `<issuer>/upstream/github/callback` as its callback URL.
    #[arg(
        long,
        env = "GENKAN_GITHUB_CLIENT_ID",
        requires = "github_client_secret_file"
    )]
    pub github_client_id: Option<String>,

    /// File holding the GitHub OAuth app's client secret.
    #[arg(
        long,
        env = "GENKAN_GITHUB_CLIENT_SECRET_FILE",
        requires = "github_client_id"
    )]
    pub github_client_secret_file: Option<PathBuf>,

    /// Enable "Continue with Google": the OAuth client ID. Register
    /// `<issuer>/upstream/google/callback` as an authorized redirect URI.
    #[arg(
        long,
        env = "GENKAN_GOOGLE_CLIENT_ID",
        requires = "google_client_secret_file"
    )]
    pub google_client_id: Option<String>,

    /// File holding the Google OAuth client secret.
    #[arg(
        long,
        env = "GENKAN_GOOGLE_CLIENT_SECRET_FILE",
        requires = "google_client_id"
    )]
    pub google_client_secret_file: Option<PathBuf>,

    /// Extra CA (PEM) trusted for upstream providers.
    #[arg(long, env = "GENKAN_UPSTREAM_CA_FILE")]
    pub upstream_ca_file: Option<PathBuf>,

    /// Extra CA (PEM) trusted for the SMTP server, for a private relay.
    #[arg(long, env = "GENKAN_SMTP_CA_FILE")]
    pub smtp_ca_file: Option<PathBuf>,

    /// Sender address of invitation mail.
    #[arg(long, env = "GENKAN_MAIL_FROM")]
    pub mail_from: Option<String>,

    /// Lifetime of elevated tokens (1m to 15m). The `elevate` scope yields such a token, without
    /// refresh, adding `elevated:<group>` for each of the user's elevated groups, after a passkey
    /// sign-in only. kube-apiserver cannot revoke it.
    #[arg(long, env = "GENKAN_ELEVATED_TOKEN_LIFETIME", default_value = "5m", value_parser = parse_duration)]
    pub elevated_token_lifetime: Duration,

    /// Address of the internal TLS listener kube-apiserver fetches discovery and keys from.
    /// Binds at startup; TLS handshakes fail until `genkanctl kube-config` issues its certificate
    /// (Kubernetes store only).
    #[arg(long, env = "GENKAN_INTERNAL_LISTEN", default_value = "0.0.0.0:8443")]
    pub internal_listen: SocketAddr,

    /// Base URL kube-apiserver uses for the internal listener; by default the one recorded in
    /// the certificate Secret.
    #[arg(long, env = "GENKAN_INTERNAL_URL", value_parser = parse_internal_url)]
    pub internal_url: Option<BaseUrl>,
}

/// Storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StoreKind {
    /// Kubernetes objects.
    Kubernetes,
    /// Process memory (development only).
    Memory,
}

fn parse_issuer(input: &str) -> Result<BaseUrl, ConfigError> {
    BaseUrl::parse("issuer", input)
}

fn parse_internal_url(input: &str) -> Result<BaseUrl, ConfigError> {
    BaseUrl::parse("internal URL", input)
}

impl ServeArgs {
    /// Builds and validates the server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the values are inconsistent.
    pub fn config(&self) -> Result<ServeConfig, ConfigError> {
        let config = ServeConfig {
            issuer: self.issuer.clone(),
            listen: self.listen,
            rotation: RotationPolicy {
                rotation_period: self.key_rotation_period,
                publish_ahead: self.key_publish_ahead,
                retain_after: self.key_retain_after,
            },
            metadata_max_age: self.metadata_max_age,
            invitations: self.invitations,
            upstream: [
                (
                    Kind::GitHub,
                    &self.github_client_id,
                    &self.github_client_secret_file,
                ),
                (
                    Kind::Google,
                    &self.google_client_id,
                    &self.google_client_secret_file,
                ),
            ]
            .into_iter()
            .filter_map(|(kind, id, secret)| {
                Some(UpstreamConfig {
                    kind,
                    client_id: id.clone()?,
                    client_secret_file: secret.clone()?,
                })
            })
            .collect(),
            upstream_ca_file: self.upstream_ca_file.clone(),
            mail: match (&self.smtp_url, &self.mail_from) {
                (Some(url), Some(from)) => Some(MailConfig {
                    url: url.clone(),
                    password_file: self.smtp_password_file.clone(),
                    ca_file: self.smtp_ca_file.clone(),
                    from: from.clone(),
                }),
                (None, None) => None,
                _ => {
                    return Err(ConfigError::Incomplete(
                        "--smtp-url and --mail-from go together",
                    ));
                }
            },
            internal_listen: self.internal_listen,
            internal_url: self.internal_url.clone(),
            store: match self.store {
                StoreKind::Kubernetes => Store::Kubernetes {
                    namespace: self.namespace.clone(),
                    key_secret: self.key_secret.clone(),
                },
                StoreKind::Memory => Store::Memory,
            },
            lifetimes: genkan_oauth::Lifetimes {
                access_token: self.token_lifetime,
                id_token: self.token_lifetime,
                refresh_idle: self.refresh_idle,
                refresh_absolute: self.refresh_absolute,
                elevated_token: Some(self.elevated_token_lifetime),
                ..genkan_oauth::Lifetimes::DEFAULT
            },
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    fn parse(args: &[&str]) -> Result<ServeArgs, clap::Error> {
        ServeArgs::try_parse_from(std::iter::once("genkan").chain(args.iter().copied()))
    }

    #[test]
    fn cli_definition_is_valid() {
        ServeArgs::command().debug_assert();
    }

    #[test]
    fn defaults() {
        let args = parse(&["--issuer", "https://login.example.com"]).unwrap();
        let config = args.config().unwrap();
        assert_eq!(config.rotation, RotationPolicy::DEFAULT);
        assert_eq!(config.metadata_max_age, Duration::from_secs(300));
    }

    #[test]
    fn rejects_bad_issuers_and_inconsistent_timings() {
        assert!(parse(&["--issuer", "http://login.example.com"]).is_err());
        let args = parse(&[
            "--issuer",
            "https://login.example.com",
            "--metadata-max-age",
            "2d",
        ])
        .unwrap();
        assert!(args.config().is_err());
    }
}

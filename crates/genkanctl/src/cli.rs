//! Command-line interface of `genkanctl`.

use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use genkan_core::config::{BaseUrl, ConfigError, parse_duration};
use genkan_k8s::kube_config::{DiscoveryMode, Distro};

/// Administer Genkan with your own kubeconfig: install manifests, configure kube-apiserver,
/// issue setup links and invitations, register clients.
#[derive(Debug, Parser)]
#[command(name = "genkanctl", version, about)]
pub(crate) struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Print the custom resource definitions as a Kubernetes `List` (JSON), for
    /// `genkanctl crds | kubectl apply -f -`.
    Crds,
    /// Create a one-time setup link for a user, using your own kubeconfig (cluster admin). Prints
    /// the link; it works once and expires.
    SetupLink(SetupLinkArgs),
    /// Print the namespace, service account, `Role`, `RoleBinding` and empty key Secret as a
    /// Kubernetes `List` (JSON), for `genkanctl rbac | kubectl apply -f -`.
    Rbac {
        /// Namespace to install into.
        #[arg(long, default_value = genkan_k8s::rbac::DEFAULT_NAMESPACE)]
        namespace: String,
    },
    /// Print everything to install (the `rbac` objects, the Service and the Deployment) as a
    /// Kubernetes `List` (JSON), for `genkanctl manifests … | kubectl apply -f -`.
    Manifests(ManifestsArgs),
    /// Prepare kube-apiserver to accept Genkan's tokens, using your own kubeconfig (cluster
    /// admin): issues the internal listener's certificate if needed, prints the
    /// `AuthenticationConfiguration` (stdout) and how to install it (stderr).
    KubeConfig(KubeConfigArgs),
    /// Invite a user, using your own kubeconfig (admin): creates the `User` if needed and a
    /// one-time enrolment link, printed for you to send.
    Invite(InviteArgs),
    /// Register OAuth clients.
    Client {
        /// The client command to run.
        #[command(subcommand)]
        command: ClientCommand,
    },
}

/// `genkanctl client` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum ClientCommand {
    /// Print an `OAuthClient` (JSON), for `genkanctl client create … | kubectl apply -f -`. A
    /// confidential client gets a generated secret, printed once on stderr; only its hash goes
    /// into the object.
    Create(ClientCreateArgs),
}

/// Arguments of `genkanctl client create`.
#[derive(Debug, Args)]
pub(crate) struct ClientCreateArgs {
    /// The client ID, also the object name: a lowercase DNS subdomain of at most 63 characters.
    pub client_id: String,
    /// `public` for clients that cannot keep a secret (kubectl, native and browser apps),
    /// `confidential` for servers.
    #[arg(long = "type", value_enum)]
    pub kind: ClientKind,
    /// Redirect URI (repeatable): `https://` with a host, or `http://127.0.0.1` / `http://[::1]`
    /// with a path for native apps; any port matches for those.
    #[arg(long = "redirect-uri", required = true)]
    pub redirect_uris: Vec<String>,
    /// Audience the client may request tokens for (repeatable), for example `kubernetes`.
    #[arg(long = "audience")]
    pub audiences: Vec<String>,
    /// Name shown on the sign-in pages.
    #[arg(long)]
    pub display_name: Option<String>,
    /// Let the client request the `elevate` scope (short tokens with the user's `elevated:`
    /// groups). Only for clients meant for administration, such as an admin `kubectl` context.
    #[arg(long)]
    pub allow_elevation: bool,
    /// ID token signing algorithm, for a client that cannot verify `ES256`.
    #[arg(long, value_enum)]
    pub id_token_signing_alg: Option<SigningAlg>,
    /// Namespace Genkan runs in.
    #[arg(long, env = "GENKAN_NAMESPACE", default_value = genkan_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
}

/// Client type.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ClientKind {
    /// Identifies itself with its client ID only.
    Public,
    /// Authenticates at the token endpoint with a generated secret.
    Confidential,
}

/// ID token signing algorithm.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum SigningAlg {
    /// ECDSA P-256 (the default).
    #[value(name = "ES256")]
    Es256,
    /// RSA PKCS #1 v1.5.
    #[value(name = "RS256")]
    Rs256,
}

/// Arguments of `genkanctl invite`.
#[derive(Debug, Args)]
pub(crate) struct InviteArgs {
    /// The issuer identifier (the same as `genkan --issuer`).
    #[arg(long, env = "GENKAN_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,
    /// Login name: a lowercase DNS subdomain, at most 63 characters; Kubernetes sees
    /// `genkan:<username>`.
    #[arg(long)]
    pub username: String,
    /// Display name, for a new user.
    #[arg(long)]
    pub display_name: Option<String>,
    /// Group of a new user (repeatable).
    #[arg(long = "group")]
    pub groups: Vec<String>,
    /// Elevated group of a new user (repeatable): `genkan:elevated:<group>` after a passkey
    /// sign-in with the `elevate` scope.
    #[arg(long = "elevated-group")]
    pub elevated_groups: Vec<String>,
    /// How long the link works.
    #[arg(long, default_value = "7d", value_parser = parse_duration)]
    pub valid_for: Duration,
    /// Namespace Genkan runs in.
    #[arg(long, env = "GENKAN_NAMESPACE", default_value = genkan_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
}

/// Arguments of `genkanctl manifests`.
#[derive(Debug, Args)]
pub(crate) struct ManifestsArgs {
    /// The issuer identifier.
    #[arg(long, env = "GENKAN_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,
    /// The container image, preferably by digest.
    #[arg(long)]
    pub image: String,
    /// Namespace to install into.
    #[arg(long, default_value = genkan_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
    /// An argument for `genkan` (repeatable), for example `--serve-arg=--invitations`.
    #[arg(long = "serve-arg", allow_hyphen_values = true)]
    pub serve_args: Vec<String>,
    /// A Secret mounted read-only at /etc/genkan, for files such as client secrets.
    #[arg(long)]
    pub config_secret: Option<String>,
}

/// Arguments of `genkanctl kube-config`.
#[derive(Debug, Args)]
pub(crate) struct KubeConfigArgs {
    /// The issuer identifier (the same as `genkan --issuer`).
    #[arg(long, env = "GENKAN_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,
    /// The Kubernetes distribution kube-apiserver belongs to.
    #[arg(long, value_enum)]
    pub distro: Distro,
    /// Namespace Genkan runs in.
    #[arg(long, env = "GENKAN_NAMESPACE", default_value = genkan_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
    /// How kube-apiserver fetches discovery and keys.
    #[arg(long, value_enum, default_value_t = DiscoveryMode::Internal)]
    pub discovery: DiscoveryMode,
    /// Token audience kube-apiserver accepts (repeatable).
    #[arg(long = "audience", default_value = "kubernetes")]
    pub audiences: Vec<String>,
    /// Longest token lifetime kube-apiserver accepts.
    #[arg(long, default_value = "1h", value_parser = parse_duration)]
    pub max_token_lifetime: Duration,
    /// Longest lifetime kube-apiserver accepts for a token carrying `elevated:` groups.
    #[arg(long, default_value = "5m", value_parser = parse_duration)]
    pub max_elevated_token_lifetime: Duration,
    /// Issue a new internal certificate even if the current one is still good.
    #[arg(long)]
    pub renew_certificate: bool,
    /// Lifetime of a newly issued internal certificate.
    #[arg(long, default_value = "365d", value_parser = parse_duration)]
    pub certificate_validity: Duration,
}

/// Arguments of `genkanctl setup-link`.
#[derive(Debug, Args)]
pub(crate) struct SetupLinkArgs {
    /// The issuer identifier (the same as `genkan --issuer`).
    #[arg(long, env = "GENKAN_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,
    /// The `User` to enrol a passkey for; created in group `admins` if it does not exist.
    /// The username must be a lowercase DNS subdomain of at most 63 characters.
    #[arg(long, default_value = "admin")]
    pub username: String,
    /// Namespace Genkan runs in.
    #[arg(long, env = "GENKAN_NAMESPACE", default_value = genkan_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
    /// How long the link works.
    #[arg(long, default_value = "60m", value_parser = parse_duration)]
    pub valid_for: Duration,
    /// Remove the user's pending invitations, passkeys and sessions first (account recovery).
    #[arg(long)]
    pub reset: bool,
}

fn parse_issuer(input: &str) -> Result<BaseUrl, ConfigError> {
    BaseUrl::parse("issuer", input)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}

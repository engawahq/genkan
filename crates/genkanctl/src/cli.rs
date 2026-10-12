//! Command-line interface of `genkanctl`.

use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use genkan_core::config::{BaseUrl, ConfigError, parse_duration};
use genkan_k8s::kube_config::{DiscoveryMode, Distro};

/// Administer Genkan with your own kubeconfig: install manifests, configure kube-apiserver,
/// issue setup links and invitations.
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
    /// one-time enrolment link, printed, or mailed by Genkan with --email.
    Invite(InviteArgs),
}

/// Arguments of `genkanctl invite`.
#[derive(Debug, Args)]
pub(crate) struct InviteArgs {
    /// The issuer identifier (the same as `genkan --issuer`).
    #[arg(long, env = "GENKAN_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,
    /// Login name of the user; Kubernetes sees `genkan:<username>`.
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
    /// Have Genkan mail the link to this address (needs `genkan --smtp-url`).
    #[arg(long)]
    pub email: Option<String>,
    /// Language of the mail.
    #[arg(long, value_parser = ["en", "zh-TW", "zh-CN"])]
    pub language: Option<String>,
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
    /// A Secret mounted read-only at /etc/genkan, for files such as client secrets and the
    /// SMTP password.
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
    #[arg(long, default_value = "admin")]
    pub username: String,
    /// Namespace Genkan runs in.
    #[arg(long, env = "GENKAN_NAMESPACE", default_value = genkan_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
    /// How long the link works.
    #[arg(long, default_value = "60m", value_parser = parse_duration)]
    pub valid_for: Duration,
    /// Remove the user's existing passkeys and sessions first (account recovery).
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

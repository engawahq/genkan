//! `genkanctl kube-config`: the kube-apiserver side of the integration.
//!
//! Run by the cluster admin with their own kubeconfig. It finds Genkan's Service, makes sure the
//! internal listener has a certificate for the Service's ClusterIP (issuing one if needed,
//! [`crate::internal_tls`]), and prints the `AuthenticationConfiguration` for the chosen
//! distribution together with how to install it there.
//!
//! # Trust-preserving renewal
//!
//! Built-in CA keys are discarded, so renewal changes the trust anchor. `prepare` persists a
//! candidate and prints old+new CA trust without replacing the live leaf. Only explicit
//! `activate`, naming the persisted rotation id, changes the serving pair. Distribute the exact
//! overlap configuration and observe a successful reload on **every** control plane first;
//! the CLI cannot inspect external host files. Keep overlap until every serving leaf matches
//! the candidate's SHA-256 DER fingerprint, then `finish` removes rollback material and prints
//! new-only trust. `rollback` restores the previous unexpired pair with overlap retained;
//! `cancel` discards a prepared or rolled-back candidate. Each write preserves the Secret's
//! `resourceVersion` ([API updates]); conflicts fail closed and retries read persisted state.
//! Terminal id/phase markers make retries after lost responses idempotent, including across
//! CLI restarts. Rotation ids are opaque random identifiers, not certificate fingerprints.
//!
//! There is no automatic CA replacement on expiry or parse failure, nor a timed trust cutover.
//! Ordinary invocation creates initial material only when absent and never overwrites an
//! externally managed Secret. Activate/finish/cancel are operator acknowledgements of the
//! documented rollout prerequisites, not proofs that host configuration was distributed.
//!
//! [API updates]: https://kubernetes.io/docs/reference/using-api/api-concepts/#updates-to-existing-resources
//! Successful reload evidence is the per-apiserver success metric and the hash of the exact
//! applied configuration ([reload metrics], [reload success path]), not elapsed time.
//!
//! [reload metrics]: https://github.com/kubernetes/kubernetes/blob/v1.37.1/staging/src/k8s.io/apiserver/pkg/server/options/authenticationconfig/metrics/metrics.go
//! [reload success path]: https://github.com/kubernetes/kubernetes/blob/v1.37.1/pkg/kubeapiserver/options/authentication.go
//!
//! The file is a structured `AuthenticationConfiguration` (`apiserver.config.k8s.io/v1`, GA in
//! Kubernetes 1.34, [KEP-3331]). kube-apiserver re-reads it about once a minute, so only the
//! flag that names it needs a restart. It cannot be combined with `--oidc-*` flags.
//!
//! # Discovery from inside the cluster
//!
//! With [`DiscoveryMode::Internal`] (the default), the control plane does not depend on public
//! DNS, the ingress or a publicly trusted certificate. kube-apiserver redirects only the
//! discovery request to `discoveryURL`; the document it gets there must still name the public
//! issuer, and the JWK set is fetched from the document's `jwks_uri` ([oidc.go]). Genkan's
//! internal listener therefore serves a copy of the metadata that differs only in `jwks_uri`.
//! kube-apiserver resolves names with the host's resolver, so cluster DNS names do not resolve
//! ([DNS]); it uses the Service's ClusterIP, over `https` (required by [validation.go]), with
//! Genkan's own CA as `certificateAuthority` ([`crate::internal_tls`]). kube-apiserver starts even
//! while Genkan is down and retries discovery every 10 s; it fetches discovery once, when the
//! authenticator starts. A static JWK set is not an option: KEP-3331 lists other key discovery
//! methods as a non-goal. `egressSelectorType` is never set: k3s dials a host name through it as
//! a node name, and kubeadm has no egress configuration, so the authenticator would fail.
//!
//! # Rules kube-apiserver enforces
//!
//! - `has(claims.client_id)`: kube-apiserver does not look at the JWT `typ`, so this accepts access
//!   tokens, which carry `client_id` ([RFC 9068] §2.2), and rejects ID tokens, which are meant for
//!   the client.
//! - `exp - iat` is bounded, because kube-apiserver cannot revoke a token before it expires.
//! - A token whose groups include `elevated:` must be short and issued within two minutes of the
//!   sign-in (`auth_time`), so a mistake in the issuer cannot hand out long-lived privilege. JSON
//!   claims are untyped in CEL, so the list is wrapped in `dyn(claims.groups)` for the
//!   comprehension to type-check; this was verified on a real API server.
//! - Usernames and groups get the `genkan:` prefix, which already rules out `system:`. Structured
//!   configuration has no built-in rejection of `system:`, so `userValidationRules` reject it as
//!   well, in case the mapping changes.
//! - `client_id`, `amr` and `jti` are mapped into `extra` under `genkan.engawahq.dev/`, so `kubectl
//!   auth whoami` and audit events tie a request to one token issuance.
//!
//! # Distributions
//!
//! | `--distro` | `anonymous` section | Internal discovery |
//! |---|---|---|
//! | `k3s` | `enabled: false` | With the embedded agent |
//! | `k0s` | omitted | With a worker on the controller |
//! | `kubeadm`, kind | health paths only | Yes |
//! | `kubesolo` | unsupported | - |
//! | `generic` | omitted | Depends on the cluster |
//!
//! - **k3s** normally passes `--anonymous-auth=false` but drops it when it sees an authentication
//!   configuration file, so the file restores it. Internal discovery needs kube-proxy on the
//!   server, which `--disable-agent` removes.
//! - **k0s** keeps `--anonymous-auth=false`, and releases before v1.34.11+k0s.0, v1.35.8+k0s.0 and
//!   v1.36.3+k0s.1 refuse to start kube-apiserver when the file has an `anonymous` field.
//!   kube-apiserver runs as the user `kube-apiserver`, so the file must be readable by it (mode
//!   0644; it holds no secrets). Dedicated controllers run no kube-proxy and use public discovery.
//! - **kubeadm** runs kube-apiserver as a static pod whose probes the kubelet sends without
//!   credentials, so anonymous access stays on for `/livez`, `/readyz` and `/healthz` only. The
//!   directory, not the file, is mounted into the pod: a single-file bind mount would keep showing
//!   the old file after an atomic replace.
//! - **KubeSolo** v1.2.1 hard-codes kube-apiserver's flags, so the file cannot be passed
//!   ([KubeSolo]).
//!
//! Installation follows each distribution's documented mechanism ([k3s], [k0s], [kubeadm]); see
//! [`instructions`].
//!
//! # References
//!
//! - [KEP-3331] The Kubernetes Authors, "KEP-3331: Structured Authentication Configuration,"
//!   kubernetes/enhancements.
//! - [oidc.go] The Kubernetes Authors,
//!   `staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go`.
//! - [validation.go] The Kubernetes Authors,
//!   `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go`, v1.37.1.
//! - [DNS] The Kubernetes Authors, "DNS for Services and Pods," Kubernetes documentation.
//! - [RFC 9068] V. Bertocci, "JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens," RFC 9068,
//!   IETF, Oct. 2021.
//! - [k3s] K3s project, K3s documentation, `k3s server` command reference.
//! - [k0s] k0s project, k0s documentation, configuration reference.
//! - [kubeadm] The Kubernetes Authors, Kubernetes documentation, kubeadm control-plane flags.
//! - [KubeSolo] Portainer, KubeSolo, GitHub repository.
//!
//! [KEP-3331]: https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/3331-structured-authentication-configuration
//! [oidc.go]: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go
//! [validation.go]: https://github.com/kubernetes/kubernetes/blob/v1.37.1/staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go
//! [DNS]: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
//! [RFC 9068]: https://www.rfc-editor.org/rfc/rfc9068
//! [k3s]: https://docs.k3s.io/cli/server
//! [k0s]: https://docs.k0sproject.io/stable/configuration/
//! [kubeadm]: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/control-plane-flags/
//! [KubeSolo]: https://github.com/portainer/kubesolo

use std::net::IpAddr;
use std::time::Duration;

use clap::ValueEnum;
use genkan_core::clock::UnixTime;
use genkan_core::config::{BaseUrl, ConfigError};
use genkan_core::protocol::{ELEVATED_GROUP_PREFIX, OPENID_CONFIGURATION_PATH};
use k8s_openapi::api::core::v1::{Secret, Service};
use kube::Client;
use kube::api::{Api, PostParams};
use thiserror::Error;

use crate::internal_tls::{self, TlsError};
use crate::rbac::{IDENTITY_PREFIX, NAME};

/// Prefix of the `extra` keys Genkan maps into Kubernetes user info.
pub const EXTRA_PREFIX: &str = "genkan.engawahq.dev/";

/// Most seconds between sign-in and an elevated token's issue: the code lifetime with slack.
const ELEVATED_FRESHNESS: u64 = 120;

/// Warn before this remaining validity; never silently replace a live CA.
const RENEW_BEFORE: Duration = Duration::from_hours(30 * 24);

const ROTATION_ID: &str = "genkan.engawahq.dev/tls-rotation-id";
const ROTATION_PHASE: &str = "genkan.engawahq.dev/tls-rotation-phase";
const NEXT_EXPIRY: &str = "genkan.engawahq.dev/tls-next-not-after";
const PREVIOUS_EXPIRY: &str = "genkan.engawahq.dev/tls-previous-not-after";
const ACTIVE_CA: &str = "active.ca.crt";
const NEXT_CERT: &str = "next.tls.crt";
const NEXT_KEY: &str = "next.tls.key";
const NEXT_CA: &str = "next.ca.crt";
const PREVIOUS_CERT: &str = "previous.tls.crt";
const PREVIOUS_KEY: &str = "previous.tls.key";
const PREVIOUS_CA: &str = "previous.ca.crt";

/// Built-in CA rotation operations. Activation and cleanup require operator rollout checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CertificateAction {
    /// Reuse existing material, or issue the initial certificate if the Secret is absent.
    Current,
    /// Persist a candidate and print overlapping old+new trust, keeping the old leaf active.
    Prepare,
    /// Activate the candidate after every control plane has successfully loaded overlap.
    Activate,
    /// Restore the previous unexpired leaf, keeping overlapping trust.
    Rollback,
    /// Remove rollback material and print new-only trust after all listeners serve the new leaf.
    Finish,
    /// Discard a prepared or rolled-back candidate after all listeners serve the old leaf.
    Cancel,
}

/// Persisted rotation identity and phase, including terminal markers for retry safety.
#[derive(Debug, Clone)]
pub struct Rotation {
    /// Opaque identifier to pass to the exact rotation's transition command.
    pub id: String,
    /// One of `prepared`, `activated`, `rolled-back`, `finished`, or `cancelled`.
    pub phase: String,
}

/// Where kube-apiserver runs; decides the `anonymous` section and the install instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Distro {
    /// k3s (kube-apiserver inside the k3s process).
    K3s,
    /// k0s with a worker on each controller (`--enable-worker` or `--single`).
    K0s,
    /// kubeadm, and kind, which uses it (kube-apiserver as a static pod).
    Kubeadm,
    /// KubeSolo: not supported, it cannot pass flags to kube-apiserver.
    Kubesolo,
    /// Any other distribution: the configuration file only.
    Generic,
}

/// How kube-apiserver reaches discovery and the JWK set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiscoveryMode {
    /// Through the Service's ClusterIP, with Genkan's own certificate (no dependency on public
    /// DNS, ingress or a public certificate).
    Internal,
    /// Through the public issuer URL, which the control-plane nodes must reach and trust.
    Public,
}

/// Internal discovery: where, and the CA that vouches for it.
#[derive(Debug, Clone)]
pub struct InternalDiscovery {
    /// Base URL of the internal listener (`https://<ClusterIP>`).
    pub url: BaseUrl,
    /// PEM of the CA kube-apiserver trusts for that URL.
    pub ca_pem: String,
}

/// Everything the generated `AuthenticationConfiguration` depends on.
#[derive(Debug, Clone)]
pub struct ApiserverOptions {
    /// The distribution.
    pub distro: Distro,
    /// The issuer identifier.
    pub issuer: BaseUrl,
    /// Internal discovery, or `None` for the public URL.
    pub internal: Option<InternalDiscovery>,
    /// Accepted token audiences.
    pub audiences: Vec<String>,
    /// Longest accepted token lifetime (`exp - iat`).
    pub max_token_lifetime: Duration,
    /// Longest accepted lifetime of a token carrying `elevated:` groups.
    pub max_elevated_token_lifetime: Duration,
}

/// Why `kube-config` failed.
#[derive(Debug, Error)]
pub enum KubeConfigError {
    /// The distribution cannot be configured.
    #[error(
        "KubeSolo hard-codes kube-apiserver's flags, so it cannot use an AuthenticationConfiguration yet"
    )]
    Unsupported,
    /// The Kubernetes API failed.
    #[error("Kubernetes API: {0}")]
    Kubernetes(#[from] kube::Error),
    /// Genkan's Service is missing or has no ClusterIP.
    #[error(
        "Service {namespace}/{name} has no ClusterIP; install Genkan first (`genkanctl manifests`)"
    )]
    NoService {
        /// Namespace searched.
        namespace: String,
        /// Service name.
        name: &'static str,
    },
    /// The ClusterIP is not an IP address.
    #[error("Service ClusterIP {0:?} is not an IP address")]
    BadClusterIp(String),
    /// Issuing or reading the certificate failed.
    #[error("internal certificate: {0}")]
    Tls(#[from] TlsError),
    /// The existing Secret carries no CA certificate to give kube-apiserver.
    #[error(
        "Secret {0} has no ca.crt; add the CA from its issuer without replacing the serving pair"
    )]
    NoCa(&'static str),
    /// An option is invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// An audience cannot be used.
    #[error("audience {0:?} must be non-empty printable ASCII without spaces")]
    BadAudience(String),
    /// The requested or persisted certificate rotation is unsafe or inconsistent.
    #[error("certificate rotation: {0}")]
    Rotation(String),
}

/// A YAML double-quoted scalar (JSON string syntax is valid YAML).
fn quoted(value: &str) -> String {
    serde_json::Value::String(value.to_owned()).to_string()
}

fn validate_configuration(options: &ApiserverOptions) -> Result<(), KubeConfigError> {
    if options.distro == Distro::Kubesolo {
        return Err(KubeConfigError::Unsupported);
    }
    if let Some(bad) = options
        .audiences
        .iter()
        .find(|a| a.is_empty() || !a.bytes().all(|b| b.is_ascii_graphic()))
    {
        return Err(KubeConfigError::BadAudience(bad.clone()));
    }
    Ok(())
}

/// Renders the `AuthenticationConfiguration` (YAML).
///
/// # Errors
///
/// Returns [`KubeConfigError::Unsupported`] for KubeSolo, and [`KubeConfigError::BadAudience`]
/// for an empty or unusual audience.
pub fn authentication_configuration(options: &ApiserverOptions) -> Result<String, KubeConfigError> {
    validate_configuration(options)?;
    let mut out = String::new();
    let mut line = |text: &str| {
        out.push_str(text);
        out.push('\n');
    };
    line("# kube-apiserver AuthenticationConfiguration for Genkan, from `genkanctl kube-config`.");
    line("apiVersion: apiserver.config.k8s.io/v1");
    line("kind: AuthenticationConfiguration");
    match options.distro {
        // k3s drops its own --anonymous-auth=false when it sees this file; restore it.
        Distro::K3s => {
            line("anonymous:");
            line("  enabled: false");
        }
        // kubelet probes the static pod anonymously.
        Distro::Kubeadm => {
            line("anonymous:");
            line("  enabled: true");
            line("  conditions:");
            for path in ["/livez", "/readyz", "/healthz"] {
                line(&format!("  - path: {path}"));
            }
        }
        // k0s keeps --anonymous-auth=false; older k0s refuses the field.
        Distro::K0s | Distro::Generic | Distro::Kubesolo => {}
    }
    line("jwt:");
    line("- issuer:");
    line(&format!("    url: {}", quoted(options.issuer.as_str())));
    if let Some(internal) = &options.internal {
        line(&format!(
            "    discoveryURL: {}",
            quoted(&internal.url.join(OPENID_CONFIGURATION_PATH))
        ));
        line("    certificateAuthority: |");
        for pem in internal.ca_pem.lines().filter(|l| !l.trim().is_empty()) {
            line(&format!("      {}", pem.trim_end()));
        }
    }
    line("    audiences:");
    for audience in &options.audiences {
        line(&format!("    - {}", quoted(audience)));
    }
    line("    audienceMatchPolicy: MatchAny");
    line("  claimValidationRules:");
    line("  - expression: \"has(claims.client_id)\"");
    line("    message: \"only Genkan access tokens are accepted (ID tokens carry no client_id)\"");
    let lifetime = options.max_token_lifetime.as_secs();
    line(&format!(
        "  - expression: \"claims.exp - claims.iat <= {lifetime}\""
    ));
    line(&format!(
        "    message: \"token lifetime must not exceed {lifetime} seconds\""
    ));
    // Elevated groups only in short tokens issued right after a sign-in, enforced here too, so a
    // mistake in the issuer cannot hand out long-lived privilege. JSON claims are untyped in CEL;
    // `dyn()` lets the comprehension accept the list.
    let elevated = options.max_elevated_token_lifetime.as_secs();
    line(&format!(
        "  - expression: \"!has(claims.groups) || !dyn(claims.groups).exists(g, g.startsWith('{ELEVATED_GROUP_PREFIX}')) || (claims.exp - claims.iat <= {elevated} && claims.iat - claims.auth_time <= {ELEVATED_FRESHNESS})\""
    ));
    line(&format!(
        "    message: \"elevated groups need a token of at most {elevated} seconds issued right after a passkey sign-in\""
    ));
    line("  claimMappings:");
    line("    username:");
    line("      claim: preferred_username");
    line(&format!("      prefix: {}", quoted(IDENTITY_PREFIX)));
    line("    groups:");
    line("      claim: groups");
    line(&format!("      prefix: {}", quoted(IDENTITY_PREFIX)));
    line("    uid:");
    line("      claim: sub");
    line("    extra:");
    line(&format!(
        "    - key: {}",
        quoted(&format!("{EXTRA_PREFIX}client-id"))
    ));
    line("      valueExpression: \"claims.client_id\"");
    line(&format!(
        "    - key: {}",
        quoted(&format!("{EXTRA_PREFIX}amr"))
    ));
    line("      valueExpression: \"has(claims.amr) ? claims.amr : []\"");
    line(&format!(
        "    - key: {}",
        quoted(&format!("{EXTRA_PREFIX}jti"))
    ));
    line("      valueExpression: \"claims.jti\"");
    line("  userValidationRules:");
    line("  - expression: \"!user.username.startsWith('system:')\"");
    line("    message: \"the system: prefix is reserved\"");
    line("  - expression: \"user.groups.all(g, !g.startsWith('system:'))\"");
    line("    message: \"the system: prefix is reserved\"");
    Ok(out)
}

/// How to install the file on `distro`, for the cluster admin (plain text).
#[must_use]
pub fn instructions(distro: Distro, discovery: DiscoveryMode) -> String {
    let (path, steps): (&str, &[&str]) = match distro {
        Distro::K3s => (
            "/etc/rancher/k3s/genkan/authn.yaml",
            &[
                "On every server node, save the configuration above as /etc/rancher/k3s/genkan/authn.yaml.",
                "Add /etc/rancher/k3s/config.yaml.d/50-genkan.yaml containing:",
                "    kube-apiserver-arg:",
                "      - \"authentication-config=/etc/rancher/k3s/genkan/authn.yaml\"",
                "Run `systemctl restart k3s` once. Later changes to authn.yaml are picked up within about a minute.",
                "Internal discovery needs the node's embedded agent (it does not work with --disable-agent).",
            ],
        ),
        Distro::K0s => (
            "/etc/k0s/genkan/authn.yaml",
            &[
                "On every controller, save the configuration above as /etc/k0s/genkan/authn.yaml with mode 0644 (kube-apiserver runs as user kube-apiserver).",
                "In /etc/k0s/k0s.yaml set:",
                "    spec:",
                "      api:",
                "        extraArgs:",
                "          authentication-config: /etc/k0s/genkan/authn.yaml",
                "Remove any oidc-* extraArgs (they cannot be combined with authentication-config).",
                "Run `systemctl restart k0scontroller` on each controller, one at a time.",
                "Internal discovery needs a worker on the controller (--enable-worker or --single); dedicated controllers should use --discovery public.",
            ],
        ),
        Distro::Kubeadm => (
            "/etc/kubernetes/genkan/authn.yaml",
            &[
                "On every control-plane node, save the configuration above as /etc/kubernetes/genkan/authn.yaml.",
                "Add to the ClusterConfiguration (kubeadm.k8s.io/v1beta4, `kubectl -n kube-system edit cm kubeadm-config`):",
                "    apiServer:",
                "      extraArgs:",
                "      - name: authentication-config",
                "        value: /etc/kubernetes/genkan/authn.yaml",
                "      extraVolumes:",
                "      - name: genkan",
                "        hostPath: /etc/kubernetes/genkan",
                "        mountPath: /etc/kubernetes/genkan",
                "        readOnly: true",
                "        pathType: DirectoryOrCreate",
                "Then on each control-plane node: `kubeadm init phase control-plane apiserver --config <file>`.",
                "The directory (not the file) is mounted so that replacing authn.yaml is seen by kube-apiserver.",
            ],
        ),
        Distro::Generic | Distro::Kubesolo => (
            "authn.yaml",
            &[
                "Save the configuration above where kube-apiserver can read it and start kube-apiserver with --authentication-config=<path>.",
                "Remove any --oidc-* flags; they cannot be combined with --authentication-config.",
                "Check how your distribution handles --anonymous-auth: the file may need an `anonymous` section.",
            ],
        ),
    };
    let mut lines = vec![format!("Install ({path}):")];
    lines.extend(steps.iter().map(|step| format!("  {step}")));
    if discovery == DiscoveryMode::Public {
        lines.push(
            "  Public discovery: every control-plane node must resolve the issuer and trust its certificate."
                .to_owned(),
        );
    }
    lines.push(format!(
        "Check: `kubectl --token=<access token> auth whoami` shows a user named {IDENTITY_PREFIX}<username>."
    ));
    lines.join("\n")
}

/// Inputs of [`prepare`].
#[derive(Debug, Clone)]
pub struct Request {
    /// Genkan's namespace.
    pub namespace: String,
    /// What to generate.
    pub distro: Distro,
    /// The issuer identifier.
    pub issuer: BaseUrl,
    /// How kube-apiserver reaches discovery.
    pub discovery: DiscoveryMode,
    /// Accepted audiences.
    pub audiences: Vec<String>,
    /// Longest accepted token lifetime.
    pub max_token_lifetime: Duration,
    /// Longest accepted lifetime of an elevated token.
    pub max_elevated_token_lifetime: Duration,
    /// Built-in certificate lifecycle operation; ordinary invocation is `Current`.
    pub certificate_action: CertificateAction,
    /// Exact persisted rotation id; required for activate, rollback, finish and cancel.
    pub rotation_id: Option<String>,
    /// Lifetime of a newly issued certificate.
    pub certificate_validity: Duration,
    /// The current time.
    pub now: UnixTime,
}

/// What [`prepare`] produced.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The `AuthenticationConfiguration` (YAML).
    pub configuration: String,
    /// When a newly issued certificate expires, if one was issued.
    pub issued_until: Option<UnixTime>,
    /// Persisted rotation state, if any.
    pub rotation: Option<Rotation>,
    /// SHA-256 of the active leaf DER (lowercase hex), for checking actual listener rollout.
    pub serving_leaf_sha256: Option<String>,
    /// SHA-256 of the candidate leaf DER, distinct from the opaque rotation id.
    pub candidate_leaf_sha256: Option<String>,
    /// Active certificate expiry when expired or within the 30-day renewal warning window.
    /// An unannotated external certificate has no reported expiry.
    pub expiry_warning: Option<UnixTime>,
}

/// Prepares the cluster for internal discovery (if chosen) and renders the configuration.
///
/// # Errors
///
/// Returns [`KubeConfigError`] if the distribution is unsupported, Genkan's Service is missing,
/// or the API refuses a request.
pub async fn prepare(client: Client, request: &Request) -> Result<Prepared, KubeConfigError> {
    // Validate rendering before a lifecycle write, so invalid input never changes trust.
    let options = ApiserverOptions {
        distro: request.distro,
        issuer: request.issuer.clone(),
        internal: None,
        audiences: request.audiences.clone(),
        max_token_lifetime: request.max_token_lifetime,
        max_elevated_token_lifetime: request.max_elevated_token_lifetime,
    };
    validate_configuration(&options)?;
    let (
        internal,
        issued_until,
        rotation,
        serving_leaf_sha256,
        candidate_leaf_sha256,
        expiry_warning,
    ) = match request.discovery {
        DiscoveryMode::Public => {
            if request.certificate_action != CertificateAction::Current
                || request.rotation_id.is_some()
            {
                return Err(rotation_error(
                    "certificate rotation requires internal discovery",
                ));
            }
            (None, None, None, None, None, None)
        }
        DiscoveryMode::Internal => {
            let certificate = ensure_certificate(client, request).await?;
            (
                Some(certificate.discovery),
                certificate.issued_until,
                certificate.rotation,
                Some(certificate.serving_leaf_sha256),
                certificate.candidate_leaf_sha256,
                certificate.expiry_warning,
            )
        }
    };
    let configuration = authentication_configuration(&ApiserverOptions {
        internal,
        ..options
    })?;
    Ok(Prepared {
        configuration,
        issued_until,
        rotation,
        serving_leaf_sha256,
        candidate_leaf_sha256,
        expiry_warning,
    })
}

struct Certificate {
    discovery: InternalDiscovery,
    issued_until: Option<UnixTime>,
    rotation: Option<Rotation>,
    serving_leaf_sha256: String,
    candidate_leaf_sha256: Option<String>,
    expiry_warning: Option<UnixTime>,
}

#[expect(
    clippy::too_many_lines,
    reason = "one read-modify-CAS lifecycle kept together"
)]
async fn ensure_certificate(
    client: Client,
    request: &Request,
) -> Result<Certificate, KubeConfigError> {
    let namespace = &request.namespace;
    let services: Api<Service> = Api::namespaced(client.clone(), namespace);
    let no_service = || KubeConfigError::NoService {
        namespace: namespace.clone(),
        name: NAME,
    };
    let cluster_ip = services
        .get_opt(NAME)
        .await?
        .and_then(|s| s.spec)
        .and_then(|spec| spec.cluster_ip)
        .filter(|ip| !ip.is_empty() && ip != "None")
        .ok_or_else(no_service)?;
    let ip: IpAddr = cluster_ip
        .parse()
        .map_err(|_parse| KubeConfigError::BadClusterIp(cluster_ip.clone()))?;
    let url = internal_tls::internal_url(ip)?;

    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let existing = secrets.get_opt(internal_tls::SECRET).await?;
    let dns_names = [
        format!("{NAME}.{namespace}.svc"),
        format!("{NAME}.{namespace}.svc.cluster.local"),
    ];
    let issue = || {
        genkan_tls::certificate::issue(ip, &dns_names, request.now, request.certificate_validity)
            .map_err(TlsError::from)
    };
    let mut issued_until = None;
    let secret = match existing {
        None => {
            if request.certificate_action != CertificateAction::Current
                || request.rotation_id.is_some()
            {
                return Err(rotation_error(
                    "create the initial certificate with --certificate-action current first",
                ));
            }
            let issued = issue()?;
            issued_until = Some(issued.not_after);
            secrets
                .create(
                    &PostParams::default(),
                    &internal_tls::secret(namespace, &issued, &url),
                )
                .await?
        }
        Some(mut current) => {
            let material = internal_tls::parse(&current)?;
            if material.url.as_ref() != Some(&url) {
                return Err(rotation_error(
                    "the active Secret URL differs from the Service; restore the Service address or replace externally issued material explicitly",
                ));
            }
            material
                .ca_pem
                .as_ref()
                .ok_or(KubeConfigError::NoCa(internal_tls::SECRET))?;
            let state = rotation(&current)?;
            let changed = match request.certificate_action {
                CertificateAction::Current => {
                    if request.rotation_id.is_some() {
                        return Err(rotation_error("current does not take --rotation-id"));
                    }
                    false
                }
                CertificateAction::Prepare
                | CertificateAction::Activate
                | CertificateAction::Rollback
                | CertificateAction::Finish
                | CertificateAction::Cancel => {
                    if current
                        .metadata
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get(crate::MANAGED_BY.0))
                        .map(String::as_str)
                        != Some(crate::MANAGED_BY.1)
                        || current
                            .metadata
                            .owner_references
                            .as_ref()
                            .is_some_and(|owners| !owners.is_empty())
                    {
                        return Err(rotation_error(
                            "externally managed material must be renewed by its issuer; the CLI never replaces it",
                        ));
                    }
                    match request.certificate_action {
                        CertificateAction::Prepare => {
                            if request.rotation_id.is_some() {
                                return Err(rotation_error("prepare does not take --rotation-id"));
                            }
                            match state.as_ref().map(|state| state.phase.as_str()) {
                                Some("prepared") => false,
                                Some("activated" | "rolled-back") => {
                                    return Err(rotation_error(
                                        "finish or cancel the outstanding rotation first",
                                    ));
                                }
                                _ => {
                                    let issued = issue()?;
                                    issued_until = Some(issued.not_after);
                                    stage(&mut current, &issued)?;
                                    true
                                }
                            }
                        }
                        CertificateAction::Activate
                        | CertificateAction::Rollback
                        | CertificateAction::Finish
                        | CertificateAction::Cancel => transition(&mut current, request)?,
                        CertificateAction::Current => false,
                    }
                }
            };
            if changed {
                // Replace the exact object read, retaining UID/resourceVersion and unrelated
                // fields.
                current = secrets
                    .replace(internal_tls::SECRET, &PostParams::default(), &current)
                    .await?;
            }
            current
        }
    };
    let material = internal_tls::parse(&secret)?;
    let ca_pem = material
        .ca_pem
        .ok_or(KubeConfigError::NoCa(internal_tls::SECRET))?;
    let serving_leaf_sha256 = fingerprint(&material.key)?;
    let candidate_leaf_sha256 = secret
        .data
        .as_ref()
        .and_then(|fields| fields.get(NEXT_CERT))
        .map(|cert| {
            let key = data(&secret, NEXT_KEY)?;
            let certified =
                genkan_tls::certificate::certified_key(&cert.0, &key.0).map_err(TlsError::from)?;
            fingerprint(&certified)
        })
        .transpose()?;
    Ok(Certificate {
        discovery: InternalDiscovery { url, ca_pem },
        issued_until,
        rotation: rotation(&secret)?,
        serving_leaf_sha256,
        candidate_leaf_sha256,
        expiry_warning: material
            .not_after
            .filter(|expires| *expires <= request.now.saturating_add(RENEW_BEFORE)),
    })
}

fn fingerprint(key: &rustls::sign::CertifiedKey) -> Result<String, KubeConfigError> {
    let leaf = key
        .cert
        .first()
        .ok_or_else(|| rotation_error("certificate chain is empty"))?;
    Ok(genkan_core::crypto::hex(&genkan_core::crypto::sha256(
        leaf.as_ref(),
    )))
}

fn rotation_error(message: &str) -> KubeConfigError {
    KubeConfigError::Rotation(message.to_owned())
}

fn annotation<'a>(secret: &'a Secret, key: &str) -> Option<&'a str> {
    secret
        .metadata
        .annotations
        .as_ref()?
        .get(key)
        .map(String::as_str)
}

fn rotation(secret: &Secret) -> Result<Option<Rotation>, KubeConfigError> {
    match (
        annotation(secret, ROTATION_ID),
        annotation(secret, ROTATION_PHASE),
    ) {
        (None, None) => Ok(None),
        (
            Some(id),
            Some(phase @ ("prepared" | "activated" | "rolled-back" | "finished" | "cancelled")),
        ) if !id.is_empty() => Ok(Some(Rotation {
            id: id.to_owned(),
            phase: phase.to_owned(),
        })),
        _ => Err(rotation_error(
            "persisted rotation identity or phase is invalid",
        )),
    }
}

fn data(secret: &Secret, key: &str) -> Result<k8s_openapi::ByteString, KubeConfigError> {
    secret
        .data
        .as_ref()
        .and_then(|fields| fields.get(key))
        .cloned()
        .ok_or_else(|| rotation_error("rotation material is incomplete"))
}

fn stage(
    secret: &mut Secret,
    issued: &genkan_tls::certificate::Issued,
) -> Result<(), KubeConfigError> {
    let old_ca = data(secret, internal_tls::CA_KEY)?;
    let old_pem = std::str::from_utf8(&old_ca.0)
        .map_err(|_utf8| rotation_error("active CA is not PEM text"))?;
    let bundle =
        k8s_openapi::ByteString(format!("{}\n{}", old_pem.trim_end(), issued.ca_pem).into_bytes());
    let id = genkan_core::crypto::random::<16>()
        .map_err(|_crypto| rotation_error("generating the rotation id failed"))?;
    let fields = secret.data.get_or_insert_default();
    fields.insert(ACTIVE_CA.into(), old_ca);
    for (key, value) in [
        (NEXT_CERT, &issued.cert_pem),
        (NEXT_KEY, &issued.key_pem),
        (NEXT_CA, &issued.ca_pem),
    ] {
        fields.insert(
            key.into(),
            k8s_openapi::ByteString(value.as_bytes().to_vec()),
        );
    }
    fields.insert(internal_tls::CA_KEY.into(), bundle);
    let annotations = secret.metadata.annotations.get_or_insert_default();
    annotations.insert(ROTATION_ID.into(), genkan_core::crypto::hex(&id));
    annotations.insert(ROTATION_PHASE.into(), "prepared".into());
    annotations.insert(NEXT_EXPIRY.into(), issued.not_after.as_secs().to_string());
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "all persisted trust transitions share one exhaustive operation match"
)]
fn transition(secret: &mut Secret, request: &Request) -> Result<bool, KubeConfigError> {
    let state = rotation(secret)?
        .ok_or_else(|| rotation_error("no staged rotation; run --certificate-action prepare"))?;
    if request.rotation_id.as_deref() != Some(state.id.as_str()) {
        return Err(rotation_error(
            "supply --rotation-id from the exact prepared bundle",
        ));
    }
    let (source, expiry_key, phase) = match request.certificate_action {
        CertificateAction::Activate => {
            if state.phase == "activated" {
                return Ok(false);
            }
            if state.phase != "prepared" && state.phase != "rolled-back" {
                return Err(rotation_error(
                    "only prepared or rolled-back material can be activated",
                ));
            }
            ([NEXT_CERT, NEXT_KEY, NEXT_CA], NEXT_EXPIRY, "activated")
        }
        CertificateAction::Rollback => {
            if state.phase == "rolled-back" {
                return Ok(false);
            }
            if state.phase != "activated" {
                return Err(rotation_error(
                    "only an activated rotation can be rolled back",
                ));
            }
            (
                [PREVIOUS_CERT, PREVIOUS_KEY, PREVIOUS_CA],
                PREVIOUS_EXPIRY,
                "rolled-back",
            )
        }
        CertificateAction::Finish | CertificateAction::Cancel => {
            let (allowed, completed) = if request.certificate_action == CertificateAction::Finish {
                (state.phase == "activated", "finished")
            } else {
                (
                    state.phase == "prepared" || state.phase == "rolled-back",
                    "cancelled",
                )
            };
            if state.phase == completed {
                return Ok(false);
            }
            if !allowed {
                return Err(rotation_error(
                    "finish requires activation; cancel requires prepared or rolled-back material",
                ));
            }
            let ca = data(secret, ACTIVE_CA)?;
            let fields = secret.data.get_or_insert_default();
            fields.insert(internal_tls::CA_KEY.into(), ca);
            for key in [
                ACTIVE_CA,
                NEXT_CERT,
                NEXT_KEY,
                NEXT_CA,
                PREVIOUS_CERT,
                PREVIOUS_KEY,
                PREVIOUS_CA,
            ] {
                fields.remove(key);
            }
            let annotations = secret.metadata.annotations.get_or_insert_default();
            annotations.remove(NEXT_EXPIRY);
            annotations.remove(PREVIOUS_EXPIRY);
            annotations.insert(ROTATION_PHASE.into(), completed.into());
            return Ok(true);
        }
        CertificateAction::Current | CertificateAction::Prepare => {
            return Err(rotation_error(
                "this operation does not transition a rotation",
            ));
        }
    };
    let expiry = annotation(secret, expiry_key)
        .and_then(|seconds| seconds.parse::<u64>().ok())
        .map(UnixTime::from_secs)
        .ok_or_else(|| rotation_error("rotation expiry is missing"))?;
    if expiry <= request.now {
        return Err(rotation_error(
            "refusing to activate an expired certificate",
        ));
    }
    let [cert_name, key_name, ca_name] = source;
    let [cert, key, ca] = [
        data(secret, cert_name)?,
        data(secret, key_name)?,
        data(secret, ca_name)?,
    ];
    genkan_tls::certificate::certified_key(&cert.0, &key.0).map_err(TlsError::from)?;
    if state.phase == "prepared" {
        let old = [
            data(secret, internal_tls::CERT_KEY)?,
            data(secret, internal_tls::KEY_KEY)?,
            data(secret, ACTIVE_CA)?,
        ];
        let old_expiry = annotation(secret, internal_tls::NOT_AFTER_ANNOTATION)
            .ok_or_else(|| rotation_error("built-in certificate has no expiry"))?
            .to_owned();
        let fields = secret.data.get_or_insert_default();
        for (name, value) in [PREVIOUS_CERT, PREVIOUS_KEY, PREVIOUS_CA]
            .into_iter()
            .zip(old)
        {
            fields.insert(name.into(), value);
        }
        secret
            .metadata
            .annotations
            .get_or_insert_default()
            .insert(PREVIOUS_EXPIRY.into(), old_expiry);
    }
    let fields = secret.data.get_or_insert_default();
    for (name, value) in [internal_tls::CERT_KEY, internal_tls::KEY_KEY, ACTIVE_CA]
        .into_iter()
        .zip([cert, key, ca])
    {
        fields.insert(name.into(), value);
    }
    let annotations = secret.metadata.annotations.get_or_insert_default();
    annotations.insert(
        internal_tls::NOT_AFTER_ANNOTATION.into(),
        expiry.as_secs().to_string(),
    );
    annotations.insert(ROTATION_PHASE.into(), phase.into());
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(distro: Distro, internal: bool) -> ApiserverOptions {
        ApiserverOptions {
            distro,
            issuer: BaseUrl::parse("issuer", "https://login.example.com").unwrap(),
            internal: internal.then(|| InternalDiscovery {
                url: BaseUrl::parse("internal", "https://10.43.0.53").unwrap(),
                ca_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into(),
            }),
            audiences: vec!["kubernetes".into()],
            max_token_lifetime: Duration::from_hours(1),
            max_elevated_token_lifetime: Duration::from_mins(5),
        }
    }

    #[test]
    fn k3s_internal_configuration() {
        let yaml = authentication_configuration(&options(Distro::K3s, true)).unwrap();
        let expected = r#"# kube-apiserver AuthenticationConfiguration for Genkan, from `genkanctl kube-config`.
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
anonymous:
  enabled: false
jwt:
- issuer:
    url: "https://login.example.com"
    discoveryURL: "https://10.43.0.53/.well-known/openid-configuration"
    certificateAuthority: |
      -----BEGIN CERTIFICATE-----
      AAAA
      -----END CERTIFICATE-----
    audiences:
    - "kubernetes"
    audienceMatchPolicy: MatchAny
  claimValidationRules:
  - expression: "has(claims.client_id)"
    message: "only Genkan access tokens are accepted (ID tokens carry no client_id)"
  - expression: "claims.exp - claims.iat <= 3600"
    message: "token lifetime must not exceed 3600 seconds"
  - expression: "!has(claims.groups) || !dyn(claims.groups).exists(g, g.startsWith('elevated:')) || (claims.exp - claims.iat <= 300 && claims.iat - claims.auth_time <= 120)"
    message: "elevated groups need a token of at most 300 seconds issued right after a passkey sign-in"
  claimMappings:
    username:
      claim: preferred_username
      prefix: "genkan:"
    groups:
      claim: groups
      prefix: "genkan:"
    uid:
      claim: sub
    extra:
    - key: "genkan.engawahq.dev/client-id"
      valueExpression: "claims.client_id"
    - key: "genkan.engawahq.dev/amr"
      valueExpression: "has(claims.amr) ? claims.amr : []"
    - key: "genkan.engawahq.dev/jti"
      valueExpression: "claims.jti"
  userValidationRules:
  - expression: "!user.username.startsWith('system:')"
    message: "the system: prefix is reserved"
  - expression: "user.groups.all(g, !g.startsWith('system:'))"
    message: "the system: prefix is reserved"
"#;
        assert_eq!(yaml, expected);
    }

    #[test]
    fn anonymous_section_follows_the_distribution() {
        let kubeadm = authentication_configuration(&options(Distro::Kubeadm, true)).unwrap();
        assert!(kubeadm.contains("  enabled: true\n  conditions:\n  - path: /livez\n"));
        for distro in [Distro::K0s, Distro::Generic] {
            let yaml = authentication_configuration(&options(distro, true)).unwrap();
            assert!(!yaml.contains("anonymous"), "{distro:?}");
        }
        assert!(matches!(
            authentication_configuration(&options(Distro::Kubesolo, true)),
            Err(KubeConfigError::Unsupported)
        ));
    }

    #[test]
    fn public_discovery_has_no_discovery_url_or_ca() {
        let yaml = authentication_configuration(&options(Distro::K3s, false)).unwrap();
        assert!(!yaml.contains("discoveryURL") && !yaml.contains("certificateAuthority"));
    }

    #[test]
    fn audiences_are_validated() {
        for bad in ["", "two words", "tab\t"] {
            let mut o = options(Distro::K3s, false);
            o.audiences = vec![bad.into()];
            assert!(matches!(
                authentication_configuration(&o),
                Err(KubeConfigError::BadAudience(_))
            ));
        }
    }

    #[test]
    fn instructions_name_the_file_and_the_restart() {
        let k3s = instructions(Distro::K3s, DiscoveryMode::Internal);
        assert!(
            k3s.contains("/etc/rancher/k3s/genkan/authn.yaml")
                && k3s.contains("systemctl restart k3s")
        );
        let k0s = instructions(Distro::K0s, DiscoveryMode::Internal);
        assert!(k0s.contains("0644") && k0s.contains("oidc-*"));
        let kubeadm = instructions(Distro::Kubeadm, DiscoveryMode::Public);
        assert!(kubeadm.contains("extraVolumes") && kubeadm.contains("Public discovery"));
    }
}

//! The certificate of the in-cluster discovery listener.
//!
//! kube-apiserver fetches discovery and keys over `https` only, and does not resolve cluster DNS
//! names, so it reaches Genkan at its Service's ClusterIP with a certificate for that IP.
//! `genkanctl kube-config`, run with the cluster admin's credentials, creates a
//! private CA and a serving certificate, stores the serving pair in the `kubernetes.io/tls`
//! Secret [`SECRET`], prints the CA for `issuer.certificateAuthority`, and **discards the CA
//! key**: nothing can issue another certificate under that CA. Genkan's service account can only
//! `get` the Secret. Any other issuer of a `kubernetes.io/tls` Secret (for example cert-manager)
//! works too.
//!
//! Pinning kube-apiserver to this CA, rather than the system roots or plain `http`, is what
//! keeps someone who can answer at the ClusterIP from handing kube-apiserver their own keys. The
//! chain ends in a certificate with `CA:TRUE` because Go's TLS stack, which kube-apiserver uses,
//! requires that even for a self-signed setup ([Authenticating]). The certificate also names the
//! Service's DNS names, for clients that can resolve them. Built-in CA renewal stages an
//! overlapping trust bundle without changing the live serving pair; explicit activation
//! follows distribution to every control plane ([`crate::kube_config`]). External issuers
//! retain ownership of their Secrets.
//!
//! # References
//!
//! - [Authenticating] The Kubernetes Authors, "Authenticating: Using authentication configuration,"
//!   Kubernetes documentation.
//!
//! [Authenticating]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use genkan_core::clock::UnixTime;
use genkan_core::config::{BaseUrl, ConfigError};
use genkan_tls::certificate::{CertificateError, Issued, certified_key};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::ObjectMeta;
use rustls::sign::CertifiedKey;
use thiserror::Error;

use super::MANAGED_BY;

/// Name of the Secret holding the serving certificate.
pub const SECRET: &str = "genkan-internal-tls";
/// Annotation: the `https` base URL kube-apiserver uses to reach the internal listener.
pub const URL_ANNOTATION: &str = "genkan.engawahq.dev/internal-url";
/// Annotation: when the serving certificate expires (Unix seconds).
pub const NOT_AFTER_ANNOTATION: &str = "genkan.engawahq.dev/not-after";

const TLS_TYPE: &str = "kubernetes.io/tls";
pub(crate) const CERT_KEY: &str = "tls.crt";
pub(crate) const KEY_KEY: &str = "tls.key";
pub(crate) const CA_KEY: &str = "ca.crt";

/// Why the certificate Secret could not be used.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Issuing or loading the certificate failed.
    #[error(transparent)]
    Certificate(#[from] CertificateError),
    /// A required field is missing from the Secret.
    #[error("the Secret has no {0}")]
    Missing(&'static str),
    /// The URL annotation is not an `https` base URL.
    #[error(transparent)]
    Url(#[from] ConfigError),
}

/// The Secret holding `issued`, for kube-apiserver to reach Genkan at `url`.
#[must_use]
pub fn secret(namespace: &str, issued: &Issued, url: &BaseUrl) -> Secret {
    let bytes = |s: &str| ByteString(s.as_bytes().to_vec());
    Secret {
        metadata: ObjectMeta {
            name: Some(SECRET.to_owned()),
            namespace: Some(namespace.to_owned()),
            labels: Some(BTreeMap::from([(
                MANAGED_BY.0.to_owned(),
                MANAGED_BY.1.to_owned(),
            )])),
            annotations: Some(BTreeMap::from([
                (URL_ANNOTATION.to_owned(), url.as_str().to_owned()),
                (
                    NOT_AFTER_ANNOTATION.to_owned(),
                    issued.not_after.as_secs().to_string(),
                ),
            ])),
            ..ObjectMeta::default()
        },
        type_: Some(TLS_TYPE.to_owned()),
        data: Some(BTreeMap::from([
            (CERT_KEY.to_owned(), bytes(&issued.cert_pem)),
            (KEY_KEY.to_owned(), bytes(&issued.key_pem)),
            (CA_KEY.to_owned(), bytes(&issued.ca_pem)),
        ])),
        ..Secret::default()
    }
}

/// The `https` base URL for an address inside the cluster.
///
/// # Errors
///
/// Never for an IP address; the result type follows [`BaseUrl::parse`].
pub fn internal_url(ip: IpAddr) -> Result<BaseUrl, ConfigError> {
    match ip {
        IpAddr::V4(ip) => BaseUrl::parse("internal URL", &format!("https://{ip}")),
        IpAddr::V6(ip) => BaseUrl::parse("internal URL", &format!("https://[{ip}]")),
    }
}

/// What the internal listener needs from the Secret.
#[derive(Debug, Clone)]
pub struct Material {
    /// Certificate chain and key, ready for rustls.
    pub key: Arc<CertifiedKey>,
    /// Where kube-apiserver reaches the listener (the annotation), if recorded.
    pub url: Option<BaseUrl>,
    /// When the certificate expires (the annotation), if recorded.
    pub not_after: Option<UnixTime>,
    /// The CA certificate, if the Secret carries it.
    pub ca_pem: Option<String>,
}

fn field<'a>(secret: &'a Secret, key: &'static str) -> Result<&'a [u8], TlsError> {
    secret
        .data
        .as_ref()
        .and_then(|data| data.get(key))
        .map(|bytes| bytes.0.as_slice())
        .ok_or(TlsError::Missing(key))
}

/// Reads a `kubernetes.io/tls` Secret.
///
/// # Errors
///
/// Returns [`TlsError`] if the certificate or key is missing or unusable, or the URL annotation
/// is not an `https` base URL.
pub fn parse(secret: &Secret) -> Result<Material, TlsError> {
    let key = certified_key(field(secret, CERT_KEY)?, field(secret, KEY_KEY)?)?;
    let annotation = |key: &str| {
        secret
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(key))
    };
    let url = annotation(URL_ANNOTATION)
        .map(|url| BaseUrl::parse("internal URL", url))
        .transpose()?;
    let not_after = annotation(NOT_AFTER_ANNOTATION)
        .and_then(|secs| secs.parse().ok())
        .map(UnixTime::from_secs);
    let ca_pem = field(secret, CA_KEY)
        .ok()
        .and_then(|ca| String::from_utf8(ca.to_vec()).ok());
    Ok(Material {
        key,
        url,
        not_after,
        ca_pem,
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use genkan_tls::certificate::issue;

    use super::*;

    const NOW: UnixTime = UnixTime::from_secs(1_800_000_000);

    #[test]
    fn issued_certificate_round_trips_through_the_secret() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 43, 0, 53));
        let issued = issue(
            ip,
            &["genkan.genkan-system.svc".to_owned()],
            NOW,
            Duration::from_hours(24),
        )
        .unwrap();
        assert!(issued.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(
            issued.not_after,
            NOW.saturating_add(Duration::from_hours(24))
        );
        let url = internal_url(ip).unwrap();
        assert_eq!(url.as_str(), "https://10.43.0.53");

        let material = parse(&secret("genkan-system", &issued, &url)).unwrap();
        assert_eq!(material.url, Some(url));
        assert_eq!(material.not_after, Some(issued.not_after));
        assert_eq!(material.ca_pem.as_deref(), Some(issued.ca_pem.as_str()));
        assert_eq!(material.key.cert.len(), 1);
        assert!(
            format!("{issued:?}").contains("not_after")
                && !format!("{issued:?}").contains("PRIVATE")
        );
    }

    #[test]
    fn ipv6_urls_use_brackets() {
        let url = internal_url("fd00::53".parse().unwrap()).unwrap();
        assert_eq!(url.as_str(), "https://[fd00::53]");
    }

    #[test]
    fn rejects_incomplete_secrets() {
        let mut secret = Secret::default();
        assert!(matches!(parse(&secret), Err(TlsError::Missing("tls.crt"))));
        secret.data = Some(BTreeMap::from([
            ("tls.crt".to_owned(), ByteString(b"not pem".to_vec())),
            ("tls.key".to_owned(), ByteString(b"not pem".to_vec())),
        ]));
        assert!(matches!(
            parse(&secret),
            Err(TlsError::Certificate(CertificateError::Pem(_)))
        ));
    }
}

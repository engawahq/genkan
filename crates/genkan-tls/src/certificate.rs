//! Issuing a private CA and a serving certificate, and loading a certificate for rustls.
//!
//! The CA is ECDSA P-256 with path length 0, and its private key is dropped as soon as the
//! serving certificate is signed: nothing can issue another certificate under it. The serving
//! certificate is for TLS servers only (extended key usage `serverAuth`) and names exactly the
//! given IP address and DNS names.
//!
//! The pair exists for kube-apiserver, which reaches Genkan's internal listener by IP address
//! and trusts only the CA configured in its `issuer.certificateAuthority`. A CA certificate is
//! issued rather than a single self-signed one because Go's TLS stack requires the chain to end
//! in a certificate with `CA:TRUE`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use genkan_core::clock::UnixTime;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use thiserror::Error;
use time::OffsetDateTime;

/// Clock skew tolerated between the issuing machine and the client.
const BACKDATE: Duration = Duration::from_mins(5);

/// Why a certificate could not be issued or loaded.
#[derive(Debug, Error)]
pub enum CertificateError {
    /// Key or certificate generation failed.
    #[error("generating the certificate: {0}")]
    Generate(#[from] rcgen::Error),
    /// The validity period cannot be represented.
    #[error("the certificate validity is out of range")]
    Validity,
    /// The certificate chain or key is not valid PEM.
    #[error("the {0} is not valid PEM")]
    Pem(&'static str),
    /// The private key is not supported.
    #[error("the private key cannot be used: {0}")]
    Key(rustls::Error),
}

/// A freshly issued serving certificate. The CA key is already gone.
pub struct Issued {
    /// The CA certificate, for `issuer.certificateAuthority`.
    pub ca_pem: String,
    /// The serving certificate.
    pub cert_pem: String,
    /// The serving key (PKCS #8).
    pub key_pem: String,
    /// When the serving certificate expires.
    pub not_after: UnixTime,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

fn offset(time: UnixTime) -> Result<OffsetDateTime, CertificateError> {
    i64::try_from(time.as_secs())
        .ok()
        .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
        .ok_or(CertificateError::Validity)
}

fn name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

/// Issues a CA (path length 0) and an ECDSA P-256 serving certificate for `ip` and `dns_names`,
/// valid from `now` (backdated by five minutes) for `validity`.
///
/// # Errors
///
/// Returns [`CertificateError`] if a name is not a valid DNS name or generation fails.
pub fn issue(
    ip: IpAddr,
    dns_names: &[String],
    now: UnixTime,
    validity: Duration,
) -> Result<Issued, CertificateError> {
    let not_before = offset(now.saturating_sub(BACKDATE))?;
    let not_after_time = now.saturating_add(validity);
    let not_after = offset(not_after_time)?;

    let mut ca = CertificateParams::default();
    ca.distinguished_name = name("Genkan internal CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.not_before = not_before;
    ca.not_after = not_after;
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let ca_pem = ca.self_signed(&ca_key)?.pem();

    let mut leaf = CertificateParams::default();
    leaf.distinguished_name = name("genkan internal");
    leaf.subject_alt_names = std::iter::once(Ok(SanType::IpAddress(ip)))
        .chain(
            dns_names
                .iter()
                .map(|n| n.as_str().try_into().map(SanType::DnsName)),
        )
        .collect::<Result<_, _>>()?;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.use_authority_key_identifier_extension = true;
    leaf.not_before = not_before;
    leaf.not_after = not_after;
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    // The CA key is dropped (and its memory freed) when `issuer` goes out of scope.
    let issuer = Issuer::new(ca, ca_key);
    let cert_pem = leaf.signed_by(&leaf_key, &issuer)?.pem();

    Ok(Issued {
        ca_pem,
        cert_pem,
        key_pem: leaf_key.serialize_pem(),
        not_after: not_after_time,
    })
}

/// Loads a PEM certificate chain and PKCS #8 (or SEC1 / PKCS #1) key for rustls.
///
/// # Errors
///
/// [`CertificateError`] if either is not valid PEM, the chain is empty, the key type is not
/// supported, or the key does not match the leaf. A staged renewal must not activate material
/// that can load but cannot complete a TLS handshake.
pub fn certified_key(
    chain_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<CertifiedKey>, CertificateError> {
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_pem| CertificateError::Pem("certificate chain"))?;
    if chain.is_empty() {
        return Err(CertificateError::Pem("certificate chain"));
    }
    let key =
        PrivateKeyDer::from_pem_slice(key_pem).map_err(|_pem| CertificateError::Pem("key"))?;
    let signing_key = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(CertificateError::Key)?;
    let key = CertifiedKey::new(chain, signing_key);
    key.keys_match().map_err(CertificateError::Key)?;
    Ok(Arc::new(key))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const NOW: UnixTime = UnixTime::from_secs(1_800_000_000);

    #[test]
    fn rejects_invalid_dns_names() {
        let result = issue(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &["not a name ✗".to_owned()],
            NOW,
            Duration::from_hours(1),
        );
        assert!(matches!(result, Err(CertificateError::Generate(_))));
    }

    #[test]
    fn issued_certificate_loads_for_rustls() {
        let issued = issue(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &["localhost".to_owned()],
            NOW,
            Duration::from_hours(1),
        )
        .unwrap();
        let key = certified_key(issued.cert_pem.as_bytes(), issued.key_pem.as_bytes()).unwrap();
        assert_eq!(key.cert.len(), 1);
        assert!(certified_key(b"", issued.key_pem.as_bytes()).is_err());
        assert!(certified_key(issued.cert_pem.as_bytes(), b"nope").is_err());
        let other = issue(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[],
            NOW,
            Duration::from_hours(1),
        )
        .unwrap();
        assert!(certified_key(issued.cert_pem.as_bytes(), other.key_pem.as_bytes()).is_err());
    }
}

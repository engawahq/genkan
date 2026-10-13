//! Certificate authorities trusted for outgoing TLS (upstream identity providers): the
//! system bundle, plus an optional extra PEM file for private servers.
//!
//! Genkan's image ships a CA bundle; `SSL_CERT_FILE` and `SSL_CERT_DIR` override where it is
//! looked for. No root list is compiled in: `webpki-roots` is licensed CDLA-Permissive-2.0, which
//! is not OSI-approved. Connections to kube-apiserver do not use this: they trust the service
//! account's CA only.

use std::path::Path;

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use thiserror::Error;

/// Why trust roots could not be loaded.
#[derive(Debug, Error)]
pub enum TrustError {
    /// The extra CA file cannot be read or holds no certificate.
    #[error("{0}: not a readable PEM file with at least one certificate")]
    File(String),
    /// No CA was found at all.
    #[error("no trusted certificate authorities found (set SSL_CERT_FILE or pass a CA file)")]
    Empty,
}

/// The system's CAs plus those in `extra`.
///
/// # Errors
///
/// [`TrustError`] if `extra` is unusable, or nothing at all is trusted.
pub fn roots(extra: Option<&Path>) -> Result<RootCertStore, TrustError> {
    let mut store = RootCertStore::empty();
    let system = rustls_native_certs::load_native_certs();
    for error in &system.errors {
        tracing::debug!(
            reason = "system_ca_unavailable",
            %error,
            "skipping part of the system CA bundle"
        );
    }
    let (_added, _ignored) = store.add_parsable_certificates(system.certs);
    if let Some(path) = extra {
        let unreadable = || TrustError::File(path.display().to_string());
        let pem = std::fs::read(path).map_err(|_io| unreadable())?;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<_, _>>()
            .map_err(|_pem| unreadable())?;
        if certs.is_empty() {
            return Err(unreadable());
        }
        let (added, _ignored) = store.add_parsable_certificates(certs);
        if added == 0 {
            return Err(unreadable());
        }
    }
    if store.is_empty() {
        return Err(TrustError::Empty);
    }
    Ok(store)
}

//! The in-cluster listener kube-apiserver fetches discovery and keys from.
//!
//! It serves only the internal metadata document (whose `jwks_uri` points back here) and the JWK
//! set, over TLS with the certificate from the Secret `genkanctl kube-config` writes
//! ([`genkan_k8s::internal_tls`]). The listener starts once that Secret exists and picks up a
//! renewed certificate without a restart.
//!
//! The internal document differs from the public one only in `jwks_uri`: its `issuer` stays the
//! public issuer, because kube-apiserver requires the fetched document to name its configured
//! `issuer.url` ([`genkan_k8s::kube_config`] explains the mechanism). No authorization, token or
//! sign-in endpoint is reachable here; this listener is the only one that terminates TLS itself.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use genkan_core::clock::{Clock, UnixTime};
use genkan_core::config::BaseUrl;
use genkan_k8s::internal_tls::{self, Material};
use genkan_keys::manager::PublishedKeys;
use genkan_oauth::discovery::ProviderMetadata;
use genkan_oauth::metadata::{AppState, router};
use genkan_tls::listener::{Resolver, TlsListener, server_config};
use k8s_openapi::api::core::v1::Secret;
use kube::Api;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How often the certificate Secret is re-read.
const RELOAD_INTERVAL: Duration = Duration::from_mins(1);
/// Warn this long before the certificate expires.
const EXPIRY_WARNING: Duration = Duration::from_hours(30 * 24);

/// Settings of the internal listener.
#[derive(Debug, Clone)]
pub struct InternalConfig {
    /// Address to bind.
    pub listen: SocketAddr,
    /// The public issuer (the internal document keeps it).
    pub issuer: BaseUrl,
    /// Overrides the URL recorded in the Secret.
    pub url: Option<BaseUrl>,
    /// `Cache-Control: max-age` for the documents.
    pub max_age: Duration,
}

/// Runs the internal listener until `shutdown`: polls the certificate Secret, starts serving
/// once it exists, and swaps in renewed certificates.
pub async fn run<C: Clock>(
    config: InternalConfig,
    secrets: Api<Secret>,
    keys: PublishedKeys,
    clock: C,
    mut shutdown: watch::Receiver<bool>,
) {
    let resolver = Arc::new(Resolver::default());
    let (metadata_tx, metadata_rx) = watch::channel(Bytes::new());
    let mut server: Option<JoinHandle<()>> = None;
    let mut reported_missing = false;
    let mut interval = tokio::time::interval(RELOAD_INTERVAL);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.changed() => break,
        }
        let material = match secrets.get_opt(internal_tls::SECRET).await {
            Ok(Some(secret)) => match internal_tls::parse(&secret) {
                Ok(material) => material,
                Err(error) => {
                    tracing::error!(%error, secret = internal_tls::SECRET, "internal listener: unusable certificate");
                    continue;
                }
            },
            Ok(None) => {
                if !reported_missing {
                    tracing::info!(
                        secret = internal_tls::SECRET,
                        "internal listener waits for its certificate; run `genkanctl kube-config`"
                    );
                    reported_missing = true;
                }
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, "internal listener: reading the certificate failed");
                continue;
            }
        };
        let Some(url) = config.url.clone().or_else(|| material.url.clone()) else {
            tracing::error!(
                annotation = internal_tls::URL_ANNOTATION,
                "internal listener: the certificate Secret does not say where kube-apiserver reaches it"
            );
            continue;
        };
        warn_if_expiring(&material, clock.now());
        resolver.set(Arc::clone(&material.key));
        let document = ProviderMetadata::new(&config.issuer, &url).to_bytes();
        metadata_tx.send_if_modified(|current| {
            let changed = *current != document;
            if changed {
                *current = document;
            }
            changed
        });
        if server.is_none() {
            server = start(&config, &resolver, &metadata_rx, &keys, &shutdown, &url).await;
        }
    }
    if let Some(server) = server
        && let Err(error) = server.await
    {
        tracing::error!(%error, "internal listener failed");
    }
}

fn warn_if_expiring(material: &Material, now: UnixTime) {
    if let Some(not_after) = material.not_after
        && now.saturating_add(EXPIRY_WARNING) > not_after
    {
        tracing::warn!(
            expires_in_hours = not_after.as_secs().saturating_sub(now.as_secs()) / 3600,
            "internal listener certificate expires soon; prepare overlapping trust with `genkanctl kube-config --certificate-action prepare` before activation (external issuers renew their own material)"
        );
    }
}

async fn start(
    config: &InternalConfig,
    resolver: &Arc<Resolver>,
    metadata: &watch::Receiver<Bytes>,
    keys: &PublishedKeys,
    shutdown: &watch::Receiver<bool>,
    url: &BaseUrl,
) -> Option<JoinHandle<()>> {
    let tls = match server_config(Arc::clone(resolver)) {
        Ok(tls) => tls,
        Err(error) => {
            tracing::error!(%error, "internal listener: TLS configuration");
            return None;
        }
    };
    let listener = match TcpListener::bind(config.listen).await {
        Ok(tcp) => TlsListener::new(tcp, tls),
        Err(error) => Err(error),
    };
    let listener = match listener {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, address = %config.listen, "internal listener: bind failed");
            return None;
        }
    };
    tracing::info!(address = %config.listen, %url, "internal listener serving");
    let app = router(AppState::dynamic(
        metadata.clone(),
        keys.clone(),
        config.max_age,
    ));
    let mut shutdown = shutdown.clone();
    Some(tokio::spawn(async move {
        let stopped = async move {
            drop(shutdown.wait_for(|stop| *stop).await);
        };
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(stopped)
            .await
        {
            tracing::error!(%error, "internal listener stopped");
        }
    }))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use genkan_k8s::internal_tls::{internal_url, parse, secret};
    use genkan_tls::certificate::issue;
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    use super::*;

    fn client(ca_pem: &str) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    /// The issued certificate verifies for its IP (as kube-apiserver checks it), serves the
    /// metadata over TLS, and a renewed certificate is used without restarting the listener.
    #[tokio::test]
    async fn serves_metadata_with_the_issued_certificate_and_renews_in_place() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let now = UnixTime::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        let first = issue(ip, &[], now, Duration::from_hours(1)).unwrap();
        let url = internal_url(ip).unwrap();
        let resolver = Arc::new(Resolver::default());
        resolver.set(parse(&secret("ns", &first, &url)).unwrap().key);

        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener =
            TlsListener::new(tcp, server_config(Arc::clone(&resolver)).unwrap()).unwrap();
        let address = axum::serve::Listener::local_addr(&listener).unwrap();
        let issuer = BaseUrl::parse("issuer", "https://login.example.com").unwrap();
        let metadata = ProviderMetadata::new(&issuer, &url).to_bytes();
        let (_keys_tx, keys) = watch::channel(None);
        let app = router(AppState::new(metadata, keys, Duration::from_mins(5)));
        tokio::spawn(async move { axum::serve(listener, app).await });

        let fetch = |ca: String| async move {
            let tcp = TcpStream::connect(address).await.unwrap();
            let name = ServerName::IpAddress(ip.into());
            let mut tls = client(&ca).connect(name, tcp).await?;
            tls.write_all(
                b"GET /.well-known/openid-configuration HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await?;
            let mut response = String::new();
            tls.read_to_string(&mut response).await?;
            std::io::Result::Ok(response)
        };

        let response = fetch(first.ca_pem.clone()).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains(r#""issuer":"https://login.example.com""#));
        assert!(response.contains(r#""jwks_uri":"https://127.0.0.1/jwks""#));

        // A certificate from another CA is refused by a client trusting the first.
        let second = issue(ip, &[], now, Duration::from_hours(1)).unwrap();
        resolver.set(parse(&secret("ns", &second, &url)).unwrap().key);
        assert!(fetch(first.ca_pem).await.is_err());
        assert!(
            fetch(second.ca_pem)
                .await
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
    }
}

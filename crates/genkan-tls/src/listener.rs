//! A TLS listener for axum whose certificate can be replaced while it runs.
//!
//! Handshakes run in their own tasks with a timeout, so a slow or stalled client cannot hold up
//! others. TLS 1.2 and 1.3 with the aws-lc-rs provider; HTTP/1.1 only.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{fmt, io};

use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// A TLS handshake that takes longer is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Handshakes in progress at once.
const MAX_HANDSHAKES: usize = 64;

/// Serves the current certificate; [`Resolver::set`] replaces it.
#[derive(Default)]
pub struct Resolver(RwLock<Option<Arc<CertifiedKey>>>);

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Resolver")
    }
}

impl Resolver {
    /// Replaces the certificate.
    pub fn set(&self, key: Arc<CertifiedKey>) {
        if let Ok(mut current) = self.0.write() {
            *current = Some(key);
        }
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.read().ok().and_then(|current| current.clone())
    }
}

/// TLS server configuration: TLS 1.2 and 1.3 with the aws-lc-rs provider, HTTP/1.1 only.
///
/// # Errors
///
/// Returns an error if the provider rejects the default protocol versions (it does not).
pub fn server_config(resolver: Arc<Resolver>) -> Result<Arc<ServerConfig>, rustls::Error> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A TCP listener whose connections arrive already through the TLS handshake. Handshakes run in
/// their own tasks, so a slow client cannot hold up others.
pub struct TlsListener {
    incoming: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    acceptor: JoinHandle<()>,
}

impl fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsListener")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.acceptor.abort();
    }
}

impl TlsListener {
    /// Starts accepting on `tcp`.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket has no local address.
    pub fn new(tcp: TcpListener, config: Arc<ServerConfig>) -> io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, incoming) = mpsc::channel(MAX_HANDSHAKES);
        let tls = TlsAcceptor::from(config);
        let slots = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        let acceptor = tokio::spawn(async move {
            loop {
                let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
                    return;
                };
                let (stream, peer) = match tcp.accept().await {
                    Ok(accepted) => accepted,
                    Err(_error) => {
                        tracing::warn!(
                            reason = "accept_failed",
                            "internal listener: accept failed"
                        );
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let tls = tls.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.accept(stream));
                    match handshake.await {
                        Ok(Ok(stream)) => {
                            drop(tx.send((stream, peer)).await);
                        }
                        Ok(Err(_error)) => {
                            tracing::debug!(
                                reason = "tls_handshake_failed",
                                "internal listener: TLS handshake failed"
                            );
                        }
                        Err(_elapsed) => {
                            tracing::debug!(
                                reason = "tls_handshake_timeout",
                                "internal listener: TLS handshake timed out"
                            );
                        }
                    }
                    drop(permit);
                });
            }
        });
        Ok(Self {
            incoming,
            local,
            acceptor,
        })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.incoming.recv().await {
            Some(accepted) => accepted,
            // The acceptor only stops when the listener is dropped.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_starts_empty() {
        assert!(Resolver::default().0.read().unwrap().is_none());
    }
}

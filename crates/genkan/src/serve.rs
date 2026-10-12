//! `genkan`: wires configuration, storage, keys and HTTP together.
//!
//! Startup order: signing keys are reconciled once (and the process exits if that fails), then
//! the background tasks start (key rotation, garbage collection of grants and, with invitations,
//! of invitations, the mailer, the internal listener), and only then is the public port bound.
//! With the Kubernetes store, if the API server becomes unreachable, Genkan keeps serving the
//! last published keys; logins and refreshes that need a write fail closed, and the background
//! tasks retry.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use genkan_core::clock::SystemClock;
use genkan_core::crypto::{Sealer, hash_secret};
use genkan_k8s::crd::grant::Grant;
use genkan_k8s::crd::invitation::Invitation;
use genkan_k8s::credentials::KubeCredentialStore;
use genkan_k8s::directory::KubeDirectory;
use genkan_k8s::gc;
use genkan_k8s::grants::KubeGrantStore;
use genkan_k8s::keys::SecretKeyStore;
use genkan_k8s::setup::KubeSetupStore;
use genkan_k8s::users::KubeUserAdmin;
use genkan_keys::manager::{KeyManager, ManagerError};
use genkan_keys::store::{KeyStore, MemoryKeyStore};
use genkan_mail::Mailer;
use genkan_oauth::discovery::ProviderMetadata;
use genkan_oauth::metadata::{AppState, router};
use genkan_oauth::{AuthorizationServer, OneTimeIds, endpoints};
use genkan_scim::Scim;
use genkan_signin::passkeys::Passkeys;
use genkan_signin::upstream::http::HyperClient;
use genkan_signin::upstream::provider::{Endpoints, Kind, Provider};
use genkan_signin::upstream::{self, Upstream};
use genkan_signin::{SignIn, pages};
use genkan_store::scim::{MemoryUserAdmin, UserAdmin};
use genkan_store::{
    CredentialStore, Directory, GrantStore, MemoryCredentialStore, MemoryDirectory,
    MemoryGrantStore, MemorySetupStore, SetupStore,
};
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::Api;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{MailConfig, ServeConfig, Store};
use crate::internal::{self, InternalConfig};

/// How often signing keys are reconciled. Rotation timings are hours to days, so a minute of
/// lateness is irrelevant; the interval mainly bounds how quickly a storage outage recovers.
const RECONCILE_INTERVAL: Duration = Duration::from_mins(1);

/// Maximum request body. Every request this server accepts is a small form.
const MAX_BODY: usize = 16 * 1024;
/// Maximum time to handle one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Four independent groups reserve capacity within the original 256-request budget.
const GROUP_CONCURRENT: usize = 64;

/// Why the server stopped with an error.
#[derive(Debug, Error)]
pub enum ServeError {
    /// No Kubernetes client could be configured (no in-cluster service account and no
    /// kubeconfig).
    #[error("connecting to Kubernetes: {0}")]
    Kubernetes(#[from] kube::Error),
    /// Signing keys could not be prepared at startup.
    #[error("preparing signing keys: {0}")]
    Keys(#[from] ManagerError),
    /// The process sealing key could not be created.
    #[error("creating the process sealing key failed")]
    Crypto,
    /// The configuration cannot be used (for example as a WebAuthn origin).
    #[error("configuration: {0}")]
    Config(String),
    /// Binding or serving failed.
    #[error("serving HTTP: {0}")]
    Io(#[from] io::Error),
}

/// Runs the server until SIGTERM or SIGINT.
///
/// # Errors
///
/// Returns [`ServeError`] if storage or keys cannot be prepared at startup, or the listener
/// fails.
pub async fn serve(config: ServeConfig) -> Result<(), ServeError> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    match &config.store {
        Store::Memory => {
            tracing::warn!(
                "store=memory: keys, clients, users and grants live in process memory and start \
                 empty; use only for development"
            );
            let stores = (
                MemoryKeyStore::default(),
                MemoryDirectory::default(),
                MemoryGrantStore::default(),
                MemoryCredentialStore::default(),
                MemorySetupStore::default(),
            );
            let scim = scim_router(&config, MemoryUserAdmin::default())?;
            run(&config, stores, Vec::new(), None, scim, shutdown_tx).await
        }
        Store::Kubernetes {
            namespace,
            key_secret,
        } => {
            let client = Client::try_default().await?;
            let namespace = namespace
                .clone()
                .unwrap_or_else(|| client.default_namespace().to_owned());
            tracing::info!(%namespace, %key_secret, "using Kubernetes storage");
            let keys = SecretKeyStore::new(
                Api::namespaced(client.clone(), &namespace),
                key_secret.clone(),
            );
            let directory = KubeDirectory::new(
                Api::namespaced(client.clone(), &namespace),
                Api::namespaced(client.clone(), &namespace),
            );
            let grants = KubeGrantStore::new(Api::namespaced(client.clone(), &namespace));
            let credentials = KubeCredentialStore::new(Api::namespaced(client.clone(), &namespace));
            let mut setup = KubeSetupStore::new(Api::namespaced(client.clone(), &namespace));
            let mut background = Vec::new();
            if config.invitations {
                setup = setup.with_invitations(Api::namespaced(client.clone(), &namespace));
                background.push(tokio::spawn({
                    let (client, namespace, shutdown) =
                        (client.clone(), namespace.clone(), shutdown_rx.clone());
                    async move {
                        gc::run::<Invitation, _>(client, &namespace, SystemClock, shutdown).await;
                    }
                }));
                if let Some(mail) = &config.mail {
                    let mailer = mailer(mail)?;
                    tracing::info!(?mailer, "mailing invitation links");
                    background.push(tokio::spawn(crate::mailer::run_mailer(
                        Api::namespaced(client.clone(), &namespace),
                        mailer,
                        config.issuer.clone(),
                        SystemClock,
                        shutdown_rx.clone(),
                    )));
                }
            }
            let internal_secrets = Api::namespaced(client.clone(), &namespace);
            let scim = scim_router(
                &config,
                KubeUserAdmin::new(Api::namespaced(client.clone(), &namespace)),
            )?;
            let gc = tokio::spawn({
                let shutdown = shutdown_rx.clone();
                async move { gc::run::<Grant, _>(client, &namespace, SystemClock, shutdown).await }
            });
            run(
                &config,
                (keys, directory, grants, credentials, setup),
                background.into_iter().chain([gc]).collect(),
                Some(internal_secrets),
                scim,
                shutdown_tx,
            )
            .await
        }
    }
}

/// The SCIM routes, if SCIM is enabled: reads the token file and keeps only its hash.
fn scim_router<A: UserAdmin>(
    config: &ServeConfig,
    users: A,
) -> Result<Option<axum::Router>, ServeError> {
    let Some(scim) = &config.scim else {
        return Ok(None);
    };
    let token = std::fs::read_to_string(&scim.token_file)
        .map_err(|error| ServeError::Config(format!("{}: {error}", scim.token_file.display())))?;
    let token = token.trim();
    if token.len() < 32 {
        return Err(ServeError::Config(
            "the SCIM token must be at least 32 characters".to_owned(),
        ));
    }
    tracing::info!(groups = ?scim.groups, "SCIM provisioning enabled");
    Ok(Some(genkan_scim::router(Arc::new(Scim {
        users,
        token_hash: hash_secret(token.as_bytes()),
        groups: scim.groups.clone(),
        base: config.issuer.join(genkan_scim::BASE_PATH),
    }))))
}

/// The configured upstream providers, with their client secrets read from files.
fn upstream_providers(config: &ServeConfig) -> Result<Vec<Provider>, ServeError> {
    config
        .upstream
        .iter()
        .map(|upstream| {
            let secret = std::fs::read_to_string(&upstream.client_secret_file)
                .map_err(|error| {
                    ServeError::Config(format!(
                        "{}: {error}",
                        upstream.client_secret_file.display()
                    ))
                })?
                .trim()
                .to_owned();
            let endpoints = match upstream.kind {
                Kind::GitHub => Endpoints::github(),
                Kind::Google => Endpoints::google(),
            };
            Ok(Provider::new(
                upstream.kind,
                upstream.client_id.clone(),
                secret,
                endpoints,
            ))
        })
        .collect()
}

/// Builds the mailer: reads the password file and the trusted CAs.
fn mailer(config: &MailConfig) -> Result<Mailer, ServeError> {
    let password = config
        .password_file
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path)
                .map(|p| p.trim_end_matches(['\r', '\n']).to_owned())
                .map_err(|error| ServeError::Config(format!("{}: {error}", path.display())))
        })
        .transpose()?;
    let roots = genkan_tls::trust::roots(config.ca_file.as_deref())
        .map_err(|error| ServeError::Config(error.to_string()))?;
    Mailer::new(&config.url, password, &config.from, roots)
        .map_err(|error| ServeError::Config(error.to_string()))
}

/// One group's admission budget and process-lifetime rejection counter.
struct RequestGroup {
    name: &'static str,
    slots: tokio::sync::Semaphore,
    rejected: AtomicU64,
}

impl RequestGroup {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            slots: tokio::sync::Semaphore::new(GROUP_CONCURRENT),
            rejected: AtomicU64::new(0),
        }
    }
}

/// Independent budgets prevent authorization traffic from exhausting token or sign-in capacity.
struct RequestLimits {
    authorization: RequestGroup,
    tokens: RequestGroup,
    signin: RequestGroup,
    other: RequestGroup,
}

impl RequestLimits {
    fn new() -> Self {
        Self {
            authorization: RequestGroup::new("authorization"),
            tokens: RequestGroup::new("tokens"),
            signin: RequestGroup::new("signin"),
            other: RequestGroup::new("other"),
        }
    }

    fn group(&self, path: &str) -> &RequestGroup {
        match path {
            "/authorize" | "/par" => &self.authorization,
            "/token" | "/revoke" => &self.tokens,
            path if path == "/login"
                || path.starts_with("/login/")
                || path == "/setup"
                || path.starts_with("/setup/")
                || path.starts_with("/upstream/") =>
            {
                &self.signin
            }
            _ => &self.other,
        }
    }
}

/// Rejects overload before reading a body, with no queue outside the handler timeout.
///
/// A borrowed permit is held until the handler completes, and released on cancellation or
/// timeout. Responses are small, non-streaming forms/JSON/pages. Overload uses `503` and a
/// one-second retry suggestion ([RFC 9110 §15.6.4 and §10.2.3]).
///
/// [RFC 9110 §15.6.4 and §10.2.3]: https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.4
async fn admit(
    axum::extract::State(limits): axum::extract::State<Arc<RequestLimits>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse as _;

    let group = limits.group(request.uri().path());
    let Ok(_permit) = group.slots.try_acquire() else {
        let rejected_total = group.rejected.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(
            event = "request_overload",
            group = group.name,
            rejected_total,
            "request rejected for load"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (header::RETRY_AFTER, "1"),
                (header::CACHE_CONTROL, "no-store"),
            ],
        )
            .into_response();
    };
    next.run(request).await
}

/// Body and time limits are universal; concurrency admission reserves per-group capacity.
fn limits(router: axum::Router) -> axum::Router {
    router
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(RequestLimits::new()),
            admit,
        ))
}

async fn run<S: KeyStore, D: Directory, G: GrantStore, K: CredentialStore, T: SetupStore>(
    config: &ServeConfig,
    (keys, directory, grants, credentials, setup): (S, D, G, K, T),
    mut background: Vec<JoinHandle<()>>,
    internal_secrets: Option<Api<Secret>>,
    scim: Option<axum::Router>,
    shutdown_tx: watch::Sender<bool>,
) -> Result<(), ServeError> {
    let manager = Arc::new(KeyManager::new(keys, SystemClock, config.rotation));
    // Refuse to start without keys rather than serve an empty JWK set.
    manager.reconcile().await?;

    let rotator = tokio::spawn({
        let manager = Arc::clone(&manager);
        let shutdown = shutdown_tx.subscribe();
        async move { manager.run(RECONCILE_INTERVAL, shutdown).await }
    });

    if let Some(secrets) = internal_secrets {
        let internal = InternalConfig {
            listen: config.internal_listen,
            issuer: config.issuer.clone(),
            url: config.internal_url.clone(),
            max_age: config.metadata_max_age,
        };
        background.push(tokio::spawn(internal::run(
            internal,
            secrets,
            manager.subscribe(),
            SystemClock,
            shutdown_tx.subscribe(),
        )));
    }

    let mut metadata = ProviderMetadata::new(&config.issuer, &config.issuer);
    if config.lifetimes.elevated_token.is_some() {
        metadata = metadata.with_elevation();
    }
    let metadata = metadata.to_bytes();
    let server = Arc::new(AuthorizationServer {
        issuer: config.issuer.clone(),
        lifetimes: config.lifetimes,
        directory,
        grants,
        clock: SystemClock,
        keys: manager.subscribe(),
        sealer: Sealer::ephemeral().map_err(|_crypto| ServeError::Crypto)?,
        used_codes: OneTimeIds::default(),
        used_request_uris: OneTimeIds::default(),
    });
    let sign_in = Arc::new(SignIn {
        oauth: Arc::clone(&server),
        passkeys: Passkeys::new(&config.issuer)
            .map_err(|error| ServeError::Config(error.to_string()))?,
        credentials,
        setup,
        used_ceremonies: OneTimeIds::default(),
    });
    let providers = upstream_providers(config)?;
    let kinds: Vec<Kind> = providers.iter().map(Provider::kind).collect();
    let mut app = router(AppState::new(
        metadata,
        manager.subscribe(),
        config.metadata_max_age,
    ))
    .merge(endpoints::router(Arc::clone(&server)))
    .merge(genkan_signin::router(Arc::clone(&sign_in)))
    .merge(pages::router(Arc::clone(&server), &kinds));
    if !providers.is_empty() {
        let roots = genkan_tls::trust::roots(config.upstream_ca_file.as_deref())
            .map_err(|error| ServeError::Config(error.to_string()))?;
        let http =
            HyperClient::new(roots).map_err(|error| ServeError::Config(error.to_string()))?;
        tracing::info!(providers = ?kinds, "upstream sign-in enabled");
        app = app.merge(upstream::router(Arc::new(Upstream {
            sign_in,
            providers,
            http,
            used_states: OneTimeIds::default(),
        })));
    }
    if let Some(scim) = scim {
        app = app.merge(scim);
    }
    let app = limits(app);
    let listener = TcpListener::bind(config.listen).await?;
    tracing::info!(address = %listener.local_addr()?, issuer = %config.issuer, "listening");

    let outcome = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    shutdown_tx.send_replace(true);
    for task in background.into_iter().chain([rotator]) {
        if let Err(error) = task.await {
            tracing::error!(%error, "background task failed");
        }
    }
    tracing::info!("stopped");
    Ok(outcome?)
}

async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "cannot listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tokio::sync::Semaphore;
    use tower::ServiceExt as _;

    use super::*;

    fn request(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn overloaded_authorization_does_not_block_token_or_signin() {
        let entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let app = limits(
            axum::Router::new()
                .route(
                    "/authorize",
                    get({
                        let entered = Arc::clone(&entered);
                        let release = Arc::clone(&release);
                        move || {
                            let entered = Arc::clone(&entered);
                            let release = Arc::clone(&release);
                            async move {
                                entered.add_permits(1);
                                release.acquire().await.unwrap().forget();
                                StatusCode::OK
                            }
                        }
                    }),
                )
                .route("/par", get(|| async { StatusCode::OK }))
                .route("/token", get(|| async { StatusCode::OK }))
                .route("/login/options", get(|| async { StatusCode::OK })),
        );
        let mut tasks = Vec::new();
        for _ in 0..64 {
            tasks.push(tokio::spawn(app.clone().oneshot(request("/authorize"))));
        }
        entered.acquire_many(64).await.unwrap().forget();
        let rejected =
            tokio::time::timeout(Duration::from_secs(1), app.clone().oneshot(request("/par")))
                .await
                .expect("overload must not queue")
                .unwrap();
        assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejected.headers()[header::RETRY_AFTER], "1");
        for path in ["/token", "/login/options"] {
            let response =
                tokio::time::timeout(Duration::from_secs(1), app.clone().oneshot(request(path)))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        release.add_permits(64);
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap().status(), StatusCode::OK);
        }
        assert_eq!(
            app.oneshot(request("/par")).await.unwrap().status(),
            StatusCode::OK
        );
    }
}

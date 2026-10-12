//! [`Directory`] backed by `User` and `OAuthClient` objects.
//!
//! Users and known clients are read by name on every request, so disabling a user or changing
//! a client takes effect immediately. Only absent clients are cached: five seconds of monotonic
//! time, at most 1024 names, shared by clones. This limits repeated unknown-client API reads
//! without retaining stale authorization data; a newly created client can take five seconds to
//! appear. Backend errors are never cached.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use genkan_keys::Algorithm;
use genkan_store::{Client, Directory, StoreError, User};
use kube::ResourceExt as _;
use kube::api::Api;
use tokio::sync::Mutex;

use crate::crd::client::OAuthClient;
use crate::crd::user::User as UserObject;

/// Reads clients and users from the API server.
#[derive(Clone)]
pub struct KubeDirectory {
    clients: Api<OAuthClient>,
    users: Api<UserObject>,
    missing_clients: Arc<Mutex<NegativeClients>>,
}

impl std::fmt::Debug for KubeDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KubeDirectory")
    }
}

impl KubeDirectory {
    /// Uses the given (namespaced) APIs and a bounded, shared negative client cache.
    #[must_use]
    pub fn new(clients: Api<OAuthClient>, users: Api<UserObject>) -> Self {
        Self {
            clients,
            users,
            missing_clients: Arc::new(Mutex::new(NegativeClients::default())),
        }
    }

    /// The clock seam keeps expiry tests deterministic without changing the runtime clock.
    async fn client_at(
        &self,
        id: &str,
        now: impl Fn() -> Instant + Send,
    ) -> Result<Option<Client>, StoreError> {
        {
            let mut missing = self.missing_clients.lock().await;
            if missing.contains(id, now()) {
                return Ok(None);
            }
        }
        let started = Instant::now();
        let result = self.clients.get_opt(id).await;
        record_lookup("client", started.elapsed(), &result);
        let object = result.map_err(|e| backend(&e))?;
        if object.is_none() {
            self.missing_clients.lock().await.insert(id, now());
        }
        Ok(object.map(|object| {
            let id = object.name_any();
            let spec = object.spec;
            Client {
                id,
                display_name: spec.display_name,
                kind: spec.kind,
                redirect_uris: spec.redirect_uris,
                audiences: spec.audiences,
                secret_hash: spec.secret_hash,
                id_token_alg: spec.id_token_signing_alg.unwrap_or(Algorithm::Es256),
            }
        }))
    }
}

const NEGATIVE_TTL: Duration = Duration::from_secs(5);
const NEGATIVE_CAPACITY: usize = 1024;

/// Insertion order is also expiry order. Hits never extend a miss's lifetime, and duplicate
/// concurrent misses never add another queue entry. Different names may still read concurrently.
#[derive(Default)]
struct NegativeClients {
    entries: HashMap<Arc<str>, Instant>,
    oldest: VecDeque<Arc<str>>,
}

impl NegativeClients {
    fn expire(&mut self, now: Instant) {
        while self.oldest.front().is_some_and(|id| {
            self.entries
                .get(id)
                .is_some_and(|inserted| now.duration_since(*inserted) >= NEGATIVE_TTL)
        }) {
            if let Some(id) = self.oldest.pop_front() {
                self.entries.remove(&id);
            }
        }
    }

    fn contains(&mut self, id: &str, now: Instant) -> bool {
        self.expire(now);
        self.entries.contains_key(id)
    }

    fn insert(&mut self, id: &str, now: Instant) {
        self.expire(now);
        if self.entries.contains_key(id) {
            return;
        }
        if self.entries.len() == NEGATIVE_CAPACITY
            && let Some(id) = self.oldest.pop_front()
        {
            self.entries.remove(&id);
        }
        let id: Arc<str> = Arc::from(id);
        self.oldest.push_back(Arc::clone(&id));
        self.entries.insert(id, now);
    }
}

/// Only bounded resource and outcome labels are logged; object names and errors may carry PII.
fn record_lookup<T>(
    resource: &'static str,
    elapsed: Duration,
    result: &Result<Option<T>, kube::Error>,
) {
    let outcome = match result {
        Ok(Some(_)) => "found",
        Ok(None) => "not_found",
        Err(_) => "error",
    };
    tracing::info!(
        event = "kubernetes_directory_lookup",
        resource,
        operation = "get",
        outcome,
        latency_ms = elapsed.as_secs_f64() * 1000.0,
        "Kubernetes directory API lookup"
    );
}

fn backend(error: &kube::Error) -> StoreError {
    StoreError(error.to_string())
}

impl Directory for KubeDirectory {
    fn client(&self, id: &str) -> impl Future<Output = Result<Option<Client>, StoreError>> + Send {
        self.client_at(id, Instant::now)
    }

    async fn user(&self, name: &str) -> Result<Option<User>, StoreError> {
        let started = Instant::now();
        let result = self.users.get_opt(name).await;
        record_lookup("user", started.elapsed(), &result);
        Ok(result.map_err(|e| backend(&e))?.and_then(convert))
    }
}

/// An object without a UID was never stored; it is treated as absent.
fn convert(object: UserObject) -> Option<User> {
    let subject = object.uid()?;
    Some(User {
        name: object.name_any(),
        subject,
        username: object.spec.username,
        display_name: object.spec.display_name,
        groups: object.spec.groups,
        disabled: object.spec.disabled,
        elevated_groups: object.spec.elevated_groups,
    })
}

#[cfg(test)]
#[path = "directory_cache_tests.rs"]
mod tests;

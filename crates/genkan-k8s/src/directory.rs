//! [`Directory`] backed by `User` and `OAuthClient` objects.
//!
//! Metadata-only watches index client names and user UIDs; arbitrary unknown identifiers never
//! cause per-request API reads. The initial snapshots must complete before any lookup. Relists
//! replace each index atomically, and watch errors retry with backoff without falling back to
//! per-identifier reads.
//!
//! An index is only a locator, never authorization data: known clients and users are read directly
//! on every request. Watch lag may temporarily deny a new object, but cannot retain a revoked
//! permission or client secret. Subject lookups also compare the fetched UID, because Kubernetes
//! permits a deleted object's name to be reused but assigns every new object a distinct [UID].
//! Ambiguous subjects fail closed.
//!
//! [UID]: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids

use std::fmt::Debug;
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use genkan_keys::Algorithm;
use genkan_store::{Client, Directory, StoreError, User};
use kube::api::Api;
use kube::core::{NamespaceResourceScope, PartialObjectMeta};
use kube::runtime::WatchStreamExt as _;
use kube::runtime::reflector::Store;
use kube::runtime::reflector::store::Writer;
use kube::runtime::watcher::{self, watcher};
use kube::{Resource, ResourceExt as _};
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::crd::client::OAuthClient;
use crate::crd::user::User as UserObject;

/// Locates clients and user subjects through metadata, then reads current API objects.
#[derive(Clone)]
pub struct KubeDirectory {
    clients: Api<OAuthClient>,
    users: Api<UserObject>,
    client_index: Store<PartialObjectMeta<OAuthClient>>,
    user_index: Store<PartialObjectMeta<UserObject>>,
}

impl Debug for KubeDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KubeDirectory")
    }
}

impl KubeDirectory {
    /// Starts metadata-only watches in the same namespaces as the supplied APIs.
    ///
    /// Keep the returned task alive until shutdown and call [`Self::wait_until_ready`] before
    /// serving requests. Aborting the task before its initial snapshots makes readiness fail.
    #[must_use]
    pub fn new(
        clients: Api<OAuthClient>,
        users: Api<UserObject>,
        shutdown: watch::Receiver<bool>,
    ) -> (Self, JoinHandle<()>) {
        let client_writer = Writer::default();
        let user_writer = Writer::default();
        let directory = Self {
            client_index: client_writer.as_reader(),
            user_index: user_writer.as_reader(),
            clients,
            users,
        };
        let client_metadata = metadata_api(&directory.clients);
        let user_metadata = metadata_api(&directory.users);
        let task = tokio::spawn(async move {
            tokio::join!(
                run_index(client_metadata, client_writer, shutdown.clone(), "client"),
                run_index(user_metadata, user_writer, shutdown, "user"),
            );
        });
        (directory, task)
    }

    /// Waits for both metadata indexes to contain their complete initial snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error if either watch task stops before its initial snapshot completes.
    /// The caller must bound startup waiting when the API server remains unavailable.
    pub async fn wait_until_ready(&self) -> Result<(), StoreError> {
        tokio::try_join!(
            self.client_index.wait_until_ready(),
            self.user_index.wait_until_ready(),
        )
        .map(|_| ())
        .map_err(|error| {
            StoreError(format!(
                "directory metadata index did not initialize: {error}"
            ))
        })
    }

    async fn read_user(&self, name: &str) -> Result<Option<User>, StoreError> {
        let started = Instant::now();
        let result = self.users.get_opt(name).await;
        record_lookup("user", started.elapsed(), &result);
        Ok(result.map_err(|e| backend(&e))?.and_then(convert))
    }
}

fn metadata_api<K>(api: &Api<K>) -> Api<PartialObjectMeta<K>>
where
    K: Resource<Scope = NamespaceResourceScope, DynamicType = ()> + Clone,
{
    let client = api.clone().into_client();
    match api.namespace() {
        Some(namespace) => Api::namespaced(client, namespace),
        None => Api::all(client),
    }
}

/// Each writer publishes relists only on `InitDone`, preserving the last complete snapshot.
async fn run_index<K>(
    api: Api<PartialObjectMeta<K>>,
    mut writer: Writer<PartialObjectMeta<K>>,
    mut shutdown: watch::Receiver<bool>,
    resource: &'static str,
) where
    K: Resource<Scope = NamespaceResourceScope, DynamicType = ()>
        + Clone
        + DeserializeOwned
        + Debug
        + Send
        + Sync
        + 'static,
{
    let mut events = watcher(api, watcher::Config::default())
        .default_backoff()
        .boxed();
    while !*shutdown.borrow() {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            event = events.next() => match event {
                Some(Ok(event)) => writer.apply_watcher_event(&event),
                Some(Err(error)) => {
                    tracing::warn!(
                        event = "kubernetes_directory_watch",
                        resource,
                        outcome = "error",
                        %error,
                        "directory metadata watch error; retrying with backoff"
                    );
                }
                None => {
                    tracing::warn!(
                        event = "kubernetes_directory_watch",
                        resource,
                        outcome = "stopped",
                        "directory metadata watch stopped"
                    );
                    break;
                }
            },
        }
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
    async fn client(&self, id: &str) -> Result<Option<Client>, StoreError> {
        self.wait_until_ready().await?;
        if self
            .client_index
            .find(|object| object.metadata.name.as_deref() == Some(id))
            .is_none()
        {
            return Ok(None);
        }
        let started = Instant::now();
        let result = self.clients.get_opt(id).await;
        record_lookup("client", started.elapsed(), &result);
        Ok(result.map_err(|e| backend(&e))?.map(|object| {
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

    async fn user(&self, name: &str) -> Result<Option<User>, StoreError> {
        self.wait_until_ready().await?;
        self.read_user(name).await
    }

    async fn user_by_subject(&self, subject: &str) -> Result<Option<User>, StoreError> {
        self.wait_until_ready().await?;
        // Filter under one store read lock so an ambiguous snapshot never picks an arbitrary user.
        // Only matching metadata is cloned, not a full snapshot of every user.
        let matches = self
            .user_index
            .state_filter(|object| object.metadata.uid.as_deref() == Some(subject));
        let [metadata] = matches.as_slice() else {
            return Ok(None);
        };
        let Some(name) = metadata.metadata.name.as_deref() else {
            return Ok(None);
        };
        Ok(self
            .read_user(name)
            .await?
            .filter(|user| user.subject == subject))
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
#[path = "directory_watch_tests.rs"]
mod tests;

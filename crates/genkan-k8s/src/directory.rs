//! [`Directory`] backed by `User` and `OAuthClient` objects, served from watch-fed caches.
//!
//! Two reflectors ([kube-runtime `reflector`]) keep every `OAuthClient` and `User` of the
//! namespace in memory, and lookups read only that memory: no request reaches the API server.
//! This is the informer and lister pattern Kubernetes controllers use for objects they read far
//! more often than they change.
//!
//! - **Unknown clients cost nothing.** A `client_id` that names no object is a map miss, so
//!   unauthenticated traffic to `/authorize`, `/par`, `/token` and `/revoke` puts no load on the
//!   API server, whatever IDs it carries ([#10]). [Pinniped] reads its `OIDCClient`s with one
//!   GET per request and screens out only IDs that lack its required prefix; a cache needs no
//!   such screen.
//! - **Changes apply with the watch event, not after a TTL.** Disabling a user or editing a
//!   client reaches the cache as soon as the API server delivers the event. The alternative
//!   considered in [#10], a short negative cache in front of per-request GETs, still costs one
//!   GET per distinct unknown ID and keeps a newly created client invisible for the TTL.
//! - **Lookups by subject scan memory.** UserInfo used to LIST every user per call.
//! - **Fails closed until synchronised.** Until both caches have completed their first list, every
//!   lookup is an error. `genkan serve` waits for that before it binds the public port, so the
//!   readiness probe stays unready until then.
//! - **Stale while the watch is down.** The cache keeps its last contents while the watch
//!   reconnects with backoff; kube-runtime documents that a store "may be stale". A user disabled
//!   during an API outage keeps passing lookups until the watch resumes, but no token is issued
//!   meanwhile: redeeming a code and refreshing both write a grant, and those writes fail closed
//!   while the API server is unreachable. UserInfo can still answer from the stale entry, as it
//!   answers for any unexpired access token.
//! - **Memory.** Every object of both kinds is held, with `managedFields` dropped. Users carry no
//!   secrets; clients carry only `secret_hash`. At the expected scale (tens to hundreds of
//!   objects) this is kilobytes. The Role already grants `list` and `watch` on both kinds.
//!
//! # References
//!
//! - [kube-runtime `reflector`] kube-rs project, `kube-runtime` 4.2.0, `src/reflector/store.rs`
//!   (`Store::get`, `Store::wait_until_ready`).
//! - [Pinniped] Pinniped project, `internal/federationdomain/clientregistry/clientregistry.go`,
//!   `ClientManager::GetClient`, branch `main` as read on 2026-10-13.
//!
//! [kube-runtime `reflector`]: https://docs.rs/kube-runtime/4.2.0/kube_runtime/reflector/index.html
//! [Pinniped]: https://github.com/vmware-tanzu/pinniped/blob/main/internal/federationdomain/clientregistry/clientregistry.go
//! [#10]: https://github.com/engawahq/genkan/issues/10

use std::future::{self, Future};
use std::hash::Hash;

use futures_util::{FutureExt as _, StreamExt as _, stream};
use genkan_keys::Algorithm;
use genkan_store::{Client, Directory, StoreError, User, unique_user};
use kube::ResourceExt as _;
use kube::api::Api;
use kube::runtime::WatchStreamExt as _;
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::watcher::{self, watcher};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::crd::client::OAuthClient;
use crate::crd::user::User as UserObject;

/// Reads clients and users from in-memory caches kept current by watches.
#[derive(Clone)]
pub struct KubeDirectory {
    namespace: String,
    clients: Store<OAuthClient>,
    users: Store<UserObject>,
}

impl std::fmt::Debug for KubeDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeDirectory")
            .field("namespace", &self.namespace)
            .field("clients", &self.clients.len())
            .field("users", &self.users.len())
            .finish()
    }
}

impl KubeDirectory {
    /// Starts watching `OAuthClient`s and `User`s in `namespace`.
    ///
    /// The returned task runs both watches until `shutdown` changes, retrying errors with
    /// kube-runtime's default backoff. Lookups fail until [`Self::wait_until_ready`] would
    /// return.
    #[must_use]
    pub fn watch(
        client: &kube::Client,
        namespace: &str,
        mut shutdown: watch::Receiver<bool>,
    ) -> (Self, JoinHandle<()>) {
        let (clients, client_writer) = reflector::store();
        let (users, user_writer) = reflector::store();
        let config = watcher::Config::default();
        let client_events = watcher(
            Api::<OAuthClient>::namespaced(client.clone(), namespace),
            config.clone(),
        )
        .default_backoff()
        .modify(|object| object.managed_fields_mut().clear())
        .reflect(client_writer)
        .map(|event| log_error("OAuthClient", event))
        .boxed();
        let user_events = watcher(
            Api::<UserObject>::namespaced(client.clone(), namespace),
            config,
        )
        .default_backoff()
        .modify(|object| object.managed_fields_mut().clear())
        .reflect(user_writer)
        .map(|event| log_error("User", event))
        .boxed();
        let mut events = stream::select(client_events, user_events);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = events.next() => if event.is_none() {
                        break;
                    },
                    _ = shutdown.changed() => break,
                }
            }
            tracing::info!("directory watches stopped");
        });
        let directory = Self {
            namespace: namespace.to_owned(),
            clients,
            users,
        };
        (directory, task)
    }

    /// Waits until both caches have completed their first list.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if a watch stopped before that.
    pub async fn wait_until_ready(&self) -> Result<(), StoreError> {
        self.clients
            .wait_until_ready()
            .await
            .map_err(|error| StoreError(error.to_string()))?;
        self.users
            .wait_until_ready()
            .await
            .map_err(|error| StoreError(error.to_string()))
    }
}

/// Logs a watch error; the stream retries it with backoff.
fn log_error<T>(kind: &'static str, event: Result<T, watcher::Error>) {
    if let Err(error) = event {
        tracing::warn!(kind, %error, "directory watch error; retrying with backoff");
    }
}

/// An error unless `store` has completed its first list. Lookups never wait: a request that
/// arrives early fails closed instead of queueing behind the watch.
fn synced<K>(store: &Store<K>) -> Result<(), StoreError>
where
    K: reflector::Lookup + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone,
{
    match store.wait_until_ready().now_or_never() {
        Some(Ok(())) => Ok(()),
        Some(Err(_)) | None => Err(StoreError(
            "the directory cache has not completed its first list".to_owned(),
        )),
    }
}

impl Directory for KubeDirectory {
    fn client(&self, id: &str) -> impl Future<Output = Result<Option<Client>, StoreError>> + Send {
        let result = synced(&self.clients).map(|()| {
            self.clients
                .get(&ObjectRef::new(id).within(&self.namespace))
                .map(|object| convert_client(&object))
        });
        future::ready(result)
    }

    fn user(&self, name: &str) -> impl Future<Output = Result<Option<User>, StoreError>> + Send {
        let result = synced(&self.users).map(|()| {
            self.users
                .get(&ObjectRef::new(name).within(&self.namespace))
                .and_then(|object| convert_user(&object))
        });
        future::ready(result)
    }

    fn user_by_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Option<User>, StoreError>> + Send {
        let result = synced(&self.users).and_then(|()| {
            let users: Vec<User> = self
                .users
                .state()
                .iter()
                .filter_map(|object| convert_user(object))
                .collect();
            unique_user(&users, |u| u.subject == subject)
        });
        future::ready(result)
    }
}

fn convert_client(object: &OAuthClient) -> Client {
    let spec = &object.spec;
    Client {
        id: object.name_any(),
        display_name: spec.display_name.clone(),
        kind: spec.kind,
        redirect_uris: spec.redirect_uris.clone(),
        audiences: spec.audiences.clone(),
        secret_hash: spec.secret_hash.clone(),
        id_token_alg: spec.id_token_signing_alg.unwrap_or(Algorithm::Es256),
    }
}

/// An object without a UID was never stored; it is treated as absent.
fn convert_user(object: &UserObject) -> Option<User> {
    let subject = object.uid()?;
    let spec = &object.spec;
    Some(User {
        name: object.name_any(),
        subject,
        username: spec.username.clone(),
        display_name: spec.display_name.clone(),
        groups: spec.groups.clone(),
        disabled: spec.disabled,
        elevated_groups: spec.elevated_groups.clone(),
    })
}

#[cfg(test)]
mod tests {
    use genkan_store::ClientType;
    use kube::api::ObjectMeta;
    use kube::runtime::reflector::store::Writer;
    use kube::runtime::watcher::Event;

    use super::*;
    use crate::crd::client::OAuthClientSpec;
    use crate::crd::user::UserSpec;

    const NS: &str = "genkan-system";

    fn meta(name: &str) -> ObjectMeta {
        ObjectMeta {
            name: Some(name.to_owned()),
            namespace: Some(NS.to_owned()),
            uid: Some(format!("uid-{name}")),
            ..ObjectMeta::default()
        }
    }

    fn oauth_client(name: &str, redirect: &str) -> OAuthClient {
        OAuthClient {
            metadata: meta(name),
            spec: OAuthClientSpec {
                display_name: None,
                kind: ClientType::Public,
                redirect_uris: vec![redirect.to_owned()],
                audiences: vec!["kubernetes".to_owned()],
                secret_hash: None,
                id_token_signing_alg: None,
            },
        }
    }

    fn user(name: &str, disabled: bool) -> UserObject {
        UserObject {
            metadata: meta(name),
            spec: UserSpec {
                username: name.to_owned(),
                disabled,
                ..UserSpec::default()
            },
        }
    }

    /// A directory over hand-fed stores, and their writers. No API server is involved, so a
    /// lookup that tried to reach one could not succeed.
    fn directory() -> (KubeDirectory, Writer<OAuthClient>, Writer<UserObject>) {
        let (clients, client_writer) = reflector::store();
        let (users, user_writer) = reflector::store();
        let directory = KubeDirectory {
            namespace: NS.to_owned(),
            clients,
            users,
        };
        (directory, client_writer, user_writer)
    }

    /// Feeds a complete initial list, which marks the store ready.
    fn initial<K>(writer: &mut Writer<K>, objects: Vec<K>)
    where
        K: reflector::Lookup + Clone + 'static,
        K::DynamicType: Eq + Hash + Clone,
    {
        writer.apply_watcher_event(&Event::Init);
        for object in objects {
            writer.apply_watcher_event(&Event::InitApply(object));
        }
        writer.apply_watcher_event(&Event::InitDone);
    }

    #[tokio::test]
    async fn lookups_fail_closed_until_the_first_list_completes() {
        let (directory, mut clients, mut users) = directory();
        assert!(directory.client("kubectl").await.is_err());
        assert!(directory.user("alice").await.is_err());
        assert!(directory.user_by_subject("uid-alice").await.is_err());

        initial(
            &mut clients,
            vec![oauth_client("kubectl", "http://127.0.0.1/")],
        );
        initial(&mut users, vec![user("alice", false)]);
        directory.wait_until_ready().await.unwrap();
        assert_eq!(
            directory.client("kubectl").await.unwrap().unwrap().id,
            "kubectl"
        );
        assert_eq!(
            directory.user("alice").await.unwrap().unwrap().name,
            "alice"
        );
    }

    #[tokio::test]
    async fn unknown_client_is_a_miss_not_an_error() {
        let (directory, mut clients, mut users) = directory();
        initial(
            &mut clients,
            vec![oauth_client("kubectl", "http://127.0.0.1/")],
        );
        initial(&mut users, Vec::new());
        for id in ["", "nope", "a/b", &"x".repeat(10_000)] {
            assert_eq!(directory.client(id).await, Ok(None));
        }
    }

    #[tokio::test]
    async fn watch_events_apply_immediately() {
        let (directory, mut clients, mut users) = directory();
        initial(&mut clients, Vec::new());
        initial(&mut users, vec![user("alice", false)]);

        // A client created after startup is visible as soon as its event arrives.
        assert_eq!(directory.client("new").await, Ok(None));
        clients.apply_watcher_event(&Event::Apply(oauth_client("new", "http://127.0.0.1/a")));
        assert_eq!(
            directory
                .client("new")
                .await
                .unwrap()
                .unwrap()
                .redirect_uris,
            ["http://127.0.0.1/a"]
        );

        // An edit replaces the cached client.
        clients.apply_watcher_event(&Event::Apply(oauth_client("new", "http://127.0.0.1/b")));
        assert_eq!(
            directory
                .client("new")
                .await
                .unwrap()
                .unwrap()
                .redirect_uris,
            ["http://127.0.0.1/b"]
        );

        // Disabling a user takes effect on the next lookup.
        users.apply_watcher_event(&Event::Apply(user("alice", true)));
        assert!(directory.user("alice").await.unwrap().unwrap().disabled);

        // Deletions remove the entry.
        clients.apply_watcher_event(&Event::Delete(oauth_client("new", "http://127.0.0.1/b")));
        users.apply_watcher_event(&Event::Delete(user("alice", true)));
        assert_eq!(directory.client("new").await, Ok(None));
        assert_eq!(directory.user("alice").await, Ok(None));
    }

    #[tokio::test]
    async fn objects_in_other_namespaces_are_not_found() {
        let (directory, mut clients, mut users) = directory();
        let mut foreign = oauth_client("kubectl", "http://127.0.0.1/");
        foreign.metadata.namespace = Some("elsewhere".to_owned());
        initial(&mut clients, vec![foreign]);
        initial(&mut users, Vec::new());
        assert_eq!(directory.client("kubectl").await, Ok(None));
    }

    #[tokio::test]
    async fn user_by_subject_matches_the_uid() {
        let (directory, mut clients, mut users) = directory();
        initial(&mut clients, Vec::new());
        let mut unstored = user("ghost", false);
        unstored.metadata.uid = None;
        initial(
            &mut users,
            vec![user("alice", false), user("bob", false), unstored],
        );
        assert_eq!(
            directory
                .user_by_subject("uid-bob")
                .await
                .unwrap()
                .unwrap()
                .name,
            "bob"
        );
        assert_eq!(directory.user_by_subject("uid-carol").await, Ok(None));
        assert_eq!(directory.user("ghost").await, Ok(None));
    }

    #[tokio::test]
    async fn a_relist_forgets_objects_deleted_while_the_watch_was_down() {
        let (directory, mut clients, mut users) = directory();
        initial(
            &mut clients,
            vec![
                oauth_client("kept", "http://127.0.0.1/"),
                oauth_client("gone", "http://127.0.0.1/"),
            ],
        );
        initial(&mut users, Vec::new());
        initial(
            &mut clients,
            vec![oauth_client("kept", "http://127.0.0.1/")],
        );
        assert!(directory.client("kept").await.unwrap().is_some());
        assert_eq!(directory.client("gone").await, Ok(None));
    }
}

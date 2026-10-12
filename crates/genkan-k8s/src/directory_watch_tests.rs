//! HTTP-level regression tests using real `kube::Api` list/watch streams.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::{Json, Router};
use futures_util::stream;
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc, oneshot, watch};

use super::{Api, Directory as _, KubeDirectory};

const CLIENTS: &str = "oauthclients";
const USERS: &str = "users";

type ListReply = oneshot::Sender<Value>;
type WatchSender = mpsc::UnboundedSender<Bytes>;

enum BackendRequest {
    List(&'static str, ListReply),
    Watch(&'static str, WatchSender),
}

struct Backend {
    objects: HashMap<&'static str, HashMap<String, Value>>,
    gets: HashMap<String, usize>,
    lists: HashMap<&'static str, usize>,
    fail_gets: bool,
    requests: mpsc::UnboundedSender<BackendRequest>,
}

async fn kubernetes(
    State(backend): State<Arc<Mutex<Backend>>>,
    request: Request<Body>,
) -> Response {
    let (request, _) = request.into_parts();
    assert_eq!(request.method, Method::GET);
    let path = request.uri.path();
    let resource = path
        .strip_prefix("/apis/genkan.engawahq.dev/v1alpha1/namespaces/test/")
        .unwrap();
    let mut backend = backend.lock().await;
    if let Some((kind, name)) = resource.split_once('/') {
        *backend.gets.entry(resource.to_owned()).or_default() += 1;
        if backend.fail_gets {
            return status(StatusCode::INTERNAL_SERVER_ERROR, "InternalError");
        }
        return backend
            .objects
            .get(kind)
            .and_then(|objects| objects.get(name))
            .cloned()
            .map_or_else(
                || status(StatusCode::NOT_FOUND, "NotFound"),
                |object| Json(object).into_response(),
            );
    }
    let resource = match resource {
        CLIENTS => CLIENTS,
        USERS => USERS,
        other => panic!("unexpected collection: {other}"),
    };
    // Api<PartialObjectMeta<K>> must negotiate metadata, not download full specs or secrets.
    assert!(
        request.headers["accept"]
            .to_str()
            .unwrap()
            .contains("as=PartialObjectMetadata")
    );
    let is_watch = form_urlencoded::parse(request.uri.query().unwrap_or_default().as_bytes())
        .any(|(key, value)| key == "watch" && value == "true");
    if is_watch {
        let (sender, receiver) = mpsc::unbounded_channel();
        backend
            .requests
            .send(BackendRequest::Watch(resource, sender))
            .unwrap();
        drop(backend);
        let chunks = stream::unfold(receiver, |mut receiver| async move {
            receiver
                .recv()
                .await
                .map(|bytes| (Ok::<_, std::convert::Infallible>(bytes), receiver))
        });
        Response::builder()
            .header("content-type", "application/json")
            .body(Body::from_stream(chunks))
            .unwrap()
    } else {
        *backend.lists.entry(resource).or_default() += 1;
        let (reply, response) = oneshot::channel();
        backend
            .requests
            .send(BackendRequest::List(resource, reply))
            .unwrap();
        drop(backend);
        response.await.map_or_else(
            |_| status(StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable"),
            |objects| Json(objects).into_response(),
        )
    }
}

fn status(code: StatusCode, reason: &str) -> Response {
    (
        code,
        Json(
            json!({"apiVersion":"v1", "kind":"Status", "status":"Failure",
            "code":code.as_u16(), "reason":reason, "message":reason}),
        ),
    )
        .into_response()
}

fn client(name: &str) -> Value {
    json!({"apiVersion":"genkan.engawahq.dev/v1alpha1", "kind":"OAuthClient",
        "metadata":{"name":name, "namespace":"test", "uid":format!("uid-{name}"), "resourceVersion":"101"},
        "spec":{"type":"Public", "displayName":"Original", "redirectUris":["https://example.com/callback"]}})
}

fn user(name: &str, uid: &str) -> Value {
    json!({"apiVersion":"genkan.engawahq.dev/v1alpha1", "kind":"User",
        "metadata":{"name":name, "namespace":"test", "uid":uid, "resourceVersion":"101"},
        "spec":{"username":name, "groups":["admins"], "elevatedGroups":[], "disabled":false}})
}

fn metadata(object: &Value) -> Value {
    json!({"apiVersion":"meta.k8s.io/v1", "kind":"PartialObjectMetadata",
        "metadata":object["metadata"]})
}

fn reply_list(reply: ListReply, items: &[Value], continuation: &str) {
    reply
        .send(
            json!({"apiVersion":"meta.k8s.io/v1", "kind":"PartialObjectMetadataList",
            "metadata":{"resourceVersion":"100", "continue":continuation}, "items":items}),
        )
        .unwrap();
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("stream gate or index did not advance")
}

async fn wait_for(predicate: impl Fn() -> bool) {
    bounded(async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

fn assert_pending<F: Future>(future: Pin<&mut F>) {
    assert!(matches!(
        future.poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
}

struct Mock {
    directory: KubeDirectory,
    backend: Arc<Mutex<Backend>>,
    requests: mpsc::UnboundedReceiver<BackendRequest>,
    pending_lists: HashMap<&'static str, ListReply>,
    streams: HashMap<&'static str, WatchSender>,
    shutdown: watch::Sender<bool>,
    watcher: tokio::task::JoinHandle<()>,
    server: tokio::task::JoinHandle<()>,
}

impl Mock {
    async fn unready(clients: Vec<Value>, users: Vec<Value>, stopping: bool) -> Self {
        let (requests, receiver) = mpsc::unbounded_channel();
        let collect = |objects: Vec<Value>| {
            objects
                .into_iter()
                .map(|object| {
                    (
                        object["metadata"]["name"].as_str().unwrap().to_owned(),
                        object,
                    )
                })
                .collect()
        };
        let backend = Arc::new(Mutex::new(Backend {
            objects: HashMap::from([(CLIENTS, collect(clients)), (USERS, collect(users))]),
            gets: HashMap::new(),
            lists: HashMap::new(),
            fail_gets: false,
            requests,
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(kubernetes)
            .with_state(Arc::clone(&backend));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = kube::Client::try_from(kube::Config::new(
            format!("http://{address}").parse().unwrap(),
        ))
        .unwrap();
        let (shutdown, shutdown_rx) = watch::channel(stopping);
        let (directory, watcher) = KubeDirectory::new(
            Api::namespaced(client.clone(), "test"),
            Api::namespaced(client, "test"),
            shutdown_rx,
        );
        Self {
            directory,
            backend,
            requests: receiver,
            pending_lists: HashMap::new(),
            streams: HashMap::new(),
            shutdown,
            watcher,
            server,
        }
    }

    async fn new(clients: Vec<Value>, users: Vec<Value>) -> Self {
        let mut mock = Self::unready(clients, users, false).await;
        for resource in [CLIENTS, USERS] {
            let reply = mock.take_list(resource).await;
            reply_list(reply, &mock.snapshot(resource).await, "");
        }
        bounded(mock.directory.wait_until_ready()).await.unwrap();
        mock.connect_watch(CLIENTS).await;
        mock.connect_watch(USERS).await;
        mock
    }

    async fn receive(&mut self) {
        match bounded(self.requests.recv()).await.unwrap() {
            BackendRequest::List(resource, reply) => {
                assert!(self.pending_lists.insert(resource, reply).is_none());
            }
            BackendRequest::Watch(resource, sender) => {
                assert!(self.streams.insert(resource, sender).is_none());
            }
        }
    }

    async fn take_list(&mut self, resource: &'static str) -> ListReply {
        loop {
            if let Some(reply) = self.pending_lists.remove(resource) {
                return reply;
            }
            self.receive().await;
        }
    }

    async fn connect_watch(&mut self, resource: &'static str) {
        while !self.streams.contains_key(resource) {
            self.receive().await;
        }
    }

    async fn snapshot(&self, resource: &str) -> Vec<Value> {
        self.backend.lock().await.objects[resource]
            .values()
            .map(metadata)
            .collect()
    }

    async fn put(&self, resource: &'static str, object: Value) {
        let name = object["metadata"]["name"].as_str().unwrap().to_owned();
        self.backend
            .lock()
            .await
            .objects
            .get_mut(resource)
            .unwrap()
            .insert(name, object);
    }

    fn event(&self, resource: &str, event: &str, object: &Value) {
        self.streams[resource]
            .send(Bytes::from(format!(
                "{}\n",
                json!({"type":event, "object":object})
            )))
            .unwrap();
    }

    async fn gets(&self, resource: &str) -> usize {
        self.backend
            .lock()
            .await
            .gets
            .get(resource)
            .copied()
            .unwrap_or_default()
    }

    fn has_client(&self, name: &str) -> bool {
        self.directory
            .client_index
            .find(|object| object.metadata.name.as_deref() == Some(name))
            .is_some()
    }

    async fn stop(&mut self) {
        self.shutdown.send(true).unwrap();
        bounded(&mut self.watcher).await.unwrap();
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        self.watcher.abort();
        self.server.abort();
    }
}

#[tokio::test]
async fn initial_snapshots_gate_resource_reads_until_all_pages_complete() {
    let known = client("known");
    let alice = user("alice", "uid-alice");
    let mut mock = Mock::unready(vec![known.clone()], vec![alice.clone()], false).await;
    let clients = mock.take_list(CLIENTS).await;
    let users = mock.take_list(USERS).await;
    let directory = mock.directory.clone();
    let mut ready = std::pin::pin!(directory.wait_until_ready());
    let mut client_lookup = std::pin::pin!(directory.client("known"));
    let mut user_lookup = std::pin::pin!(directory.user("alice"));
    let mut subject_lookup = std::pin::pin!(directory.user_by_subject("uid-alice"));
    assert_pending(ready.as_mut());
    assert_pending(client_lookup.as_mut());
    assert_pending(user_lookup.as_mut());
    assert_pending(subject_lookup.as_mut());
    reply_list(clients, &[metadata(&known)], "next-page");
    reply_list(users, &[metadata(&alice)], "");
    let second_page = mock.take_list(CLIENTS).await;
    bounded(directory.user_index.wait_until_ready())
        .await
        .unwrap();
    assert!(!mock.has_client("known"));
    assert_pending(ready.as_mut());
    assert_pending(client_lookup.as_mut());
    assert_pending(user_lookup.as_mut());
    assert_pending(subject_lookup.as_mut());
    assert!(mock.backend.lock().await.gets.is_empty());
    reply_list(second_page, &[], "");
    bounded(ready).await.unwrap();
    assert!(bounded(client_lookup).await.unwrap().is_some());
    assert!(bounded(user_lookup).await.unwrap().is_some());
    assert!(bounded(subject_lookup).await.unwrap().is_some());
    mock.stop().await;
}

#[tokio::test]
async fn unique_unknown_identifiers_never_read_resources() {
    let mock = Mock::new(vec![], vec![]).await;
    for number in 0..4096 {
        let unknown = format!("unknown-{number}");
        assert!(
            mock.directory
                .clone()
                .client(&unknown)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            mock.directory
                .user_by_subject(&unknown)
                .await
                .unwrap()
                .is_none()
        );
    }
    let backend = mock.backend.lock().await;
    assert!(backend.gets.is_empty());
    assert_eq!(backend.lists[CLIENTS], 1);
    assert_eq!(backend.lists[USERS], 1);
}

#[tokio::test]
async fn client_create_delete_events_update_existence_index() {
    let mock = Mock::new(vec![], vec![]).await;
    let created = client("created");
    mock.put(CLIENTS, created.clone()).await;
    assert!(mock.directory.client("created").await.unwrap().is_none());
    assert_eq!(mock.gets("oauthclients/created").await, 0);
    mock.event(CLIENTS, "ADDED", &metadata(&created));
    wait_for(|| mock.has_client("created")).await;
    assert!(mock.directory.client("created").await.unwrap().is_some());
    let cached = mock.directory.client_index.find(|_| true).unwrap();
    assert!(
        serde_json::to_value(cached.as_ref())
            .unwrap()
            .get("spec")
            .is_none()
    );
    mock.backend
        .lock()
        .await
        .objects
        .get_mut(CLIENTS)
        .unwrap()
        .remove("created");
    // Stale existence metadata never authorizes an object deleted before its watch event.
    assert!(mock.directory.client("created").await.unwrap().is_none());
    mock.event(CLIENTS, "DELETED", &metadata(&created));
    wait_for(|| !mock.has_client("created")).await;
    assert!(mock.directory.client("created").await.unwrap().is_none());
    assert_eq!(mock.gets("oauthclients/created").await, 2);
}

#[tokio::test]
async fn known_clients_read_latest_authorization_during_watch_interruption() {
    let mut mock = Mock::new(vec![client("known")], vec![]).await;
    assert_eq!(
        mock.directory
            .client("known")
            .await
            .unwrap()
            .unwrap()
            .display_name
            .as_deref(),
        Some("Original")
    );
    drop(mock.streams.remove(CLIENTS).unwrap());
    let mut updated = client("known");
    updated["spec"]["displayName"] = json!("Updated");
    updated["spec"]["type"] = json!("Confidential");
    updated["spec"]["secretHash"] = json!(format!("sha256:{}", "ab".repeat(32)));
    updated["spec"]["redirectUris"] = json!(["https://changed.example/callback"]);
    updated["spec"]["audiences"] = json!(["changed-audience"]);
    mock.put(CLIENTS, updated).await;
    let current = mock.directory.client("known").await.unwrap().unwrap();
    assert_eq!(current.display_name.as_deref(), Some("Updated"));
    assert_eq!(current.kind, genkan_store::ClientType::Confidential);
    assert_eq!(
        current.secret_hash,
        Some(format!("sha256:{}", "ab".repeat(32)))
    );
    assert_eq!(current.redirect_uris, ["https://changed.example/callback"]);
    assert_eq!(current.audiences, ["changed-audience"]);
    mock.backend.lock().await.fail_gets = true;
    assert!(mock.directory.client("known").await.is_err());
    mock.backend.lock().await.fail_gets = false;
    assert!(mock.directory.client("known").await.unwrap().is_some());
    assert_eq!(mock.gets("oauthclients/known").await, 4);
    mock.connect_watch(CLIENTS).await;
    assert_eq!(mock.backend.lock().await.lists[CLIENTS], 1);
    mock.stop().await;
}

#[tokio::test]
async fn subject_lookup_reads_current_authorization_without_per_request_lists() {
    let original = user("alice", "uid-alice");
    let mock = Mock::new(vec![], vec![original.clone()]).await;
    assert!(
        !mock
            .directory
            .user_by_subject("uid-alice")
            .await
            .unwrap()
            .unwrap()
            .disabled
    );
    let mut disabled = original;
    disabled["spec"]["disabled"] = json!(true);
    disabled["spec"]["groups"] = json!([]);
    mock.put(USERS, disabled).await;
    let current = mock
        .directory
        .user_by_subject("uid-alice")
        .await
        .unwrap()
        .unwrap();
    assert!(current.disabled);
    assert_eq!(current.groups, Vec::<String>::new());
    assert!(
        mock.directory
            .user("alice")
            .await
            .unwrap()
            .unwrap()
            .disabled
    );
    assert!(mock.directory.user("absent").await.unwrap().is_none());
    assert!(mock.directory.user("absent").await.unwrap().is_none());
    assert_eq!(mock.gets("users/alice").await, 3);
    assert_eq!(mock.gets("users/absent").await, 2);
    assert_eq!(mock.backend.lock().await.lists[USERS], 1);
    let cached = mock.directory.user_index.find(|_| true).unwrap();
    assert!(
        serde_json::to_value(cached.as_ref())
            .unwrap()
            .get("spec")
            .is_none()
    );
}

#[tokio::test]
async fn deleted_recreated_user_never_substitutes_subject() {
    let original = user("alice", "old-uid");
    let mock = Mock::new(vec![], vec![original.clone()]).await;
    assert!(
        mock.directory
            .user_by_subject("old-uid")
            .await
            .unwrap()
            .is_some()
    );
    mock.backend
        .lock()
        .await
        .objects
        .get_mut(USERS)
        .unwrap()
        .remove("alice");
    assert!(
        mock.directory
            .user_by_subject("old-uid")
            .await
            .unwrap()
            .is_none()
    );
    let recreated = user("alice", "new-uid");
    mock.put(USERS, recreated.clone()).await;
    assert!(
        mock.directory
            .user_by_subject("old-uid")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        mock.directory
            .user_by_subject("new-uid")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(mock.gets("users/alice").await, 3);
    mock.event(USERS, "DELETED", &metadata(&original));
    mock.event(USERS, "ADDED", &metadata(&recreated));
    wait_for(|| {
        mock.directory
            .user_index
            .find(|object| object.metadata.uid.as_deref() == Some("new-uid"))
            .is_some()
    })
    .await;
    assert!(
        mock.directory
            .user_by_subject("old-uid")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        mock.directory
            .user_by_subject("new-uid")
            .await
            .unwrap()
            .unwrap()
            .subject,
        "new-uid"
    );
    assert_eq!(mock.gets("users/alice").await, 4);
}

#[tokio::test]
async fn ambiguous_subjects_fail_closed_without_resource_reads() {
    let mock = Mock::new(
        vec![],
        vec![user("alice", "duplicate"), user("bob", "duplicate")],
    )
    .await;
    assert!(
        mock.directory
            .user_by_subject("duplicate")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        mock.directory
            .user_by_subject("absent")
            .await
            .unwrap()
            .is_none()
    );
    assert!(mock.backend.lock().await.gets.is_empty());
}

#[tokio::test]
async fn watch_reconnect_and_atomic_relist_recover_metadata_index() {
    let old = client("old");
    let retained = client("retained");
    let mut mock = Mock::new(vec![old, retained.clone()], vec![]).await;
    drop(mock.streams.remove(CLIENTS).unwrap());
    mock.connect_watch(CLIENTS).await;
    assert!(mock.has_client("old"));
    mock.event(
        CLIENTS,
        "ERROR",
        &json!({"apiVersion":"v1", "kind":"Status", "status":"Failure",
        "code":410, "reason":"Gone", "message":"resource version expired"}),
    );
    drop(mock.streams.remove(CLIENTS).unwrap());
    let first_page = mock.take_list(CLIENTS).await;
    mock.backend
        .lock()
        .await
        .objects
        .get_mut(CLIENTS)
        .unwrap()
        .remove("old");
    let created = client("created");
    mock.put(CLIENTS, created.clone()).await;
    reply_list(first_page, &[metadata(&created)], "next-page");
    let second_page = mock.take_list(CLIENTS).await;
    // The reflector keeps the previous complete index until all relist pages are published.
    assert!(mock.has_client("old"));
    assert!(!mock.has_client("created"));
    assert!(mock.directory.client("old").await.unwrap().is_none());
    assert!(mock.directory.client("created").await.unwrap().is_none());
    assert!(mock.directory.client("retained").await.unwrap().is_some());
    assert_eq!(mock.gets("oauthclients/created").await, 0);
    reply_list(second_page, &[metadata(&retained)], "");
    wait_for(|| mock.has_client("created") && !mock.has_client("old")).await;
    assert!(mock.directory.client("created").await.unwrap().is_some());
    assert_eq!(mock.directory.client_index.len(), 2);
    mock.connect_watch(CLIENTS).await;
    mock.stop().await;
}

#[tokio::test]
async fn shutdown_before_initial_sync_fails_readiness() {
    let mut mock = Mock::unready(vec![], vec![], false).await;
    let _clients = mock.take_list(CLIENTS).await;
    let _users = mock.take_list(USERS).await;
    mock.stop().await;
    assert!(bounded(mock.directory.wait_until_ready()).await.is_err());
    assert!(bounded(mock.directory.client("absent")).await.is_err());
    assert!(mock.backend.lock().await.gets.is_empty());

    let mut already_stopping = Mock::unready(vec![], vec![], true).await;
    bounded(&mut already_stopping.watcher).await.unwrap();
    assert!(
        bounded(already_stopping.directory.wait_until_ready())
            .await
            .is_err()
    );
    assert!(already_stopping.backend.lock().await.lists.is_empty());
}

#[tokio::test]
async fn aborted_watch_task_before_initial_sync_fails_readiness() {
    let mut mock = Mock::unready(vec![], vec![], false).await;
    let _clients = mock.take_list(CLIENTS).await;
    let _users = mock.take_list(USERS).await;
    mock.watcher.abort();
    assert!(bounded(&mut mock.watcher).await.unwrap_err().is_cancelled());
    assert!(bounded(mock.directory.wait_until_ready()).await.is_err());
}

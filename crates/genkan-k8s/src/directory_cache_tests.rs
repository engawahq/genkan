//! HTTP-level regression tests using the real `kube::Api` adapter.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use super::{Api, Directory as _, KubeDirectory, NEGATIVE_CAPACITY, NEGATIVE_TTL};

#[derive(Default)]
struct Backend {
    clients: HashMap<String, Value>,
    users: HashMap<String, Value>,
    gets: HashMap<String, usize>,
    fail: bool,
}

async fn kubernetes(
    State(state): State<Arc<Mutex<Backend>>>,
    request: Request<Body>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(request.method(), Method::GET);
    let path = request.uri().path();
    let mut state = state.lock().await;
    let prefix = "/apis/genkan.engawahq.dev/v1alpha1/namespaces/test/";
    let resource = path.strip_prefix(prefix).unwrap();
    *state.gets.entry(resource.to_owned()).or_default() += 1;
    let object = if let Some(name) = resource.strip_prefix("oauthclients/") {
        state.clients.get(name)
    } else if let Some(name) = resource.strip_prefix("users/") {
        state.users.get(name)
    } else {
        // LIST is not supported: returning an error makes a regression fail without hanging.
        return status(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed");
    }
    .cloned();
    if state.fail {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "InternalError");
    }
    drop(state);
    object.map_or_else(
        || status(StatusCode::NOT_FOUND, "NotFound"),
        |object| (StatusCode::OK, Json(object)),
    )
}

fn status(code: StatusCode, reason: &str) -> (StatusCode, Json<Value>) {
    (
        code,
        Json(
            json!({"apiVersion":"v1", "kind":"Status", "status":"Failure",
            "code":code.as_u16(), "reason":reason, "message":reason}),
        ),
    )
}

struct Mock {
    directory: KubeDirectory,
    backend: Arc<Mutex<Backend>>,
    task: tokio::task::JoinHandle<()>,
}

impl Mock {
    async fn new() -> Self {
        let backend = Arc::new(Mutex::new(Backend::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(kubernetes)
            .with_state(Arc::clone(&backend));
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = kube::Client::try_from(kube::Config::new(
            format!("http://{address}").parse().unwrap(),
        ))
        .unwrap();
        Self {
            directory: KubeDirectory::new(
                Api::namespaced(client.clone(), "test"),
                Api::namespaced(client, "test"),
            ),
            backend,
            task,
        }
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

    async fn put_client(&self, name: &str, display: &str) {
        self.backend.lock().await.clients.insert(name.to_owned(), json!({
            "apiVersion":"genkan.engawahq.dev/v1alpha1", "kind":"OAuthClient",
            "metadata":{"name":name},
            "spec":{"type":"Public", "displayName":display, "redirectUris":["https://example.com/callback"]}
        }));
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn repeated_unknown_client_uses_one_api_get_across_clones() {
    let mock = Mock::new().await;
    assert!(mock.directory.client("unknown").await.unwrap().is_none());
    assert!(
        mock.directory
            .clone()
            .client("unknown")
            .await
            .unwrap()
            .is_none()
    );
    assert!(mock.directory.client("unknown").await.unwrap().is_none());
    assert_eq!(mock.gets("oauthclients/unknown").await, 1);
}

#[tokio::test]
async fn positive_client_updates_and_backend_failures_are_not_cached() {
    let mock = Mock::new().await;
    mock.put_client("kubectl", "Original").await;
    assert_eq!(
        mock.directory
            .client("kubectl")
            .await
            .unwrap()
            .unwrap()
            .display_name
            .as_deref(),
        Some("Original")
    );
    mock.put_client("kubectl", "Updated").await;
    assert_eq!(
        mock.directory
            .client("kubectl")
            .await
            .unwrap()
            .unwrap()
            .display_name
            .as_deref(),
        Some("Updated")
    );
    assert_eq!(mock.gets("oauthclients/kubectl").await, 2);

    mock.backend.lock().await.fail = true;
    assert!(mock.directory.client("recovering").await.is_err());
    assert!(mock.directory.client("recovering").await.is_err());
    mock.backend.lock().await.fail = false;
    mock.put_client("recovering", "Recovered").await;
    assert!(mock.directory.client("recovering").await.unwrap().is_some());
    assert_eq!(mock.gets("oauthclients/recovering").await, 3);
}

#[tokio::test]
async fn user_lookup_reads_current_state_and_uid_by_name_without_list() {
    let mock = Mock::new().await;
    let user = json!({"apiVersion":"genkan.engawahq.dev/v1alpha1", "kind":"User",
        "metadata":{"name":"alice", "uid":"uid-alice"},
        "spec":{"username":"alice", "groups":["admins"], "elevatedGroups":[], "disabled":false}});
    mock.backend.lock().await.users.insert("alice".into(), user);
    let user = mock.directory.user("alice").await.unwrap().unwrap();
    assert_eq!(user.subject, "uid-alice");
    assert!(!user.disabled);
    mock.backend.lock().await.users.get_mut("alice").unwrap()["spec"]["disabled"] = json!(true);
    assert!(
        mock.directory
            .user("alice")
            .await
            .unwrap()
            .unwrap()
            .disabled
    );
    assert_eq!(mock.gets("users/alice").await, 2);
    assert_eq!(mock.gets("users").await, 0);

    assert!(mock.directory.user("absent").await.unwrap().is_none());
    assert!(mock.directory.user("absent").await.unwrap().is_none());
    assert_eq!(mock.gets("users/absent").await, 2);
    mock.backend.lock().await.fail = true;
    assert!(mock.directory.user("alice").await.is_err());
    mock.backend.lock().await.fail = false;
    assert!(
        mock.directory
            .user("alice")
            .await
            .unwrap()
            .unwrap()
            .disabled
    );
    assert_eq!(mock.gets("users/alice").await, 4);
}

#[tokio::test]
async fn created_client_becomes_visible_at_monotonic_expiry_without_hit_extension() {
    let mock = Mock::new().await;
    let start = Instant::now();
    assert!(
        mock.directory
            .client_at("new", || start)
            .await
            .unwrap()
            .is_none()
    );
    mock.put_client("new", "New client").await;
    let just_before = (start + NEGATIVE_TTL)
        .checked_sub(Duration::from_nanos(1))
        .unwrap();
    assert!(
        mock.directory
            .client_at("new", || just_before)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(mock.gets("oauthclients/new").await, 1);
    assert!(
        mock.directory
            .client_at("new", || start + NEGATIVE_TTL)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(mock.gets("oauthclients/new").await, 2);
    mock.put_client("new", "Updated").await;
    assert_eq!(
        mock.directory
            .client_at("new", || start + NEGATIVE_TTL)
            .await
            .unwrap()
            .unwrap()
            .display_name
            .as_deref(),
        Some("Updated")
    );
    assert_eq!(mock.gets("oauthclients/new").await, 3);
}

#[tokio::test]
async fn negative_cache_bounds_evict_oldest_not_recently_hit() {
    let mock = Mock::new().await;
    let start = Instant::now();
    for i in 0..NEGATIVE_CAPACITY {
        assert!(
            mock.directory
                .client_at(&format!("missing-{i}"), || start)
                .await
                .unwrap()
                .is_none()
        );
    }
    // A hit does not change insertion/eviction order.
    assert!(
        mock.directory
            .client_at("missing-0", || start)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(mock.gets("oauthclients/missing-0").await, 1);
    assert!(
        mock.directory
            .client_at("overflow", || start)
            .await
            .unwrap()
            .is_none()
    );
    {
        let missing = mock.directory.missing_clients.lock().await;
        assert_eq!(missing.entries.len(), NEGATIVE_CAPACITY);
        assert_eq!(missing.oldest.len(), NEGATIVE_CAPACITY);
    }
    assert!(
        mock.directory
            .client_at("missing-1", || start)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(mock.gets("oauthclients/missing-1").await, 1);
    assert!(
        mock.directory
            .client_at("missing-0", || start)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(mock.gets("oauthclients/missing-0").await, 2);
    let expired = start + NEGATIVE_TTL;
    assert!(
        mock.directory
            .client_at("after-expiry", || expired)
            .await
            .unwrap()
            .is_none()
    );
    let missing = mock.directory.missing_clients.lock().await;
    assert_eq!(missing.entries.len(), 1);
    assert_eq!(missing.oldest.len(), 1);
}

#[test]
fn duplicate_misses_do_not_extend_expiry_or_add_eviction_entries() {
    let start = Instant::now();
    let mut missing = super::NegativeClients::default();
    missing.insert("duplicate", start);
    missing.insert("duplicate", start + Duration::from_secs(4));
    assert_eq!(missing.entries.len(), 1);
    assert_eq!(missing.oldest.len(), 1);
    assert!(!missing.contains("duplicate", start + NEGATIVE_TTL));
}

//! The one-time setup token in a Secret, and the cluster admin's side of issuing it.
//!
//! The cluster admin runs `genkanctl setup-link` with their own kubeconfig. It creates the `User`
//! (in group `admins`), optionally removes the user's old passkeys and sessions (`--reset`), and
//! writes the Secret `genkan-setup` holding only the SHA-256 of a fresh 256-bit token. Genkan's
//! service account can only `get` and `delete` that Secret, so it can redeem a token but never
//! create one, and it never needs RBAC rights: the `genkan:admins` binding is created at install.
//!
//! Redeeming is a delete with `uid` and `resourceVersion` preconditions, so exactly one of any
//! number of concurrent redemptions succeeds, and issuing a new link (which replaces the Secret)
//! invalidates every earlier one. The token travels in the URL fragment, which browsers do not
//! send to servers or proxies. A user who already has passkeys gets a link only with `--reset`,
//! which also deletes the user's credentials and grants: otherwise the link's holder could add a
//! passkey to an account that someone else controls.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use genkan_core::clock::UnixTime;
use genkan_core::config::BaseUrl;
use genkan_core::crypto::{hash_secret, random};
use genkan_store::{Consume, SetupStore, SetupToken, StoreError, invitation_name};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, PostParams};
use kube::core::PartialObjectMeta;
use kube::{Client, ResourceExt as _};
use thiserror::Error;

use super::MANAGED_BY;
use super::objects::{DeleteOutcome, delete_if_unchanged};
use crate::crd::credential::Credential;
use crate::crd::grant::Grant;
use crate::crd::invitation::Invitation;
use crate::crd::user::{User, UserSpec};
use crate::crd::{EXPIRES_AT_ANNOTATION, USER_LABEL};

/// Name of the setup Secret.
pub const SETUP_SECRET: &str = "genkan-setup";
/// Its `type`.
pub const SECRET_TYPE: &str = "genkan.engawahq.dev/setup";
pub use genkan_core::protocol::ADMIN_GROUP;

const USER_KEY: &str = "user";
const HASH_KEY: &str = "token-hash";
const USER_UID_KEY: &str = "user-uid";

/// Reads and consumes the setup token and, when enabled, invitations.
#[derive(Clone)]
pub struct KubeSetupStore {
    api: Api<Secret>,
    invitations: Option<Api<Invitation>>,
}

impl std::fmt::Debug for KubeSetupStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KubeSetupStore")
    }
}

impl KubeSetupStore {
    /// Uses the given (namespaced) API.
    #[must_use]
    pub const fn new(api: Api<Secret>) -> Self {
        Self {
            api,
            invitations: None,
        }
    }

    /// Also redeems invitations from the given (namespaced) API.
    #[must_use]
    pub fn with_invitations(mut self, invitations: Api<Invitation>) -> Self {
        self.invitations = Some(invitations);
        self
    }
}

fn backend(error: &kube::Error) -> StoreError {
    StoreError(error.to_string())
}

fn data(secret: &Secret, key: &str) -> Option<String> {
    let bytes = secret.data.as_ref()?.get(key)?;
    String::from_utf8(bytes.0.clone()).ok()
}

async fn load_setup(api: &Api<Secret>) -> Result<Option<SetupToken>, StoreError> {
    let Some(secret) = api.get_opt(SETUP_SECRET).await.map_err(|e| backend(&e))? else {
        return Ok(None);
    };
    if secret.type_.as_deref() != Some(SECRET_TYPE) {
        return Err(StoreError(format!(
            "Secret {SETUP_SECRET} has the wrong type"
        )));
    }
    let expires_at = secret
        .annotations()
        .get(EXPIRES_AT_ANNOTATION)
        .and_then(|v| v.parse::<u64>().ok())
        .map(UnixTime::from_secs);
    let (Some(user), Some(user_uid), Some(token_hash), Some(expires_at), Some(uid), Some(rv)) = (
        data(&secret, USER_KEY).filter(|value| !value.is_empty()),
        data(&secret, USER_UID_KEY).filter(|value| !value.is_empty()),
        data(&secret, HASH_KEY),
        expires_at,
        secret.uid(),
        secret.resource_version(),
    ) else {
        return Err(StoreError(format!("Secret {SETUP_SECRET} is malformed")));
    };
    Ok(Some(SetupToken {
        user: genkan_store::UserReference {
            name: user,
            uid: user_uid,
        },
        token_hash,
        expires_at,
        version: format!("{SETUP_SECRET}/{uid}/{rv}"),
    }))
}

async fn load_invitation(
    api: &Api<Invitation>,
    name: &str,
) -> Result<Option<SetupToken>, StoreError> {
    let Some(invitation) = api.get_opt(name).await.map_err(|e| backend(&e))? else {
        return Ok(None);
    };
    let (Some(uid), Some(rv)) = (invitation.uid(), invitation.resource_version()) else {
        return Ok(None);
    };
    // A mailed invitation has no hash until Genkan has generated and sent its token.
    let Some(token_hash) = invitation.spec.token_hash.clone().or_else(|| {
        invitation
            .status
            .as_ref()
            .and_then(|s| s.token_hash.clone())
    }) else {
        return Ok(None);
    };
    Ok(Some(SetupToken {
        user: genkan_store::UserReference {
            name: invitation.spec.user.clone(),
            uid: invitation.spec.user_uid.clone(),
        },
        token_hash,
        expires_at: UnixTime::from_secs(u64::try_from(invitation.spec.expires_at).unwrap_or(0)),
        version: format!("{INVITATION_VERSION}{name}/{uid}/{rv}"),
    }))
}

/// Prefix of an invitation token's version.
const INVITATION_VERSION: &str = "invitation:";

impl SetupStore for KubeSetupStore {
    fn load(
        &self,
        presented: &str,
    ) -> impl Future<Output = Result<Option<SetupToken>, StoreError>> + Send {
        let api = self.api.clone();
        let invitations = self.invitations.clone();
        let invitation = invitation_name(presented).map(str::to_owned);
        async move {
            match (invitation, invitations) {
                (Some(name), Some(invitations)) => load_invitation(&invitations, &name).await,
                // Invitations are disabled: such a token refers to nothing.
                (Some(_), None) => Ok(None),
                (None, _) => load_setup(&api).await,
            }
        }
    }

    fn consume(
        &self,
        token: &SetupToken,
    ) -> impl Future<Output = Result<Consume, StoreError>> + Send {
        let api = self.api.clone();
        let invitations = self.invitations.clone();
        let version = token.version.clone();
        async move {
            let malformed = || StoreError("malformed enrolment token version".to_owned());
            let (name, rest) = version.split_once('/').ok_or_else(malformed)?;
            let (uid, rv) = rest.split_once('/').ok_or_else(malformed)?;
            // The delete is the single-use gate: with uid and resourceVersion preconditions,
            // exactly one concurrent redemption succeeds, and a regenerated token is never
            // consumed by a redemption that read the old one.
            let outcome = match name.strip_prefix(INVITATION_VERSION) {
                Some(invitation) => {
                    let api = invitations.ok_or_else(malformed)?;
                    delete_if_unchanged(&api, invitation, uid, rv).await
                }
                None if name == SETUP_SECRET => {
                    delete_if_unchanged(&api, SETUP_SECRET, uid, rv).await
                }
                None => return Err(malformed()),
            };
            match outcome.map_err(|e| backend(&e))? {
                DeleteOutcome::Deleted => Ok(Consume::Consumed),
                DeleteOutcome::Changed | DeleteOutcome::NotFound => Ok(Consume::AlreadyUsed),
            }
        }
    }
}

/// Why a setup link could not be issued.
#[derive(Debug, Error)]
pub enum SetupLinkError {
    /// The Kubernetes API failed (often: the kubeconfig lacks the rights).
    #[error("Kubernetes API: {0}")]
    Kubernetes(#[from] kube::Error),
    /// The user already has passkeys; issuing a link would let its holder add another.
    #[error(
        "user {user} already has {count} passkey(s); pass --reset to remove them and their sessions"
    )]
    HasCredentials {
        /// User object name.
        user: String,
        /// How many credentials exist.
        count: usize,
    },
    /// Randomness failed.
    #[error("generating the token failed")]
    Crypto,
    /// The API response did not identify the original user incarnation.
    #[error("the User has no Kubernetes UID")]
    MissingUserUid,
}

/// A freshly issued setup link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupLink {
    /// `https://<issuer>/setup#token=<token>`. The token is in the fragment, so it never reaches
    /// server or proxy logs.
    pub url: String,
    /// When the link stops working.
    pub expires_at: UnixTime,
}

/// Issues a setup link for `username` using the caller's (cluster admin's) credentials.
///
/// Counting and purging credentials/grants uses [`PartialObjectMeta`] rather than decoding
/// their specs, so `--reset` can remove legacy records without an original user UID. This is
/// deletion, never adoption or backfill. The [metadata-only API] preserves the resource path
/// and ignores unverifiable specs even when a collection delete returns the deleted objects.
///
/// [metadata-only API]: https://docs.rs/kube-core/4.2.0/src/kube_core/metadata.rs.html#149-180
///
/// # Errors
///
/// [`SetupLinkError`] if the API calls fail, or the user already has passkeys and `reset` is
/// false.
pub async fn issue_setup_link(
    client: Client,
    namespace: &str,
    issuer: &BaseUrl,
    username: &str,
    valid_for: Duration,
    reset: bool,
    now: UnixTime,
) -> Result<SetupLink, SetupLinkError> {
    let pp = PostParams::default();
    let users: Api<User> = Api::namespaced(client.clone(), namespace);
    let user = if let Some(user) = users.get_opt(username).await? {
        user
    } else {
        let user = User::new(
            username,
            UserSpec {
                username: username.to_owned(),
                display_name: None,
                groups: vec![ADMIN_GROUP.to_owned()],
                elevated_groups: vec![ADMIN_GROUP.to_owned()],
                disabled: false,
            },
        );
        users.create(&pp, &user).await?
    };
    let user_uid = user
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or(SetupLinkError::MissingUserUid)?;

    let selector = ListParams::default().labels(&format!("{USER_LABEL}={username}"));
    // Recovery only counts and deletes objects; it must not deserialize unverifiable legacy
    // specs. Metadata-only APIs also handle delete responses containing those old objects.
    // Authentication continues to use the strict Credential/Grant types, with no UID backfill.
    let credentials: Api<PartialObjectMeta<Credential>> =
        Api::namespaced(client.clone(), namespace);
    let existing = credentials.list(&selector).await?.items.len();
    if existing > 0 {
        if !reset {
            return Err(SetupLinkError::HasCredentials {
                user: username.to_owned(),
                count: existing,
            });
        }
        credentials
            .delete_collection(&DeleteParams::default(), &selector)
            .await?;
        // End the user's refresh-token families too: whoever held the old passkeys is out.
        let grants: Api<PartialObjectMeta<Grant>> = Api::namespaced(client.clone(), namespace);
        grants
            .delete_collection(&DeleteParams::default(), &selector)
            .await?;
    }

    let token = URL_SAFE_NO_PAD.encode(random::<32>().map_err(|_crypto| SetupLinkError::Crypto)?);
    let expires_at = now.saturating_add(valid_for);
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let mut secret = Secret {
        metadata: ObjectMeta {
            name: Some(SETUP_SECRET.to_owned()),
            labels: Some(BTreeMap::from([(
                MANAGED_BY.0.to_owned(),
                MANAGED_BY.1.to_owned(),
            )])),
            annotations: Some(BTreeMap::from([(
                EXPIRES_AT_ANNOTATION.to_owned(),
                expires_at.as_secs().to_string(),
            )])),
            ..ObjectMeta::default()
        },
        type_: Some(SECRET_TYPE.to_owned()),
        data: Some(BTreeMap::from([
            (
                USER_KEY.to_owned(),
                ByteString(username.as_bytes().to_vec()),
            ),
            (USER_UID_KEY.to_owned(), ByteString(user_uid.into_bytes())),
            (
                HASH_KEY.to_owned(),
                ByteString(hash_secret(token.as_bytes()).into_bytes()),
            ),
        ])),
        ..Secret::default()
    };
    // Replacing the Secret changes its UID or resourceVersion, which invalidates any earlier link.
    match secrets.get_opt(SETUP_SECRET).await? {
        Some(current) => {
            secret.metadata.resource_version = current.resource_version();
            secrets.replace(SETUP_SECRET, &pp, &secret).await?;
        }
        None => {
            secrets.create(&pp, &secret).await?;
        }
    }
    Ok(SetupLink {
        url: format!("{}#token={token}", issuer.join("/setup")),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::to_bytes;
    use axum::extract::{Request, State};
    use axum::http::{Method, StatusCode};
    use axum::response::{IntoResponse as _, Response};
    use axum::{Json, Router};
    use kube::Config;
    use serde_json::{Value, json};
    use tokio::sync::Mutex;

    use super::*;

    const API_ROOT: &str = "/apis/genkan.engawahq.dev/v1alpha1/namespaces/test";
    const SECRET_ROOT: &str = "/api/v1/namespaces/test/secrets";

    #[derive(Default)]
    struct LegacyStorage {
        credentials_deleted: bool,
        grants_deleted: bool,
        secret: Option<Secret>,
    }

    fn legacy_list(kind: &str) -> Value {
        let spec = if kind == "Credential" {
            json!({
                "user": "admin", "type": "Passkey",
                "passkey": { "credentialId": "Y3JlZA", "record": "{}" }
            })
        } else {
            json!({
                "user": "admin", "client": "kubectl", "audience": "kubernetes",
                "scopes": ["openid"], "authTime": 1000, "amr": ["swk", "mfa"],
                "expiresAt": 4600, "initialIdleExpiresAt": 4600,
                "initialHash": format!("sha256:{}", "a".repeat(64))
            })
        };
        json!({
            "apiVersion": "genkan.engawahq.dev/v1alpha1", "kind": format!("{kind}List"),
            "metadata": { "resourceVersion": "1" },
            "items": [{
                "apiVersion": "genkan.engawahq.dev/v1alpha1", "kind": kind,
                "metadata": {
                    "name": "legacy", "namespace": "test", "uid": "legacy-object",
                    "labels": { USER_LABEL: "admin" }
                },
                "spec": spec
            }]
        })
    }

    async fn legacy_api(
        State(storage): State<Arc<Mutex<LegacyStorage>>>,
        request: Request,
    ) -> Response {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let query = request.uri().query().unwrap_or_default().to_owned();
        let body = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
        let mut storage = storage.lock().await;
        if method == Method::GET && path == format!("{API_ROOT}/users/admin") {
            return Json(json!({
                "apiVersion": "genkan.engawahq.dev/v1alpha1", "kind": "User",
                "metadata": { "name": "admin", "namespace": "test", "uid": "original-admin" },
                "spec": { "username": "admin", "groups": ["admins"] }
            }))
            .into_response();
        }
        for (plural, kind) in [("credentials", "Credential"), ("grants", "Grant")] {
            if path != format!("{API_ROOT}/{plural}") {
                continue;
            }
            let selector = form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "labelSelector")
                .map(|(_, value)| value.into_owned());
            assert_eq!(selector, Some(format!("{USER_LABEL}=admin")));
            if method == Method::DELETE {
                if kind == "Credential" {
                    storage.credentials_deleted = true;
                } else {
                    storage.grants_deleted = true;
                }
                // A collection delete can return the deleted objects, not just a Status.
                return Json(legacy_list(kind)).into_response();
            }
            assert_eq!(method, Method::GET);
            return Json(legacy_list(kind)).into_response();
        }
        if path == format!("{SECRET_ROOT}/{SETUP_SECRET}") && method == Method::GET {
            if let Some(secret) = &storage.secret {
                return Json(secret).into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "reason": "NotFound", "message": "setup Secret not found", "code": 404
                })),
            )
                .into_response();
        }
        if path == SECRET_ROOT && method == Method::POST {
            assert!(storage.credentials_deleted && storage.grants_deleted);
            let mut secret: Secret = serde_json::from_slice(&body).unwrap();
            secret.metadata.uid = Some("setup-secret".into());
            secret.metadata.resource_version = Some("2".into());
            storage.secret = Some(secret.clone());
            drop(storage);
            return (StatusCode::CREATED, Json(secret)).into_response();
        }
        panic!("unexpected Kubernetes request: {method} {path}");
    }

    #[tokio::test]
    async fn reset_purges_legacy_specs_and_issues_uid_bound_setup_link() {
        let storage = Arc::new(Mutex::new(LegacyStorage::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(legacy_api)
            .with_state(Arc::clone(&storage));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client =
            Client::try_from(Config::new(format!("http://{address}").parse().unwrap())).unwrap();
        let issuer = BaseUrl::parse("issuer", "https://login.example.com").unwrap();
        let now = UnixTime::from_secs(1000);

        let error = issue_setup_link(
            client.clone(),
            "test",
            &issuer,
            "admin",
            Duration::from_mins(60),
            false,
            now,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            SetupLinkError::HasCredentials { count: 1, .. }
        ));
        assert!(storage.lock().await.secret.is_none());

        let link = issue_setup_link(
            client.clone(),
            "test",
            &issuer,
            "admin",
            Duration::from_mins(60),
            true,
            now,
        )
        .await
        .unwrap();
        let raw = link.url.split_once("#token=").unwrap().1;
        let token = KubeSetupStore::new(Api::namespaced(client, "test"))
            .load(raw)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token.user.name, "admin");
        assert_eq!(token.user.uid, "original-admin");
        assert_eq!(token.token_hash, hash_secret(raw.as_bytes()));
        let storage = storage.lock().await;
        assert!(storage.credentials_deleted && storage.grants_deleted);
        drop(storage);
        server.abort();
    }
}

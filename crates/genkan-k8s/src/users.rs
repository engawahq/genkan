//! [`UserAdmin`] backed by `User` objects.
//!
//! SCIM's users carry the label `genkan.engawahq.dev/source=scim` ([`SOURCE_LABEL`]) and are the
//! only ones it can see or change. With SCIM enabled, an admission policy
//! ([`super::rbac::scim_policy`]) enforces the same boundary on Genkan's service account.

use std::collections::BTreeMap;
use std::future::Future;

use genkan_store::StoreError;
use genkan_store::scim::{ManagedUser, UserAdmin, Write};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, PostParams, Preconditions};
use kube::{Resource, ResourceExt as _};

use super::MANAGED_BY;
use super::objects::{CreateOutcome, create_once};
use crate::crd::user::{User, UserSpec};

/// Label marking who created a `User`.
pub const SOURCE_LABEL: &str = "genkan.engawahq.dev/source";
/// Its value for users created through SCIM.
pub const SCIM_SOURCE: &str = "scim";
/// Annotation holding the identity provider's `externalId`.
pub const EXTERNAL_ID_ANNOTATION: &str = "genkan.engawahq.dev/scim-external-id";

/// Reads and writes SCIM's users.
#[derive(Clone)]
pub struct KubeUserAdmin {
    api: Api<User>,
}

impl std::fmt::Debug for KubeUserAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KubeUserAdmin")
    }
}

impl KubeUserAdmin {
    /// Uses the given (namespaced) API.
    #[must_use]
    pub const fn new(api: Api<User>) -> Self {
        Self { api }
    }
}

fn backend(error: &kube::Error) -> StoreError {
    StoreError(error.to_string())
}

/// An `ownerReference` to the current `User` named `name`, so that Kubernetes' garbage
/// collector deletes the dependent with that User ([Owners and Dependents]).
///
/// The reference carries the User's UID: a same-named User created later does not adopt the
/// dependent, and one deleted before the dependent is created leaves it to the collector.
/// It is not a controller reference and does not set `blockOwnerDeletion`, which would need
/// `delete` on Users. Collection is eventual and skipped by orphan deletion, so it is cleanup,
/// not revocation: reads do not check the owner's UID.
///
/// Like `Resource::owner_ref`, returns `None` for a User without a UID; API-server responses
/// always have one. Requires a namespaced API to keep owner and dependent in the same namespace.
///
/// [Owners and Dependents]: https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
pub(crate) async fn user_owner<K>(
    api: &Api<K>,
    name: &str,
) -> Result<Option<OwnerReference>, StoreError>
where
    K: Resource + Clone,
{
    let namespace = api
        .namespace()
        .ok_or_else(|| StoreError("User dependents require a namespaced API".to_owned()))?;
    let users: Api<User> = Api::namespaced(api.clone().into_client(), namespace);
    let user = users.get(name).await.map_err(|error| backend(&error))?;
    Ok(user.owner_ref(&()))
}

fn status_code(error: &kube::Error) -> Option<u16> {
    if let kube::Error::Api(status) = error {
        Some(status.code)
    } else {
        None
    }
}

fn managed(user: &User) -> bool {
    user.labels().get(SOURCE_LABEL).map(String::as_str) == Some(SCIM_SOURCE)
}

fn convert(user: &User) -> ManagedUser {
    ManagedUser {
        name: user.name_any(),
        version: user.resource_version().unwrap_or_default(),
        username: user.spec.username.clone(),
        display_name: user.spec.display_name.clone(),
        groups: user.spec.groups.clone(),
        disabled: user.spec.disabled,
        external_id: user.annotations().get(EXTERNAL_ID_ANNOTATION).cloned(),
        created: user
            .meta()
            .creation_timestamp
            .as_ref()
            .and_then(|t| serde_json::to_value(t).ok())
            .and_then(|v| v.as_str().map(str::to_owned)),
    }
}

fn object(user: &ManagedUser) -> User {
    User {
        metadata: ObjectMeta {
            name: Some(user.name.clone()),
            labels: Some(BTreeMap::from([
                (MANAGED_BY.0.to_owned(), MANAGED_BY.1.to_owned()),
                (SOURCE_LABEL.to_owned(), SCIM_SOURCE.to_owned()),
            ])),
            annotations: user
                .external_id
                .as_ref()
                .map(|id| BTreeMap::from([(EXTERNAL_ID_ANNOTATION.to_owned(), id.clone())])),
            ..ObjectMeta::default()
        },
        spec: UserSpec {
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            groups: user.groups.clone(),
            disabled: user.disabled,
            // SCIM never grants elevated groups.
            elevated_groups: Vec::new(),
        },
        status: None,
    }
}

impl UserAdmin for KubeUserAdmin {
    fn list(&self) -> impl Future<Output = Result<Vec<ManagedUser>, StoreError>> + Send {
        let api = self.api.clone();
        async move {
            let selector = ListParams::default().labels(&format!("{SOURCE_LABEL}={SCIM_SOURCE}"));
            let list = api.list(&selector).await.map_err(|e| backend(&e))?;
            let mut users: Vec<ManagedUser> = list.items.iter().map(convert).collect();
            users.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(users)
        }
    }

    fn get(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<ManagedUser>, StoreError>> + Send {
        let api = self.api.clone();
        let name = name.to_owned();
        async move {
            let user = api.get_opt(&name).await.map_err(|e| backend(&e))?;
            Ok(user.filter(managed).as_ref().map(convert))
        }
    }

    fn username_taken(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let api = self.api.clone();
        let selector = ListParams::default().fields(&format!("spec.username={username}"));
        async move {
            let list = api.list(&selector).await.map_err(|e| backend(&e))?;
            Ok(!list.items.is_empty())
        }
    }

    fn create(&self, user: &ManagedUser) -> impl Future<Output = Result<Write, StoreError>> + Send {
        let api = self.api.clone();
        let object = object(user);
        async move {
            match create_once(&api, &object).await.map_err(|e| backend(&e))? {
                CreateOutcome::Created(created) => Ok(Write::Done(convert(&created))),
                CreateOutcome::AlreadyExists => Ok(Write::Exists),
            }
        }
    }

    fn replace(
        &self,
        user: &ManagedUser,
    ) -> impl Future<Output = Result<Write, StoreError>> + Send {
        let api = self.api.clone();
        let user = user.clone();
        async move {
            let Some(current) = api.get_opt(&user.name).await.map_err(|e| backend(&e))? else {
                return Ok(Write::NotFound);
            };
            if !managed(&current) {
                return Ok(Write::NotFound);
            }
            let mut next = object(&user);
            next.metadata.resource_version = Some(user.version.clone());
            next.status = current.status;
            match api.replace(&user.name, &PostParams::default(), &next).await {
                Ok(stored) => Ok(Write::Done(convert(&stored))),
                Err(error) if status_code(&error) == Some(409) => Ok(Write::Conflict),
                Err(error) if status_code(&error) == Some(404) => Ok(Write::NotFound),
                Err(error) => Err(backend(&error)),
            }
        }
    }

    fn delete(&self, name: &str) -> impl Future<Output = Result<Write, StoreError>> + Send {
        let api = self.api.clone();
        let name = name.to_owned();
        async move {
            let Some(current) = api.get_opt(&name).await.map_err(|e| backend(&e))? else {
                return Ok(Write::NotFound);
            };
            if !managed(&current) {
                return Ok(Write::NotFound);
            }
            // The UID precondition makes sure a same-named user created meanwhile survives.
            let params = DeleteParams {
                preconditions: Some(Preconditions {
                    uid: current.uid(),
                    resource_version: None,
                }),
                ..DeleteParams::default()
            };
            match api.delete(&name, &params).await {
                Ok(_) => Ok(Write::Done(convert(&current))),
                Err(error) if matches!(status_code(&error), Some(404 | 409)) => Ok(Write::NotFound),
                Err(error) => Err(backend(&error)),
            }
        }
    }
}

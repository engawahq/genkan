//! Single-use and compare-and-swap primitives on Kubernetes objects.
//!
//! Each function is one API request whose outcome is decided atomically by the API server and its
//! storage (etcd, or kine on k3s):
//!
//! - [`create_once`]: a deterministic name turns `create` into insert-if-absent; the losers of a
//!   race get `409 AlreadyExists`.
//! - [`replace_status_if_unchanged`]: `resourceVersion` makes an update a compare-and-swap; the
//!   losers get `409 Conflict`.
//! - [`delete_if_unchanged`]: delete preconditions on `uid` and `resourceVersion`; exactly one of
//!   many concurrent deletes succeeds.
//!
//! The guarantees come from the API server ([API concepts], [DeleteOptions]): a create of an
//! existing name fails, an update carrying a stale `resourceVersion` fails, and a delete checks
//! its preconditions and then deletes only if the stored revision is unchanged (a transaction in
//! etcd; a unique index on the previous revision in kine). Gates therefore always talk to the API
//! server directly, never to a watch cache. A name derived from a hash of the identifier (as
//! [Pinniped] does) keeps raw identifiers out of object names.
//!
//! Security-relevant races are returned as outcomes, not errors; only infrastructure failures
//! are `Err`, and callers fail closed on them: an error is never treated as success. This
//! matters on k3s, where kine on SQLite has answered the losing side of a concurrent delete with
//! `500 unexpected end of JSON input` instead of `404` or `409`; the winner still got `200`.
//!
//! # References
//!
//! - [API concepts] The Kubernetes Authors, "Kubernetes API Concepts: Resource versions,"
//!   Kubernetes documentation.
//! - [DeleteOptions] The Kubernetes Authors, "`DeleteOptions`," Kubernetes API reference.
//! - [Pinniped] Pinniped project, `internal/crud/crud.go`, commit e635a39.
//!
//! [API concepts]: https://kubernetes.io/docs/reference/using-api/api-concepts/
//! [DeleteOptions]: https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/delete-options/
//! [Pinniped]: https://github.com/vmware/pinniped/tree/e635a39cf793b5b915220a846de91e089ab431c9

use std::fmt::Debug;

use kube::api::{Api, DeleteParams, PostParams, Preconditions};
use kube::core::NamespaceResourceScope;
use kube::{Resource, ResourceExt as _};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Outcome of [`create_once`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateOutcome<K> {
    /// This call created the object.
    Created(K),
    /// An object with that name already exists.
    AlreadyExists,
}

/// Outcome of [`replace_status_if_unchanged`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaceOutcome<K> {
    /// The update was applied.
    Replaced(K),
    /// The object changed since it was read.
    Conflict,
    /// The object no longer exists.
    NotFound,
}

/// Outcome of [`delete_if_unchanged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// This call deleted the object.
    Deleted,
    /// The object changed (or was replaced by a new one with the same name) since it was read.
    Changed,
    /// The object no longer exists.
    NotFound,
}

fn status_code(error: &kube::Error) -> Option<u16> {
    if let kube::Error::Api(status) = error {
        Some(status.code)
    } else {
        None
    }
}

/// Creates `object` unless an object with its name exists.
///
/// # Errors
///
/// Returns the API error for anything other than `409 AlreadyExists`.
pub async fn create_once<K>(api: &Api<K>, object: &K) -> Result<CreateOutcome<K>, kube::Error>
where
    K: Resource<Scope = NamespaceResourceScope>
        + Clone
        + Serialize
        + DeserializeOwned
        + Debug
        + Send
        + Sync,
{
    match api.create(&PostParams::default(), object).await {
        Ok(created) => Ok(CreateOutcome::Created(created)),
        Err(error) if status_code(&error) == Some(409) => Ok(CreateOutcome::AlreadyExists),
        Err(error) => Err(error),
    }
}

/// Writes `object`'s status if the stored object still has `object`'s `resourceVersion`.
///
/// # Errors
///
/// Returns the API error for anything other than `409 Conflict` or `404 Not Found`. An object
/// without a `resourceVersion` is rejected by the server as invalid, never written blindly.
pub async fn replace_status_if_unchanged<K>(
    api: &Api<K>,
    object: &K,
) -> Result<ReplaceOutcome<K>, kube::Error>
where
    K: Resource<Scope = NamespaceResourceScope>
        + Clone
        + Serialize
        + DeserializeOwned
        + Debug
        + Send
        + Sync,
{
    match api
        .replace_status(&object.name_any(), &PostParams::default(), object)
        .await
    {
        Ok(replaced) => Ok(ReplaceOutcome::Replaced(replaced)),
        Err(error) => match status_code(&error) {
            Some(409) => Ok(ReplaceOutcome::Conflict),
            Some(404) => Ok(ReplaceOutcome::NotFound),
            _ => Err(error),
        },
    }
}

/// Deletes the object `name` if it still has `uid` and `resource_version`.
///
/// # Errors
///
/// Returns the API error for anything other than `409 Conflict` (failed precondition) or
/// `404 Not Found`.
pub async fn delete_if_unchanged<K>(
    api: &Api<K>,
    name: &str,
    uid: &str,
    resource_version: &str,
) -> Result<DeleteOutcome, kube::Error>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug + Send + Sync,
{
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(uid.to_owned()),
            resource_version: Some(resource_version.to_owned()),
        }),
        ..DeleteParams::background()
    };
    match api.delete(name, &params).await {
        Ok(_) => Ok(DeleteOutcome::Deleted),
        Err(error) => match status_code(&error) {
            Some(409) => Ok(DeleteOutcome::Changed),
            Some(404) => Ok(DeleteOutcome::NotFound),
            _ => Err(error),
        },
    }
}

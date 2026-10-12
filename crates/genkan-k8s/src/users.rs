//! Owner references from a `User`'s dependents (credentials, grants, invitations) to the `User`.

use genkan_store::StoreError;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::Resource;
use kube::api::Api;

use crate::crd::user::User;

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

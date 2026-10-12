//! [`CredentialStore`] backed by `Credential` objects.

use std::collections::BTreeMap;
use std::future::Future;

use genkan_store::{
    CreateCredential, CredentialStore, NewExternal, NewPasskey, StoreError, StoredPasskey,
};
use kube::api::{Api, ObjectMeta};

use super::MANAGED_BY;
use super::objects::{CreateOutcome, create_once, user_owner};
use crate::crd::USER_LABEL;
use crate::crd::credential::{
    Credential, CredentialSpec, CredentialType, ExternalIdentity, Passkey,
};

/// Passkeys as `Credential` objects named by their credential ID.
#[derive(Clone)]
pub struct KubeCredentialStore {
    api: Api<Credential>,
}

impl std::fmt::Debug for KubeCredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KubeCredentialStore")
    }
}

impl KubeCredentialStore {
    /// Uses the given (namespaced) API.
    #[must_use]
    pub const fn new(api: Api<Credential>) -> Self {
        Self { api }
    }
}

fn backend(error: &kube::Error) -> StoreError {
    StoreError(error.to_string())
}

impl CredentialStore for KubeCredentialStore {
    fn create(
        &self,
        passkey: &NewPasskey,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send {
        let api = self.api.clone();
        let mut object = Credential {
            metadata: ObjectMeta {
                name: Some(passkey.name.clone()),
                labels: Some(BTreeMap::from([
                    (USER_LABEL.to_owned(), passkey.user.clone()),
                    (MANAGED_BY.0.to_owned(), MANAGED_BY.1.to_owned()),
                ])),
                ..ObjectMeta::default()
            },
            spec: CredentialSpec {
                user: passkey.user.clone(),
                kind: CredentialType::Passkey,
                passkey: Some(Passkey {
                    credential_id: passkey.credential_id.clone(),
                    record: passkey.record.clone(),
                    backup_eligible: false,
                    aaguid: None,
                    label: passkey.label.clone(),
                }),
                external: None,
            },
        };
        async move {
            object.metadata.owner_references =
                Some(vec![user_owner(&api, &object.spec.user).await?]);
            match create_once(&api, &object).await.map_err(|e| backend(&e))? {
                CreateOutcome::Created(_) => Ok(CreateCredential::Created),
                CreateOutcome::AlreadyExists => Ok(CreateCredential::AlreadyExists),
            }
        }
    }

    fn get(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<StoredPasskey>, StoreError>> + Send {
        let api = self.api.clone();
        let name = name.to_owned();
        async move {
            let object = api.get_opt(&name).await.map_err(|e| backend(&e))?;
            Ok(object.and_then(|object| {
                let spec = object.spec;
                spec.passkey
                    .filter(|_| spec.kind == CredentialType::Passkey)
                    .map(|passkey| StoredPasskey {
                        user: spec.user,
                        record: passkey.record,
                    })
            }))
        }
    }

    fn link(
        &self,
        external: &NewExternal,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send {
        let api = self.api.clone();
        let mut object = Credential {
            metadata: ObjectMeta {
                name: Some(external.name.clone()),
                labels: Some(BTreeMap::from([
                    (USER_LABEL.to_owned(), external.user.clone()),
                    (MANAGED_BY.0.to_owned(), MANAGED_BY.1.to_owned()),
                ])),
                ..ObjectMeta::default()
            },
            spec: CredentialSpec {
                user: external.user.clone(),
                kind: external.kind,
                passkey: None,
                external: Some(ExternalIdentity {
                    issuer: external.issuer.clone(),
                    subject: external.subject.clone(),
                }),
            },
        };
        async move {
            object.metadata.owner_references =
                Some(vec![user_owner(&api, &object.spec.user).await?]);
            match create_once(&api, &object).await.map_err(|e| backend(&e))? {
                CreateOutcome::Created(_) => Ok(CreateCredential::Created),
                CreateOutcome::AlreadyExists => Ok(CreateCredential::AlreadyExists),
            }
        }
    }

    fn linked_user(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send {
        let api = self.api.clone();
        let name = name.to_owned();
        async move {
            let object = api.get_opt(&name).await.map_err(|e| backend(&e))?;
            Ok(object
                .filter(|o| o.spec.kind != CredentialType::Passkey && o.spec.external.is_some())
                .map(|o| o.spec.user))
        }
    }
}

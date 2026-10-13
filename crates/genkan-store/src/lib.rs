#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::future::{self, Future};
use std::sync::{Mutex, PoisonError};

use genkan_core::clock::UnixTime;
use genkan_core::crypto::ct_eq;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Client type (RFC 6749 §2.1).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum ClientType {
    /// Cannot keep a secret; identifies itself with `client_id` only. Like every client, it
    /// must use PKCE.
    Public,
    /// Authenticates at the token endpoint.
    Confidential,
}

/// Kind of credential.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum CredentialType {
    /// A WebAuthn discoverable credential.
    Passkey,
    /// A GitHub account.
    GitHub,
    /// A Google account.
    Google,
}

/// A storage backend failed or answered ambiguously.
///
/// Callers fail closed: they answer `server_error` and never treat an error as success. A lost race
/// is not an error; it is an outcome such as [`CreateGrant::AlreadyExists`] or
/// [`Rotation::Replay`].
#[derive(Debug, Error, PartialEq, Eq)]
#[error("storage failed: {0}")]
pub struct StoreError(pub String);

/// A registered client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// `client_id` (the `OAuthClient` object name).
    pub id: String,
    /// Shown on the login page.
    pub display_name: Option<String>,
    /// Public or confidential.
    pub kind: ClientType,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Audiences the client may request.
    pub audiences: Vec<String>,
    /// `sha256:<hex>` of the secret, for confidential clients. The secret itself is never
    /// stored.
    pub secret_hash: Option<String>,
    /// Algorithm for this client's ID tokens.
    pub id_token_alg: genkan_keys::Algorithm,
    /// Whether the client may request the `elevate` scope. Off unless the administrator turns it
    /// on, so signing users in never implies obtaining their elevated groups.
    pub allow_elevation: bool,
}

/// A user, as needed to issue tokens.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct User {
    /// The `User` object name.
    pub name: String,
    /// Stable subject identifier: the object UID. Unique within the issuer (RFC 7519 §4.1.2),
    /// never reassigned, and never an email address.
    pub subject: String,
    /// Login name.
    pub username: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Base groups: in every access token, and in ID tokens granted the `groups` scope.
    pub groups: Vec<String>,
    /// Disabled users get no tokens.
    pub disabled: bool,
    /// Groups the user may take on after a fresh passkey sign-in. They appear only as
    /// `elevated:<group>` in short, non-refreshable tokens, never in refreshed ones.
    pub elevated_groups: Vec<String>,
}

/// Read access to clients and users.
pub trait Directory: Send + Sync + 'static {
    /// Looks up a client by `client_id`.
    fn client(&self, id: &str) -> impl Future<Output = Result<Option<Client>, StoreError>> + Send;
    /// Looks up a user by object name.
    fn user(&self, name: &str) -> impl Future<Output = Result<Option<User>, StoreError>> + Send;
    /// Looks up a user by immutable subject (the object UID), with current authorization data.
    ///
    /// Adapters may use a metadata index to locate the object, but must verify the UID of the
    /// directly read user. Ambiguous subjects fail closed.
    fn user_by_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Option<User>, StoreError>> + Send;
}

/// A refresh-token family to create.
///
/// One record per family, not per token: each rotation changes only the hashes in [`Grant`],
/// which makes reuse detection one compare-and-swap, as in Kanidm's per-session record
/// ([Kanidm]). Creating it is the first storage write of a sign-in.
///
/// [Kanidm]: https://github.com/kanidm/kanidm/tree/3331b8ed7f1541901ffe0c722f2a04c82897809c
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGrant {
    /// Object name, derived from the authorization code so a code can create at most one grant.
    pub name: String,
    /// User object name.
    pub user: String,
    /// `client_id`.
    pub client: String,
    /// Access-token audience.
    pub audience: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// OIDC `auth_time`.
    pub auth_time: UnixTime,
    /// Authentication methods.
    pub amr: Vec<String>,
    /// Absolute expiry, after which the family is dead however often it was used.
    pub expires_at: UnixTime,
    /// `sha256:<hex>` of the first refresh token.
    pub initial_hash: String,
}

/// A stored refresh-token family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The family as created.
    pub spec: NewGrant,
    /// Rotations so far.
    pub rotation: u64,
    /// Hash of the valid refresh token.
    pub current_hash: String,
    /// Hash of the previous token, kept so that its reuse is recognised as a replay rather than
    /// as an unknown token. Deleting old tokens instead makes a replay indistinguishable from an
    /// unknown token, as in Pinniped and Rauthy ([Pinniped], [Rauthy]).
    ///
    /// [Pinniped]: https://github.com/vmware/pinniped/tree/e635a39cf793b5b915220a846de91e089ab431c9
    /// [Rauthy]: https://github.com/sebadob/rauthy/tree/abd24b6d189b473178c7797787d6cbddd65df3d3
    pub previous_hash: Option<String>,
    /// Idle expiry: a family unused this long dies. Enforced when the family is read
    /// ([`classify`]); deleting it is only reclaiming space.
    pub idle_expires_at: UnixTime,
}

/// Outcome of [`GrantStore::create`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateGrant {
    /// Created.
    Created,
    /// A grant with that name exists: the code was already redeemed.
    AlreadyExists,
}

/// Outcome of [`GrantStore::rotate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotation {
    /// The presented token was current; it is now replaced.
    Rotated(Box<Grant>),
    /// The presented token was the previous one: someone used a rotated token. The caller must
    /// revoke the family (RFC 9700 §4.14.2).
    Replay,
    /// The token does not belong to this family. The caller must not revoke: a guess at a
    /// known grant name would otherwise end someone else's session.
    Invalid,
    /// The family expired.
    Expired,
    /// No such family.
    NotFound,
}

/// Refresh-token families.
pub trait GrantStore: Send + Sync + 'static {
    /// Creates a family unless one with that name exists. The name derives from the
    /// authorization code, so [`CreateGrant::AlreadyExists`] means the code was redeemed twice,
    /// possibly by another process.
    fn create(
        &self,
        grant: &NewGrant,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<CreateGrant, StoreError>> + Send;

    /// Reads a family.
    fn get(&self, name: &str) -> impl Future<Output = Result<Option<Grant>, StoreError>> + Send;

    /// Replaces the current token hash with `next_hash` if `presented_hash` is current, as one
    /// compare-and-swap. A concurrent rotation that wins first turns this call into
    /// [`Rotation::Replay`]: an adapter whose swap loses re-reads the family and classifies the
    /// presented hash again, and it is now the previous one.
    fn rotate(
        &self,
        name: &str,
        presented_hash: &str,
        next_hash: &str,
        now: UnixTime,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<Rotation, StoreError>> + Send;

    /// Deletes a family. Deleting a missing family succeeds.
    fn revoke(&self, name: &str) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Classifies a presented hash against a stored family. Shared by every backend so the security
/// outcome is identical. Hashes are compared in constant time.
#[must_use]
pub fn classify(grant: &Grant, presented_hash: &str, now: UnixTime) -> Classification {
    if now >= grant.spec.expires_at || now >= grant.idle_expires_at {
        Classification::Expired
    } else if ct_eq(presented_hash.as_bytes(), grant.current_hash.as_bytes()) {
        Classification::Current
    } else if grant
        .previous_hash
        .as_ref()
        .is_some_and(|previous| ct_eq(presented_hash.as_bytes(), previous.as_bytes()))
    {
        Classification::Previous
    } else {
        Classification::Unknown
    }
}

/// Result of [`classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// The family has expired.
    Expired,
    /// The presented token is the valid one.
    Current,
    /// The presented token was valid before the last rotation.
    Previous,
    /// The presented token is not from this family.
    Unknown,
}

/// The state after a successful rotation.
#[must_use]
pub fn rotated(grant: &Grant, next_hash: &str, idle_expires_at: UnixTime) -> Grant {
    Grant {
        spec: grant.spec.clone(),
        rotation: grant.rotation + 1,
        previous_hash: Some(grant.current_hash.clone()),
        current_hash: next_hash.to_owned(),
        idle_expires_at,
    }
}

/// In-memory directory, for tests and `--store memory`.
#[derive(Debug, Default)]
pub struct MemoryDirectory {
    clients: Mutex<HashMap<String, Client>>,
    users: Mutex<HashMap<String, User>>,
}

impl MemoryDirectory {
    /// Adds or replaces a client.
    pub fn put_client(&self, client: Client) {
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        clients.insert(client.id.clone(), client);
    }

    /// Adds or replaces a user.
    pub fn put_user(&self, user: User) {
        let mut users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        users.insert(user.name.clone(), user);
    }

    /// Removes a user.
    pub fn remove_user(&self, name: &str) {
        let mut users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        users.remove(name);
    }
}

impl Directory for MemoryDirectory {
    fn client(&self, id: &str) -> impl Future<Output = Result<Option<Client>, StoreError>> + Send {
        let clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(clients.get(id).cloned()))
    }

    fn user(&self, name: &str) -> impl Future<Output = Result<Option<User>, StoreError>> + Send {
        let users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(users.get(name).cloned()))
    }

    fn user_by_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Option<User>, StoreError>> + Send {
        let users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        let mut matches = users.values().filter(|user| user.subject == subject);
        let user = matches.next().cloned();
        let result = if matches.next().is_some() {
            Err(StoreError("ambiguous user subject".to_owned()))
        } else {
            Ok(user)
        };
        drop(users);
        future::ready(result)
    }
}

/// In-memory grant store, for tests and `--store memory`.
#[derive(Debug, Default)]
pub struct MemoryGrantStore {
    grants: Mutex<HashMap<String, Grant>>,
}

impl MemoryGrantStore {
    fn create_now(&self, grant: &NewGrant, idle_expires_at: UnixTime) -> CreateGrant {
        let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        if grants.contains_key(&grant.name) {
            return CreateGrant::AlreadyExists;
        }
        grants.insert(
            grant.name.clone(),
            Grant {
                spec: grant.clone(),
                rotation: 0,
                current_hash: grant.initial_hash.clone(),
                previous_hash: None,
                idle_expires_at,
            },
        );
        CreateGrant::Created
    }

    fn rotate_now(
        &self,
        name: &str,
        presented_hash: &str,
        next_hash: &str,
        now: UnixTime,
        idle_expires_at: UnixTime,
    ) -> Rotation {
        let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = match grants
            .get(name)
            .map(|g| (classify(g, presented_hash, now), g.clone()))
        {
            None => Rotation::NotFound,
            Some((Classification::Expired, _)) => Rotation::Expired,
            Some((Classification::Previous, _)) => Rotation::Replay,
            Some((Classification::Unknown, _)) => Rotation::Invalid,
            Some((Classification::Current, grant)) => {
                let next = rotated(&grant, next_hash, idle_expires_at);
                grants.insert(name.to_owned(), next.clone());
                Rotation::Rotated(Box::new(next))
            }
        };
        drop(grants);
        outcome
    }
}

impl GrantStore for MemoryGrantStore {
    fn create(
        &self,
        grant: &NewGrant,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<CreateGrant, StoreError>> + Send {
        future::ready(Ok(self.create_now(grant, idle_expires_at)))
    }

    fn get(&self, name: &str) -> impl Future<Output = Result<Option<Grant>, StoreError>> + Send {
        let grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(grants.get(name).cloned()))
    }

    fn rotate(
        &self,
        name: &str,
        presented_hash: &str,
        next_hash: &str,
        now: UnixTime,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<Rotation, StoreError>> + Send {
        future::ready(Ok(self.rotate_now(
            name,
            presented_hash,
            next_hash,
            now,
            idle_expires_at,
        )))
    }

    fn revoke(&self, name: &str) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.grants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
        future::ready(Ok(()))
    }
}

/// A passkey to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskey {
    /// Object name (see [`passkey_credential_name`]).
    pub name: String,
    /// `User` object name.
    pub user: String,
    /// Credential ID, base64url.
    pub credential_id: String,
    /// The serialized relying-party credential record (public key and flags).
    pub record: String,
    /// User-chosen label.
    pub label: Option<String>,
}

/// An upstream account to link to a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewExternal {
    /// Object name (see [`external_credential_name`]).
    pub name: String,
    /// `User` object name.
    pub user: String,
    /// The provider.
    pub kind: CredentialType,
    /// Upstream issuer.
    pub issuer: String,
    /// Upstream subject: the stable account ID.
    pub subject: String,
}

/// The `Credential` name for a passkey credential ID.
///
/// Deterministic, so a duplicate registration fails with `AlreadyExists`, even across replicas:
/// WebAuthn Level 3 §7.1 says that if the credential ID "is already known then the Relying Party
/// SHOULD fail this registration ceremony".
#[must_use]
pub fn passkey_credential_name(credential_id: &[u8]) -> String {
    let mut input = b"genkan/passkey/v1/".to_vec();
    input.extend_from_slice(credential_id);
    format!(
        "c-{}",
        genkan_core::crypto::hex(&genkan_core::crypto::sha256(&input))
    )
}

/// The `Credential` name for an upstream account. Derived from the issuer and subject, so finding
/// the user is a single read and linking one account twice fails with `AlreadyExists`.
#[must_use]
pub fn external_credential_name(issuer: &str, subject: &str) -> String {
    let mut input = b"genkan/external/v1/".to_vec();
    input.extend_from_slice(issuer.as_bytes());
    input.push(0);
    input.extend_from_slice(subject.as_bytes());
    format!(
        "c-{}",
        genkan_core::crypto::hex(&genkan_core::crypto::sha256(&input))
    )
}

/// A stored passkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPasskey {
    /// `User` object name.
    pub user: String,
    /// The serialized credential record.
    pub record: String,
}

/// Outcome of [`CredentialStore::create`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateCredential {
    /// Stored.
    Created,
    /// The credential ID is already registered (WebAuthn Level 3 §7.1).
    AlreadyExists,
}

/// Passkeys and linked identities.
pub trait CredentialStore: Send + Sync + 'static {
    /// Stores a passkey unless its credential ID is already registered.
    fn create(
        &self,
        passkey: &NewPasskey,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send;
    /// Reads a passkey by object name.
    fn get(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<StoredPasskey>, StoreError>> + Send;
    /// Links an upstream account unless it is linked already (to anyone).
    fn link(
        &self,
        external: &NewExternal,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send;
    /// The `User` object name an upstream account (by credential name) signs in as.
    fn linked_user(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send;
}

/// The pending setup token: who it is for, its hash and expiry, and the stored version that a
/// redemption must consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupToken {
    /// `User` object name the token enrols a passkey for.
    pub user: String,
    /// `sha256:<hex>` of the token.
    pub token_hash: String,
    /// Expiry.
    pub expires_at: UnixTime,
    /// Opaque version, consumed atomically.
    pub version: String,
}

/// Outcome of [`SetupStore::consume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consume {
    /// This call consumed the token.
    Consumed,
    /// The token was consumed or replaced by someone else.
    AlreadyUsed,
}

/// One-time enrolment tokens: the cluster admin's setup token, and invitations.
///
/// A presented token `<name>.<secret>` refers to the invitation `<name>`; any other token refers
/// to the setup token. Base64url setup tokens never contain a dot.
pub trait SetupStore: Send + Sync + 'static {
    /// Reads the stored token that `presented` refers to, if any. The caller compares hashes.
    fn load(
        &self,
        presented: &str,
    ) -> impl Future<Output = Result<Option<SetupToken>, StoreError>> + Send;
    /// Consumes `token` if it is still the stored version. Exactly one concurrent caller wins,
    /// so two simultaneous redemptions cannot both enrol a passkey. Pocket ID once let
    /// concurrent setup requests create several administrators (GHSA-x6w5-6mr5-mxrx).
    fn consume(
        &self,
        token: &SetupToken,
    ) -> impl Future<Output = Result<Consume, StoreError>> + Send;
}

/// In-memory credentials, for tests and `--store memory`.
#[derive(Debug, Default)]
pub struct MemoryCredentialStore {
    passkeys: Mutex<HashMap<String, StoredPasskey>>,
    externals: Mutex<HashMap<String, String>>,
}

impl CredentialStore for MemoryCredentialStore {
    fn create(
        &self,
        passkey: &NewPasskey,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send {
        let mut passkeys = self.passkeys.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = if passkeys.contains_key(&passkey.name) {
            CreateCredential::AlreadyExists
        } else {
            passkeys.insert(
                passkey.name.clone(),
                StoredPasskey {
                    user: passkey.user.clone(),
                    record: passkey.record.clone(),
                },
            );
            CreateCredential::Created
        };
        drop(passkeys);
        future::ready(Ok(outcome))
    }

    fn get(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<StoredPasskey>, StoreError>> + Send {
        let passkeys = self.passkeys.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(passkeys.get(name).cloned()))
    }

    fn link(
        &self,
        external: &NewExternal,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send {
        let mut externals = self
            .externals
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let outcome = if externals.contains_key(&external.name) {
            CreateCredential::AlreadyExists
        } else {
            externals.insert(external.name.clone(), external.user.clone());
            CreateCredential::Created
        };
        drop(externals);
        future::ready(Ok(outcome))
    }

    fn linked_user(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send {
        let externals = self
            .externals
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(externals.get(name).cloned()))
    }
}

/// The invitation name in a presented `<name>.<secret>` token, if it is one.
#[must_use]
pub fn invitation_name(presented: &str) -> Option<&str> {
    let (name, secret) = presented.split_once('.')?;
    let label = !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    (label && !secret.is_empty()).then_some(name)
}

/// In-memory setup token and invitations, for tests and `--store memory`.
#[derive(Debug, Default)]
pub struct MemorySetupStore {
    token: Mutex<Option<SetupToken>>,
    invitations: Mutex<HashMap<String, SetupToken>>,
}

impl MemorySetupStore {
    /// Adds an invitation, as `genkanctl invite` would.
    pub fn put_invitation(&self, name: &str, user: &str, token_hash: &str, expires_at: UnixTime) {
        let token = SetupToken {
            user: user.to_owned(),
            token_hash: token_hash.to_owned(),
            expires_at,
            version: format!("invitation/{name}"),
        };
        self.invitations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), token);
    }

    /// Replaces the token, as the admin CLI would.
    pub fn put(&self, user: &str, token_hash: &str, expires_at: UnixTime) {
        let mut slot = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        let version = slot
            .as_ref()
            .map_or(1, |t| t.version.parse::<u64>().unwrap_or(0) + 1);
        *slot = Some(SetupToken {
            user: user.to_owned(),
            token_hash: token_hash.to_owned(),
            expires_at,
            version: version.to_string(),
        });
    }
}

impl SetupStore for MemorySetupStore {
    fn load(
        &self,
        presented: &str,
    ) -> impl Future<Output = Result<Option<SetupToken>, StoreError>> + Send {
        if let Some(name) = invitation_name(presented) {
            let invitations = self
                .invitations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            return future::ready(Ok(invitations.get(name).cloned()));
        }
        let slot = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(slot.clone()))
    }

    fn consume(
        &self,
        token: &SetupToken,
    ) -> impl Future<Output = Result<Consume, StoreError>> + Send {
        if let Some(name) = token.version.strip_prefix("invitation/") {
            let mut invitations = self
                .invitations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let outcome = if invitations.remove(name).is_some() {
                Consume::Consumed
            } else {
                Consume::AlreadyUsed
            };
            drop(invitations);
            return future::ready(Ok(outcome));
        }
        let mut slot = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = if slot.as_ref().is_some_and(|t| t.version == token.version) {
            *slot = None;
            Consume::Consumed
        } else {
            Consume::AlreadyUsed
        };
        drop(slot);
        future::ready(Ok(outcome))
    }
}

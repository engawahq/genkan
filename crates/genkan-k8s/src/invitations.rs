//! Invitations: the admin's side (`genkanctl invite`). Genkan's server mails links for
//! invitations that name an address.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use genkan_core::clock::UnixTime;
use genkan_core::config::BaseUrl;
use genkan_core::crypto::{hash_secret, hex, random};
use kube::api::{Api, ObjectMeta, PostParams};
use kube::{Client, Resource as _, ResourceExt as _};
use thiserror::Error;

use super::MANAGED_BY;
use crate::crd::invitation::{Invitation, InvitationSpec};
use crate::crd::user::{User, UserSpec};
use crate::crd::{EXPIRES_AT_ANNOTATION, EXPIRY_BUCKET_LABEL, USER_LABEL};

/// Path of the enrolment page; the token goes in the fragment.
pub const ENROL_PATH: &str = "/setup";

/// Why an invitation could not be created.
#[derive(Debug, Error)]
pub enum InviteError {
    /// The Kubernetes API failed (often: the kubeconfig lacks the rights).
    #[error("Kubernetes API: {0}")]
    Kubernetes(#[from] kube::Error),
    /// Randomness failed.
    #[error("generating the token failed")]
    Crypto,
}

/// Who to invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitee {
    /// Login name; also the `User` object name.
    pub username: String,
    /// Display name, for a new user.
    pub display_name: Option<String>,
    /// Groups, for a new user.
    pub groups: Vec<String>,
    /// Elevated groups, for a new user.
    pub elevated_groups: Vec<String>,
    /// Mail the link here instead of returning it.
    pub email: Option<String>,
    /// Language of the mail.
    pub language: Option<String>,
}

/// What was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invited {
    /// The `Invitation` object name.
    pub name: String,
    /// The link, unless Genkan will mail it.
    pub url: Option<String>,
    /// Whether the `User` was created now.
    pub created_user: bool,
    /// When the link stops working.
    pub expires_at: UnixTime,
}

/// A fresh `<name>.<secret>` token.
///
/// # Errors
///
/// Returns [`InviteError::Crypto`] if randomness fails.
pub fn new_token(name: &str) -> Result<String, InviteError> {
    let secret = random::<32>().map_err(|_crypto| InviteError::Crypto)?;
    Ok(format!("{name}.{}", URL_SAFE_NO_PAD.encode(secret)))
}

/// The enrolment link for `token`.
#[must_use]
pub fn link(issuer: &BaseUrl, token: &str) -> String {
    format!("{}#token={token}", issuer.join(ENROL_PATH))
}

/// Creates the user (if missing) and an invitation, with the caller's (admin's) credentials.
///
/// # Errors
///
/// [`InviteError`] if an API call fails.
pub async fn invite(
    client: Client,
    namespace: &str,
    issuer: &BaseUrl,
    invitee: &Invitee,
    valid_for: Duration,
    now: UnixTime,
) -> Result<Invited, InviteError> {
    let pp = PostParams::default();
    let users: Api<User> = Api::namespaced(client.clone(), namespace);
    let (user, created_user) = if let Some(user) = users.get_opt(&invitee.username).await? {
        (user, false)
    } else {
        let user = User::new(
            &invitee.username,
            UserSpec {
                username: invitee.username.clone(),
                display_name: invitee.display_name.clone(),
                groups: invitee.groups.clone(),
                elevated_groups: invitee.elevated_groups.clone(),
                ..UserSpec::default()
            },
        );
        (users.create(&pp, &user).await?, true)
    };

    let name = format!(
        "inv-{}",
        hex(&random::<8>().map_err(|_crypto| InviteError::Crypto)?)
    );
    let expires_at = now.saturating_add(valid_for);
    let token = match invitee.email {
        Some(_) => None,
        None => Some(new_token(&name)?),
    };
    let invitation = Invitation {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(namespace.to_owned()),
            owner_references: user.owner_ref(&()).map(|owner| vec![owner]),
            labels: Some(BTreeMap::from([
                (MANAGED_BY.0.to_owned(), MANAGED_BY.1.to_owned()),
                (USER_LABEL.to_owned(), invitee.username.clone()),
                (
                    EXPIRY_BUCKET_LABEL.to_owned(),
                    (expires_at.as_secs() / 3600).to_string(),
                ),
            ])),
            annotations: Some(BTreeMap::from([(
                EXPIRES_AT_ANNOTATION.to_owned(),
                expires_at.as_secs().to_string(),
            )])),
            ..ObjectMeta::default()
        },
        spec: InvitationSpec {
            user: invitee.username.clone(),
            email: invitee.email.clone(),
            token_hash: token.as_deref().map(|t| hash_secret(t.as_bytes())),
            language: invitee.language.clone(),
            expires_at: i64::try_from(expires_at.as_secs()).unwrap_or(i64::MAX),
        },
        status: None,
    };
    let invitations: Api<Invitation> = Api::namespaced(client, namespace);
    let created = invitations.create(&pp, &invitation).await?;
    Ok(Invited {
        name: created.name_any(),
        url: token.map(|token| link(issuer, &token)),
        created_user,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_name_their_invitation() {
        let token = new_token("inv-abc").unwrap();
        let (name, secret) = token.split_once('.').unwrap();
        assert_eq!(name, "inv-abc");
        assert_eq!(secret.len(), 43);
        assert_eq!(genkan_store::invitation_name(&token), Some("inv-abc"));
    }
}

//! Authorization codes: sealed, self-contained, single-use, 60 seconds.
//!
//! A code carries everything the token endpoint needs, encrypted and authenticated under the
//! process key with [`PURPOSE`] as associated data (so a sealed flow or PAR value cannot pass as
//! a code). Issuing one writes nothing; Kanidm's stateless encrypted codes work the same way,
//! whereas a stored code costs a write per sign-in ([Kanidm], [Dex]).
//!
//! The token endpoint checks expiry, client, `redirect_uri` and the PKCE verifier first, and
//! only then records the code's random 128-bit id in [`super::OneTimeIds`]. Checking PKCE first
//! means a stolen code without its verifier cannot be burnt to lock out the legitimate client.
//!
//! The code's [`grant_name`] is deterministic. A second redemption in this process finds the
//! name in the single-use set and revokes that grant; a redemption racing in another process
//! fails to create the grant (`AlreadyExists`) and revokes it too. Either way RFC 6749 §4.1.2 is
//! met: the reuse is denied and what the code issued is revoked. Redeeming a code is the first
//! storage write of a sign-in.
//!
//! The key exists only in this process: a restart, or a code presented to another replica,
//! fails closed with `invalid_grant`.
//!
//! [Kanidm]: https://github.com/kanidm/kanidm/tree/3331b8ed7f1541901ffe0c722f2a04c82897809c
//! [Dex]: https://github.com/dexidp/dex/tree/05a275057112ba93e17db21f600b756f000f1c21

use genkan_core::clock::UnixTime;
use genkan_core::crypto::{CryptoError, Sealer, hex, random, sha256};
use serde::{Deserialize, Serialize};

use super::authorize::{Authentication, AuthorizationRequest};

/// Associated data for sealed codes.
pub const PURPOSE: &str = "genkan/code/v1";

/// The contents of a code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeClaims {
    /// Random identifier (128 bits, hex): the single-use key. The guessing bound of
    /// RFC 6749 §10.10 is met by the AEAD itself; the id only needs to be unique.
    pub id: String,
    /// The request the user approved.
    pub request: AuthorizationRequest,
    /// Original authenticated user incarnation.
    pub user: genkan_store::UserReference,
    /// When the user authenticated.
    pub auth_time: UnixTime,
    /// Authentication methods.
    pub amr: Vec<String>,
    /// Expiry.
    pub expires_at: UnixTime,
}

/// Issues a code for `request` after `authentication`.
///
/// # Errors
///
/// Returns [`CryptoError`] if randomness or sealing fails.
pub fn issue(
    sealer: &Sealer,
    request: AuthorizationRequest,
    authentication: Authentication,
    expires_at: UnixTime,
) -> Result<String, CryptoError> {
    let claims = CodeClaims {
        id: hex(&random::<16>()?),
        request,
        user: authentication.user,
        auth_time: authentication.auth_time,
        amr: authentication.amr,
        expires_at,
    };
    let json = serde_json::to_vec(&claims).map_err(|_serialize| CryptoError)?;
    sealer.seal(PURPOSE, &json)
}

/// Opens a code. `None` for anything not issued by this process.
#[must_use]
pub fn open(sealer: &Sealer, code: &str) -> Option<CodeClaims> {
    serde_json::from_slice(&sealer.open(PURPOSE, code)?).ok()
}

/// Name of the `Grant` a code creates: deterministic, so a code can create at most one grant,
/// and a replayed code identifies the grant to revoke (RFC 6749 §4.1.2).
#[must_use]
pub fn grant_name(code_id: &str) -> String {
    format!(
        "g-{}",
        hex(&sha256(format!("genkan/grant/v1/{code_id}").as_bytes()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: "kubectl".into(),
            redirect_uri: "http://127.0.0.1:8000/".into(),
            scopes: vec!["openid".into()],
            state: None,
            nonce: Some("n".into()),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
            audience: "kubernetes".into(),
            force_login: false,
            max_age: None,
            login_hint: None,
        }
    }

    #[test]
    fn codes_round_trip_and_are_unique() {
        let sealer = Sealer::ephemeral().unwrap();
        let auth = Authentication {
            user: genkan_store::UserReference {
                name: "alice".into(),
                uid: "uid-alice".into(),
            },
            auth_time: UnixTime::from_secs(5),
            amr: vec!["hwk".into()],
        };
        let a = issue(&sealer, request(), auth.clone(), UnixTime::from_secs(65)).unwrap();
        let b = issue(&sealer, request(), auth, UnixTime::from_secs(65)).unwrap();
        let (ca, cb) = (open(&sealer, &a).unwrap(), open(&sealer, &b).unwrap());
        assert_ne!(ca.id, cb.id);
        assert_eq!(ca.request, request());
        assert_ne!(grant_name(&ca.id), grant_name(&cb.id));
        assert!(grant_name(&ca.id).starts_with("g-") && grant_name(&ca.id).len() == 66);
        assert!(
            open(&Sealer::ephemeral().unwrap(), &a).is_none(),
            "another process cannot open it"
        );
    }
}

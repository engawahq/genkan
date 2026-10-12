#![doc = include_str!("../README.md")]

pub mod authorize;
pub mod client_auth;
pub mod code;
pub mod discovery;
pub mod endpoints;
pub mod error;
pub mod metadata;
pub mod params;
pub mod pkce;
pub mod refresh;
pub mod tokens;
pub mod userinfo;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use genkan_core::clock::{Clock, UnixTime};
use genkan_core::config::BaseUrl;
use genkan_core::crypto::Sealer;
use genkan_keys::manager::PublishedKeys;
use genkan_store::{Directory, GrantStore};

/// Lifetimes of everything the authorization server issues.
///
/// Access and ID tokens are short because kube-apiserver verifies them offline and caches the
/// result: nothing issued can be revoked, so the token lifetime is the revocation latency.
/// Long sessions come from refresh tokens instead, which can be revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetimes {
    /// Pending sign-in (the sealed authorization request).
    pub flow: Duration,
    /// Authorization code. RFC 6749 §4.1.2 recommends at most 10 minutes.
    pub code: Duration,
    /// PAR `request_uri` (RFC 9126 §2.2 suggests 5 to 600 seconds).
    pub par: Duration,
    /// Access token. kube-apiserver cannot revoke it, so it is short.
    pub access_token: Duration,
    /// ID token.
    pub id_token: Duration,
    /// A refresh-token family dies if unused this long.
    pub refresh_idle: Duration,
    /// A refresh-token family dies this long after sign-in, regardless of use.
    pub refresh_absolute: Duration,
    /// Tokens carrying elevated groups (the `elevate` scope). They have no refresh token, so
    /// this bounds how long privilege lasts after a passkey sign-in. `None` disables elevation;
    /// the `genkan` server always enables it.
    pub elevated_token: Option<Duration>,
}

impl Lifetimes {
    /// The defaults: codes and PAR request URIs 60 s, pending sign-ins 10 min, access and ID
    /// tokens 10 min, elevated tokens 5 min, refresh families 4 h idle and 12 h absolute.
    pub const DEFAULT: Self = Self {
        flow: Duration::from_mins(10),
        code: Duration::from_mins(1),
        par: Duration::from_mins(1),
        access_token: Duration::from_mins(10),
        id_token: Duration::from_mins(10),
        refresh_idle: Duration::from_hours(4),
        refresh_absolute: Duration::from_hours(12),
        elevated_token: Some(Duration::from_mins(5)),
    };

    /// The longest lifetime of any signed token, which signing keys must outlive.
    #[must_use]
    pub fn longest_signed_token(&self) -> Duration {
        self.access_token
            .max(self.id_token)
            .max(self.elevated_token.unwrap_or_default())
    }
}

/// Everything the endpoints share.
#[derive(Debug)]
pub struct AuthorizationServer<D, G, C> {
    /// Issuer identifier.
    pub issuer: BaseUrl,
    /// Lifetimes.
    pub lifetimes: Lifetimes,
    /// Clients and users.
    pub directory: D,
    /// Refresh-token families.
    pub grants: G,
    /// Time source.
    pub clock: C,
    /// Signing keys.
    pub keys: PublishedKeys,
    /// Seals flows, codes and PAR request URIs. Its key exists only in this process, so a restart
    /// invalidates everything in flight (fail closed).
    pub sealer: Sealer,
    /// Per-code ordering and single-use state, retained until codes expire.
    pub used_codes: CodeRedemptions,
    /// PAR request URIs used so far, until they expire (one-time use, RFC 9126 §4).
    pub used_request_uris: OneTimeIds,
}

impl<D: Directory, G: GrantStore, C: Clock> AuthorizationServer<D, G, C> {
    /// The current time.
    pub fn now(&self) -> UnixTime {
        self.clock.now()
    }
}

/// Outcome of [`OneTimeIds::first_use`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Use {
    /// The identifier had not been seen.
    First,
    /// The identifier was used before; carries what was recorded at first use.
    Again(String),
}

/// A set of single-use identifiers that remembers each one until it expires.
///
/// Used for PAR request URIs: the sealing key is per-process, so this in-memory set is complete
/// for everything this process can open. Memory is bounded by redemptions within one URI
/// lifetime, and nothing is written to storage.
#[derive(Debug, Default)]
pub struct OneTimeIds {
    seen: Mutex<HashMap<String, (UnixTime, String)>>,
}

impl OneTimeIds {
    /// Records `id` with `note` unless already present. Entries past `expires_at` are dropped
    /// first; they can no longer be presented because the sealed value has expired too.
    pub fn first_use(&self, id: &str, expires_at: UnixTime, note: &str, now: UnixTime) -> Use {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, (expiry, _)| *expiry > now);
        if let Some((_, recorded)) = seen.get(id) {
            return Use::Again(recorded.clone());
        }
        seen.insert(id.to_owned(), (expires_at, note.to_owned()));
        Use::First
    }
}

/// Orders redemption and replay of each code without blocking unrelated codes.
///
/// A replay must wait for the first grant creation to finish before deleting its family
/// ([RFC 6749 §4.1.2]). The endpoint keeps this lock in a detached task so cancellation of the
/// HTTP request cannot release it while a storage operation is pending. Runtime shutdown still
/// cancels tasks; the process-local sealing key then disappears, so old codes cannot reopen.
///
/// Expired entries with active holders or waiters are retained until those operations finish.
/// No global lock is held across an await. Memory is bounded by unexpired codes plus unfinished
/// operations.
///
/// [RFC 6749 §4.1.2]: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
#[derive(Debug, Default)]
pub struct CodeRedemptions {
    entries: Mutex<HashMap<String, CodeEntry>>,
}

#[derive(Debug)]
struct CodeEntry {
    expires_at: UnixTime,
    redeemed: Arc<tokio::sync::Mutex<bool>>,
}

impl CodeRedemptions {
    /// The single-use state and operation lock for one authenticated, unexpired code.
    pub(crate) fn entry(
        &self,
        id: &str,
        expires_at: UnixTime,
        now: UnixTime,
    ) -> Arc<tokio::sync::Mutex<bool>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|_, entry| entry.expires_at > now || Arc::strong_count(&entry.redeemed) > 1);
        Arc::clone(
            &entries
                .entry(id.to_owned())
                .or_insert_with(|| CodeEntry {
                    expires_at,
                    redeemed: Arc::new(tokio::sync::Mutex::new(false)),
                })
                .redeemed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_time_ids() {
        let ids = OneTimeIds::default();
        let t = UnixTime::from_secs;
        assert_eq!(ids.first_use("a", t(100), "grant-a", t(0)), Use::First);
        assert_eq!(
            ids.first_use("a", t(100), "other", t(50)),
            Use::Again("grant-a".into())
        );
        assert_eq!(ids.first_use("b", t(100), "", t(50)), Use::First);
        // After expiry the entry is forgotten; the sealed value it guarded has expired as well.
        assert_eq!(ids.first_use("a", t(200), "", t(100)), Use::First);
    }
}

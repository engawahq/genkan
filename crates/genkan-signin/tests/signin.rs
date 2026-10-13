//! End-to-end tests of passkey enrolment and sign-in, with a software authenticator (the
//! `passkey` crates) standing in for the browser and the user's device.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, Method, Request, StatusCode, header};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use genkan_core::clock::{Clock, UnixTime};
    use genkan_core::config::BaseUrl;
    use genkan_core::crypto::{Sealer, hash_secret};
    use genkan_keys::Algorithm;
    use genkan_keys::manager::KeyManager;
    use genkan_keys::rotation::RotationPolicy;
    use genkan_keys::store::MemoryKeyStore;
    use genkan_oauth::endpoints::{self, FLOW_COOKIE};
    use genkan_oauth::{AuthorizationServer, Lifetimes, OneTimeIds};
    use genkan_signin::passkeys::Passkeys;
    use genkan_signin::{CEREMONY_COOKIE, SignIn};
    use genkan_store::{
        Client, ClientType, MemoryCredentialStore, MemoryDirectory, MemoryGrantStore,
        MemorySetupStore, User,
    };
    use genkan_test_support::logging::Capture;
    use genkan_test_support::{Device, device};
    use http_body_util::BodyExt as _;
    use passkey::authenticator::{Authenticator, UiHint, UserCheck, UserValidationMethod};
    use passkey::client::{Client as PasskeyClient, DefaultClientData};
    use passkey::types::ctap2::{Aaguid, Ctap2Error};
    use passkey::types::webauthn::{CredentialCreationOptions, CredentialRequestOptions};
    use serde_json::{Value, json};
    use tokio::sync::Barrier;
    use tower::ServiceExt as _;
    use tracing::instrument::WithSubscriber as _;
    use url::Url;

    const ISSUER: &str = "https://login.example.com";
    const SETUP_TOKEN: &str = "setup-token-with-plenty-of-entropy-for-tests";
    const ADMIN_UID: &str = "5b0c7a7e-3f4b-4c1e-9a52-0d6f4b8a1c11";
    const START: u64 = 1_800_000_000;
    const INVITATION: &str = "inv-1.invitation-secret-with-plenty-of-entropy";
    const DANA_UID: &str = "8d2f1c3a-5b6e-4f70-8a91-b2c3d4e5f607";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /// A device that only tests presence: no PIN, no biometric.
    struct PresenceOnly;

    #[async_trait::async_trait]
    impl UserValidationMethod for PresenceOnly {
        type PasskeyItem = passkey::types::Passkey;

        async fn check_user<'a>(
            &self,
            _hint: UiHint<'a, Self::PasskeyItem>,
            presence: bool,
            _verification: bool,
        ) -> Result<UserCheck, Ctap2Error> {
            Ok(UserCheck {
                presence,
                verification: false,
            })
        }

        fn is_presence_enabled(&self) -> bool {
            true
        }

        fn is_verification_enabled(&self) -> Option<bool> {
            Some(false)
        }
    }

    #[derive(Debug, Clone, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl Clock for TestClock {
        fn now(&self) -> UnixTime {
            UnixTime::from_secs(self.0.load(Ordering::SeqCst))
        }
    }

    type Server = AuthorizationServer<MemoryDirectory, MemoryGrantStore, TestClock>;
    type Service = SignIn<
        MemoryDirectory,
        MemoryGrantStore,
        TestClock,
        MemoryCredentialStore,
        MemorySetupStore,
    >;

    struct Harness {
        app: Router,
        service: Arc<Service>,
        clock: TestClock,
    }

    async fn harness() -> Harness {
        let clock = TestClock::default();
        clock.0.store(START, Ordering::SeqCst);
        let manager = KeyManager::new(
            MemoryKeyStore::default(),
            clock.clone(),
            RotationPolicy::DEFAULT,
        );
        manager.reconcile().await.unwrap();
        let directory = MemoryDirectory::default();
        directory.put_client(Client {
            id: "kubectl".into(),
            display_name: None,
            kind: ClientType::Public,
            redirect_uris: vec!["http://127.0.0.1:8000/".into()],
            audiences: vec!["kubernetes".into()],
            secret_hash: None,
            id_token_alg: Algorithm::Es256,
        });
        directory.put_user(User {
            name: "admin".into(),
            subject: ADMIN_UID.into(),
            username: "admin".into(),
            display_name: Some("Cluster admin".into()),
            groups: vec!["admins".into()],
            disabled: false,
            ..User::default()
        });
        directory.put_user(User {
            name: "dana".into(),
            subject: DANA_UID.into(),
            username: "dana".into(),
            groups: vec!["dev".into()],
            ..User::default()
        });
        let issuer = BaseUrl::parse("issuer", ISSUER).unwrap();
        let oauth: Arc<Server> = Arc::new(AuthorizationServer {
            issuer: issuer.clone(),
            lifetimes: Lifetimes::DEFAULT,
            directory,
            grants: MemoryGrantStore::default(),
            clock: clock.clone(),
            keys: manager.subscribe(),
            sealer: Sealer::ephemeral().unwrap(),
            used_codes: OneTimeIds::default(),
            used_request_uris: OneTimeIds::default(),
        });
        let setup = MemorySetupStore::default();
        setup.put_invitation(
            "inv-1",
            "dana",
            &hash_secret(INVITATION.as_bytes()),
            UnixTime::from_secs(START + 3600),
        );
        setup.put(
            "admin",
            &hash_secret(SETUP_TOKEN.as_bytes()),
            UnixTime::from_secs(START + 3600),
        );
        let service = Arc::new(SignIn {
            oauth: Arc::clone(&oauth),
            passkeys: Passkeys::new(&issuer).unwrap(),
            credentials: MemoryCredentialStore::default(),
            setup,
            used_ceremonies: OneTimeIds::default(),
        });
        let app = endpoints::router(oauth).merge(genkan_signin::router(Arc::clone(&service)));
        Harness {
            app,
            service,
            clock,
        }
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Value,
        audit: Option<Value>,
        diagnostics: Vec<Value>,
    }

    impl Reply {
        fn cookie(&self, name: &str) -> Option<String> {
            self.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .find_map(|v| {
                    let v = v.to_str().ok()?;
                    let value = v.strip_prefix(&format!("{name}="))?.split(';').next()?;
                    (!value.is_empty()).then(|| value.to_owned())
                })
        }
        fn kind(&self) -> String {
            self.body["type"].as_str().unwrap_or_default().to_owned()
        }
    }

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        body: Option<Value>,
        cookies: &[(&str, &str)],
        origin: Option<&str>,
    ) -> Reply {
        let capture = Capture::new();
        let submitted = body.clone();
        let mut request = Request::builder().method(method).uri(path);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        if !cookies.is_empty() {
            let cookie = cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header(header::COOKIE, cookie);
        }
        let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
        let response = app
            .clone()
            .oneshot(request.body(body).unwrap())
            .with_subscriber(capture.dispatch())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let response_body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let records = capture.records();
        let audit: Vec<_> = records
            .iter()
            .filter(|r| r["target"] == "genkan::audit")
            .collect();
        let operation = match path {
            "/setup/options" => Some(("auth.passkey_enrollment", Some("start"))),
            "/setup" => Some(("auth.passkey_enrollment", Some("finish"))),
            "/login/options" => Some(("auth.passkey_options", None)),
            "/login" => Some(("auth.sign_in", None)),
            _ => None,
        };
        if let Some((event, phase)) = operation {
            assert_eq!(audit.len(), 1, "{records:?}");
            let fields = &audit[0]["fields"];
            assert_eq!(fields["event"], event);
            assert_eq!(fields["method"], "passkey");
            assert_eq!(
                fields["outcome"],
                if parts.status.is_success() {
                    "success"
                } else {
                    "failure"
                }
            );
            if let Some(phase) = phase {
                assert_eq!(fields["phase"], phase);
            }
            if !parts.status.is_success() {
                assert_eq!(
                    fields["reason"],
                    response_body["type"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("urn:genkan:problem:")
                        .unwrap()
                );
            }
            assert!(fields.get("client").is_none());
        }
        let serialized = serde_json::to_string(&audit).unwrap();
        for (_, secret) in cookies {
            assert!(!serialized.contains(secret), "cookie leaked");
        }
        if let Some(submitted) = &submitted {
            assert_secret_values_absent(&serialized, submitted);
        }
        assert_secret_values_absent(&serialized, &response_body);
        for value in parts.headers.get_all(header::SET_COOKIE) {
            let cookie = value.to_str().unwrap().split(';').next().unwrap();
            let secret = cookie.split_once('=').unwrap().1;
            if !secret.is_empty() {
                assert!(!serialized.contains(secret), "response cookie leaked");
            }
        }
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: response_body,
            audit: audit.first().map(|r| (*r).clone()),
            diagnostics: records
                .into_iter()
                .filter(|record| record["target"] == "genkan_signin")
                .collect(),
        }
    }

    fn assert_secret_values_absent(records: &str, value: &Value) {
        if let Value::Object(fields) = value {
            for (key, value) in fields {
                if matches!(
                    key.as_str(),
                    "token"
                        | "id"
                        | "rawId"
                        | "clientDataJSON"
                        | "authenticatorData"
                        | "signature"
                        | "attestationObject"
                        | "userHandle"
                        | "challenge"
                        | "access_token"
                        | "id_token"
                        | "refresh_token"
                ) && let Some(secret) = value.as_str().filter(|s| !s.is_empty())
                {
                    assert!(!records.contains(secret), "{key} leaked");
                }
                assert_secret_values_absent(records, value);
            }
        }
        if let Some(location) = value.get("redirect_to").and_then(Value::as_str)
            && let Some((_, query)) = location.split_once('?')
        {
            for (key, secret) in form_urlencoded::parse(query.as_bytes()) {
                if key == "code" {
                    assert!(
                        !records.contains(secret.as_ref()),
                        "authorization code leaked"
                    );
                }
            }
        }
    }

    async fn post(app: &Router, path: &str, body: Value, cookies: &[(&str, &str)]) -> Reply {
        call(app, Method::POST, path, Some(body), cookies, Some(ISSUER)).await
    }

    fn origin() -> Url {
        Url::parse(ISSUER).unwrap()
    }

    /// Starts a registration with the setup token; returns the authenticator's response and the
    /// ceremony cookie.
    async fn start_enrolment(h: &Harness, device: &mut Device, token: &str) -> (Value, String) {
        let reply = post(&h.app, "/setup/options", json!({ "token": token }), &[]).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let (user, subject) = if token == INVITATION {
            ("dana", DANA_UID)
        } else {
            ("admin", ADMIN_UID)
        };
        assert_eq!(reply.audit.as_ref().unwrap()["fields"]["user"], user);
        assert_eq!(reply.audit.as_ref().unwrap()["fields"]["subject"], subject);
        let options: CredentialCreationOptions =
            serde_json::from_value(reply.body.clone()).unwrap();
        let credential = device
            .register(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        (
            serde_json::to_value(credential).unwrap(),
            reply.cookie(CEREMONY_COOKIE).unwrap(),
        )
    }

    async fn enrol(h: &Harness, device: &mut Device) {
        let (credential, ceremony) = start_enrolment(h, device, SETUP_TOKEN).await;
        let reply = post(
            &h.app,
            "/setup",
            json!({ "token": SETUP_TOKEN, "credential": credential, "label": "Laptop" }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        assert_eq!(reply.audit.as_ref().unwrap()["fields"]["user"], "admin");
        assert!(
            reply.audit.as_ref().unwrap()["fields"]
                .get("subject")
                .is_none()
        );
        assert_eq!(reply.body["username"], "admin");
    }

    /// Opens an authorization request and signs in with `device`; returns the reply to `/login`.
    async fn sign_in(h: &Harness, device: &mut Device) -> Reply {
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid&code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyz"
        );
        let reply = call(&h.app, Method::GET, &authorize, None, &[], None).await;
        let flow = reply.cookie(FLOW_COOKIE).unwrap();
        let reply = post(&h.app, "/login/options", json!({}), &[]).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialRequestOptions = serde_json::from_value(reply.body.clone()).unwrap();
        let assertion = device
            .authenticate(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        post(
            &h.app,
            "/login",
            json!({ "credential": assertion }),
            &[(FLOW_COOKIE, &flow), (CEREMONY_COOKIE, &ceremony)],
        )
        .await
    }

    #[tokio::test]
    async fn setup_link_then_passkey_sign_in_issues_tokens() {
        let h = harness().await;
        let mut device = device();
        enrol(&h, &mut device).await;

        let reply = sign_in(&h, &mut device).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(reply.audit.as_ref().unwrap()["fields"]["user"], "admin");
        assert_eq!(
            reply.audit.as_ref().unwrap()["fields"]["subject"],
            ADMIN_UID
        );
        assert!(
            reply
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|c| c.to_str().unwrap().starts_with(&format!("{FLOW_COOKIE}=;"))),
            "flow cookie cleared"
        );
        let location = reply.body["redirect_to"].as_str().unwrap();
        assert!(location.starts_with("http://127.0.0.1:8000/?code="));
        let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();

        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("client_id", "kubectl"),
            ])
            .finish();
        let request = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let response = h.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let tokens: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let payload = tokens["access_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(claims["sub"], ADMIN_UID);
        assert_eq!(claims["groups"], json!(["admins"]));
        assert_eq!(claims["amr"], json!(["swk", "mfa"]));
        assert_eq!(claims["auth_time"], START);
    }

    #[tokio::test]
    async fn invitation_enrols_the_invited_user_once() {
        let h = harness().await;
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, INVITATION).await;
        let reply = post(
            &h.app,
            "/setup",
            json!({ "token": INVITATION, "credential": credential }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        assert_eq!(reply.body["username"], "dana");

        // Used up; and the admin's setup token is untouched by it.
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": INVITATION }),
            &[],
        )
        .await;
        assert_eq!(reply.kind(), "urn:genkan:problem:setup-invalid");
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);

        // Signing in with the new passkey yields dana's identity.
        let reply = sign_in(&h, &mut device).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

        // A guessed secret for a real invitation name is refused.
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": "inv-1.guess" }),
            &[],
        )
        .await;
        assert_eq!(reply.kind(), "urn:genkan:problem:setup-invalid");
    }

    #[tokio::test]
    async fn setup_token_is_single_use() {
        let h = harness().await;
        enrol(&h, &mut device()).await;
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.kind(), "urn:genkan:problem:setup-invalid");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_enrolments_with_one_token_add_one_passkey() {
        let h = Arc::new(harness().await);
        let mut started = Vec::new();
        for _ in 0..8 {
            let mut device = device();
            started.push(start_enrolment(&h, &mut device, SETUP_TOKEN).await);
        }
        let barrier = Arc::new(Barrier::new(started.len()));
        let tasks: Vec<_> = started
            .into_iter()
            .map(|(credential, ceremony)| {
                let (h, barrier) = (Arc::clone(&h), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    post(
                        &h.app,
                        "/setup",
                        json!({ "token": SETUP_TOKEN, "credential": credential }),
                        &[(CEREMONY_COOKIE, &ceremony)],
                    )
                    .await
                    .status
                })
            })
            .collect();
        let mut created = 0;
        for task in tasks {
            if task.await.unwrap() == StatusCode::CREATED {
                created += 1;
            }
        }
        assert_eq!(created, 1);
    }

    #[tokio::test]
    async fn setup_token_expires_and_must_match() {
        let h = harness().await;
        let reply = post(&h.app, "/setup/options", json!({ "token": "wrong" }), &[]).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

        // Started in time, finished after expiry.
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, SETUP_TOKEN).await;
        h.clock.0.fetch_add(3600, Ordering::SeqCst);
        let reply = post(
            &h.app,
            "/setup",
            json!({ "token": SETUP_TOKEN, "credential": credential }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "the ceremony expired first: {}",
            reply.body
        );
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "the token expired");
    }

    #[tokio::test]
    async fn regenerating_the_link_invalidates_the_old_one() {
        let h = harness().await;
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, SETUP_TOKEN).await;
        h.service.setup.put(
            "admin",
            &hash_secret(b"a-newer-token"),
            UnixTime::from_secs(START + 3600),
        );
        let reply = post(
            &h.app,
            "/setup",
            json!({ "token": SETUP_TOKEN, "credential": credential }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn requests_from_other_sites_are_refused() {
        let h = harness().await;
        let reply = call(
            &h.app,
            Method::POST,
            "/setup/options",
            Some(json!({ "token": SETUP_TOKEN })),
            &[],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        let reply = call(
            &h.app,
            Method::POST,
            "/login/options",
            Some(json!({})),
            &[],
            Some("https://evil.example"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(
            reply.headers[header::CONTENT_TYPE],
            "application/problem+json"
        );
    }

    #[tokio::test]
    async fn assertions_cannot_be_replayed() {
        let h = harness().await;
        let mut device = device();
        enrol(&h, &mut device).await;
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        let flow = call(&h.app, Method::GET, &authorize, None, &[], None)
            .await
            .cookie(FLOW_COOKIE)
            .unwrap();
        let reply = post(&h.app, "/login/options", json!({}), &[]).await;
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialRequestOptions = serde_json::from_value(reply.body).unwrap();
        let assertion = serde_json::to_value(
            device
                .authenticate(&origin(), options, DefaultClientData)
                .await
                .unwrap(),
        )
        .unwrap();
        let cookies = [
            (FLOW_COOKIE, flow.as_str()),
            (CEREMONY_COOKIE, ceremony.as_str()),
        ];
        // Knowing an enrolled credential ID and handle is not proof of possession.
        let mut forged = assertion.clone();
        forged["response"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 64]));
        let rejected = post(&h.app, "/login", json!({ "credential": forged }), &cookies).await;
        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(rejected.kind(), "urn:genkan:problem:passkey-failed");
        let fields = &rejected.audit.as_ref().unwrap()["fields"];
        assert!(fields.get("user").is_none());
        assert!(fields.get("subject").is_none());
        assert!(fields.get("error").is_none());
        let diagnostic = rejected.diagnostics.first().unwrap();
        assert_eq!(diagnostic["fields"]["reason"], "passkey-failed");
        // Failed signature verification does not consume the valid ceremony.
        assert_eq!(
            post(
                &h.app,
                "/login",
                json!({ "credential": assertion }),
                &cookies
            )
            .await
            .status,
            StatusCode::OK
        );
        let second = post(
            &h.app,
            "/login",
            json!({ "credential": assertion }),
            &cookies,
        )
        .await;
        assert_eq!(second.status, StatusCode::BAD_REQUEST);
        assert_eq!(second.kind(), "urn:genkan:problem:ceremony-expired");
    }

    #[tokio::test]
    async fn unknown_passkeys_and_disabled_users_cannot_sign_in() {
        let h = harness().await;
        // A device whose passkey was never enrolled here (registered against another server).
        let other = harness().await;
        let mut stranger = device();
        enrol(&other, &mut stranger).await;
        let reply = sign_in(&h, &mut stranger).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.kind(), "urn:genkan:problem:passkey-failed");
        assert!(
            reply.audit.as_ref().unwrap()["fields"]
                .get("user")
                .is_none()
        );
        assert!(
            reply.audit.as_ref().unwrap()["fields"]
                .get("subject")
                .is_none()
        );

        let mut device = device();
        enrol(&h, &mut device).await;
        let mut admin = h
            .service
            .oauth
            .directory
            .user("admin")
            .await
            .unwrap()
            .unwrap();
        admin.disabled = true;
        h.service.oauth.directory.put_user(admin);
        let reply = sign_in(&h, &mut device).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        // Disabled users are rejected before signature verification, so no identity is asserted.
        let fields = &reply.audit.as_ref().unwrap()["fields"];
        assert!(fields.get("user").is_none());
        assert!(fields.get("subject").is_none());
    }

    #[tokio::test]
    async fn sign_in_needs_a_pending_authorization_request() {
        let h = harness().await;
        let mut device = device();
        enrol(&h, &mut device).await;
        let reply = post(&h.app, "/login/options", json!({}), &[]).await;
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialRequestOptions = serde_json::from_value(reply.body).unwrap();
        let assertion = device
            .authenticate(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        let reply = post(
            &h.app,
            "/login",
            json!({ "credential": assertion }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.kind(), "urn:genkan:problem:no-request");
    }

    use genkan_store::Directory as _;

    #[tokio::test]
    async fn passkeys_without_user_verification_are_refused() {
        let h = harness().await;
        let mut device: PasskeyClient<
            Option<passkey::types::Passkey>,
            PresenceOnly,
            public_suffix::PublicSuffixList,
            (),
        > = PasskeyClient::new(Authenticator::new(Aaguid::new_empty(), None, PresenceOnly));
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialCreationOptions = serde_json::from_value(reply.body).unwrap();
        // A client honouring `userVerification: required` refuses outright; if one sends a
        // response anyway, the server must reject it.
        if let Ok(credential) = device.register(&origin(), options, DefaultClientData).await {
            let reply = post(
                &h.app,
                "/setup",
                json!({ "token": SETUP_TOKEN, "credential": credential }),
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        }
        // The token was not consumed by the failed attempt.
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn verified_passkey_does_not_succeed_with_invalid_or_expired_authorization() {
        for expired in [false, true] {
            let h = harness().await;
            let mut device = device();
            enrol(&h, &mut device).await;
            let authorize = format!(
                "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&code_challenge={CHALLENGE}&code_challenge_method=S256"
            );
            let flow = call(&h.app, Method::GET, &authorize, None, &[], None)
                .await
                .cookie(FLOW_COOKIE)
                .unwrap();
            let rejected_flow = if expired {
                h.clock
                    .0
                    .fetch_add(h.service.oauth.lifetimes.flow.as_secs(), Ordering::SeqCst);
                flow
            } else {
                "secret-forged-authorization-flow".to_owned()
            };
            // Start a fresh ceremony after the flow expires, so the assertion itself verifies.
            let options = post(&h.app, "/login/options", json!({}), &[]).await;
            let ceremony = options.cookie(CEREMONY_COOKIE).unwrap();
            let assertion = device
                .authenticate(
                    &origin(),
                    serde_json::from_value(options.body).unwrap(),
                    DefaultClientData,
                )
                .await
                .unwrap();
            let reply = post(
                &h.app,
                "/login",
                json!({ "credential": assertion }),
                &[(FLOW_COOKIE, &rejected_flow), (CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
            assert_eq!(reply.kind(), "urn:genkan:problem:no-request");
            let fields = &reply.audit.as_ref().unwrap()["fields"];
            assert_eq!(fields["outcome"], "failure");
            assert_eq!(fields["user"], "admin");
            assert_eq!(fields["subject"], ADMIN_UID);
            assert!(fields.get("error").is_none());
            let diagnostic = reply.diagnostics.first().unwrap();
            assert_eq!(diagnostic["fields"]["reason"], "no-request");
            let error = diagnostic["fields"]["error"].as_str().unwrap();
            assert!(error.contains("InvalidRequest"));
            assert!(error.contains(if expired {
                "the sign-in request expired; start again"
            } else {
                "the sign-in request is missing or invalid"
            }));
            assert!(!serde_json::to_string(fields).unwrap().contains(error));
            // A rejected authorization still consumed the verified passkey ceremony.
            let second_attempt = post(
                &h.app,
                "/login",
                json!({ "credential": assertion }),
                &[(FLOW_COOKIE, &rejected_flow), (CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(second_attempt.kind(), "urn:genkan:problem:ceremony-expired");
        }
    }

    #[tokio::test]
    async fn missing_setup_user_is_not_an_authenticated_identity() {
        let h = harness().await;
        let token = "secret-setup-for-unknown-local-user";
        h.service.setup.put(
            "missing-secret-user",
            &hash_secret(token.as_bytes()),
            UnixTime::from_secs(START + 3600),
        );
        let reply = post(&h.app, "/setup/options", json!({ "token": token }), &[]).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let fields = &reply.audit.as_ref().unwrap()["fields"];
        assert!(fields.get("user").is_none());
        assert!(fields.get("subject").is_none());
    }
}

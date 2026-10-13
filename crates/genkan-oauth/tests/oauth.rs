//! End-to-end tests of the authorization server through its HTTP router, with in-memory storage
//! and a controllable clock.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, Method, Request, StatusCode, header};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use genkan_core::clock::{Clock, UnixTime};
    use genkan_core::config::BaseUrl;
    use genkan_core::crypto::{Sealer, hash_secret};
    use genkan_keys::Algorithm;
    use genkan_keys::manager::KeyManager;
    use genkan_keys::rotation::RotationPolicy;
    use genkan_keys::store::MemoryKeyStore;
    use genkan_oauth::authorize::Authentication;
    use genkan_oauth::endpoints::{FLOW_COOKIE, complete_authorization, router};
    use genkan_oauth::{AuthorizationServer, Lifetimes, OneTimeIds};
    use genkan_store::{Client, ClientType, MemoryDirectory, MemoryGrantStore, User};
    use http_body_util::BodyExt as _;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
    use serde_json::Value;
    use tokio::sync::Barrier;
    use tower::ServiceExt as _;

    const ISSUER: &str = "https://login.example.com";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const KUBECTL_REDIRECT: &str = "http://127.0.0.1:8000/callback";
    const WEB_SECRET: &str = "a-long-random-client-secret-for-tests-only";
    const START: u64 = 1_800_000_000;

    #[derive(Debug, Clone, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl Clock for TestClock {
        fn now(&self) -> UnixTime {
            UnixTime::from_secs(self.0.load(Ordering::SeqCst))
        }
    }

    impl TestClock {
        fn advance(&self, secs: u64) {
            self.0.fetch_add(secs, Ordering::SeqCst);
        }
    }

    type Server = AuthorizationServer<MemoryDirectory, MemoryGrantStore, TestClock>;

    struct Harness {
        server: Arc<Server>,
        app: Router,
        clock: TestClock,
        jwks: JwkSet,
    }

    async fn harness() -> Harness {
        harness_with(Lifetimes::DEFAULT).await
    }

    async fn harness_with(lifetimes: Lifetimes) -> Harness {
        let clock = TestClock::default();
        clock.0.store(START, Ordering::SeqCst);
        let manager = KeyManager::new(
            MemoryKeyStore::default(),
            clock.clone(),
            RotationPolicy::DEFAULT,
        );
        manager.reconcile().await.unwrap();
        let keys = manager.subscribe();
        let jwks: JwkSet = serde_json::from_slice(&keys.borrow().clone().unwrap().jwks()).unwrap();

        let directory = MemoryDirectory::default();
        directory.put_client(Client {
            id: "kubectl".into(),
            display_name: None,
            kind: ClientType::Public,
            redirect_uris: vec![KUBECTL_REDIRECT.into()],
            audiences: vec!["kubernetes".into()],
            secret_hash: None,
            id_token_alg: Algorithm::Es256,
            allow_elevation: true,
        });
        directory.put_client(Client {
            id: "web".into(),
            display_name: Some("Web".into()),
            kind: ClientType::Confidential,
            redirect_uris: vec!["https://app.example.com/cb".into()],
            audiences: vec![],
            secret_hash: Some(hash_secret(WEB_SECRET.as_bytes())),
            id_token_alg: Algorithm::Rs256,
            allow_elevation: false,
        });
        for (name, disabled) in [("alice", false), ("bob", true)] {
            directory.put_user(User {
                name: name.into(),
                subject: format!("uid-{name}"),
                username: name.into(),
                display_name: Some(format!("{name} example")),
                groups: vec!["admins".into()],
                disabled,
                elevated_groups: vec!["cluster-admins".into()],
            });
        }
        let server = Arc::new(AuthorizationServer {
            issuer: BaseUrl::parse("issuer", ISSUER).unwrap(),
            lifetimes,
            directory,
            grants: MemoryGrantStore::default(),
            clock: clock.clone(),
            keys,
            sealer: Sealer::ephemeral().unwrap(),
            used_codes: OneTimeIds::default(),
            used_request_uris: OneTimeIds::default(),
        });
        let app = router(Arc::clone(&server));
        Harness {
            server,
            app,
            clock,
            jwks,
        }
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Reply {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).unwrap()
        }
        fn location(&self) -> String {
            self.headers[header::LOCATION].to_str().unwrap().to_owned()
        }
        fn error(&self) -> String {
            self.json()["error"].as_str().unwrap().to_owned()
        }
    }

    async fn send(app: &Router, request: Request<Body>) -> Reply {
        let response = app.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes().to_vec(),
        }
    }

    async fn get(app: &Router, uri: &str) -> Reply {
        send(
            app,
            Request::builder().uri(uri).body(Body::empty()).unwrap(),
        )
        .await
    }

    async fn post(
        app: &Router,
        path: &str,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Reply {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some((id, secret)) = basic {
            request = request.header(
                header::AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
            );
        }
        send(app, request.body(Body::from(body)).unwrap()).await
    }

    fn query(pairs: &[(&str, &str)]) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    }

    fn kubectl_authorize(extra: &[(&str, &str)]) -> String {
        let mut pairs = vec![
            ("client_id", "kubectl"),
            ("redirect_uri", KUBECTL_REDIRECT),
            ("response_type", "code"),
            ("scope", "openid profile groups"),
            ("state", "state-1"),
            ("nonce", "nonce-1"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        pairs.extend_from_slice(extra);
        format!("/authorize?{}", query(&pairs))
    }

    fn flow_cookie(reply: &Reply) -> String {
        let cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
        cookie
            .strip_prefix(&format!("{FLOW_COOKIE}="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    fn param(location: &str, name: &str) -> Option<String> {
        let (_, query) = location.split_once('?')?;
        form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    /// Runs `/authorize` and the sign-in for `user`, and returns the code.
    async fn sign_in(h: &Harness, user: &str, authorize_uri: &str) -> String {
        sign_in_with(h, user, authorize_uri, &["hwk", "user"]).await
    }

    /// [`sign_in`] with the given authentication methods.
    async fn sign_in_with(h: &Harness, user: &str, authorize_uri: &str, amr: &[&str]) -> String {
        let reply = get(&h.app, authorize_uri).await;
        assert_eq!(
            reply.status,
            StatusCode::SEE_OTHER,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        let auth = Authentication {
            user: user.into(),
            auth_time: h.clock.now(),
            amr: amr.iter().map(|m| (*m).to_owned()).collect(),
        };
        let location = complete_authorization(&h.server, &flow_cookie(&reply), auth).unwrap();
        param(&location, "code").unwrap()
    }

    async fn exchange(h: &Harness, code: &str) -> Reply {
        post(
            &h.app,
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", KUBECTL_REDIRECT),
                ("code_verifier", VERIFIER),
                ("client_id", "kubectl"),
            ],
            None,
        )
        .await
    }

    async fn refresh(h: &Harness, token: &str) -> Reply {
        post(
            &h.app,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", token),
                ("client_id", "kubectl"),
            ],
            None,
        )
        .await
    }

    fn verify(h: &Harness, token: &str, audience: &str) -> (jsonwebtoken::Header, Value) {
        let header = decode_header(token).unwrap();
        let jwk = h.jwks.find(header.kid.as_deref().unwrap()).unwrap();
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[ISSUER]);
        validation.validate_exp = false;
        let data =
            decode::<Value>(token, &DecodingKey::from_jwk(jwk).unwrap(), &validation).unwrap();
        (header, data.claims)
    }

    #[tokio::test]
    async fn code_flow_issues_tokens_kubernetes_can_use() {
        let h = harness().await;
        let reply = get(&h.app, &kubectl_authorize(&[])).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert_eq!(reply.location(), "/login");
        let cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
        for attribute in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(cookie.contains(attribute), "{cookie}");
        }

        let auth = Authentication {
            user: "alice".into(),
            auth_time: h.clock.now(),
            amr: vec!["hwk".into(), "user".into()],
        };
        let location = complete_authorization(&h.server, &flow_cookie(&reply), auth).unwrap();
        assert!(location.starts_with(KUBECTL_REDIRECT));
        assert_eq!(param(&location, "state").as_deref(), Some("state-1"));
        assert_eq!(param(&location, "iss").as_deref(), Some(ISSUER), "RFC 9207");
        let code = param(&location, "code").unwrap();

        let reply = exchange(&h, &code).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        let body = reply.json();
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 600);
        assert_eq!(body["scope"], "openid profile groups");

        let (header, at) = verify(&h, body["access_token"].as_str().unwrap(), "kubernetes");
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
        assert_eq!(at["client_id"], "kubectl");
        assert_eq!(at["sub"], "uid-alice");
        assert_eq!(at["preferred_username"], "alice");
        assert_eq!(at["groups"], serde_json::json!(["admins"]));
        assert_eq!(
            at["exp"].as_u64().unwrap() - at["iat"].as_u64().unwrap(),
            600
        );
        assert!(at.get("azp").is_none() && at.get("nonce").is_none());

        let (header, id) = verify(&h, body["id_token"].as_str().unwrap(), "kubectl");
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        assert_eq!(id["azp"], "kubectl");
        assert_eq!(id["nonce"], "nonce-1");
        assert_eq!(id["auth_time"], START);
        assert_eq!(id["name"], "alice example");
        assert!(
            id.get("client_id").is_none(),
            "ID tokens never look like access tokens"
        );
    }

    #[tokio::test]
    async fn confidential_client_gets_rs256_id_tokens_and_must_authenticate() {
        let h = harness().await;
        let authorize = format!(
            "/authorize?{}",
            query(&[
                ("client_id", "web"),
                ("redirect_uri", "https://app.example.com/cb"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
            ])
        );
        let form = |code: &str| {
            vec![
                ("grant_type", "authorization_code".to_owned()),
                ("code", code.to_owned()),
                ("code_verifier", VERIFIER.to_owned()),
            ]
        };
        let as_refs = |pairs: &[(&'static str, String)]| {
            pairs
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect::<Vec<_>>()
        };

        // Wrong secret over Basic: 401 with a Basic challenge.
        let code = sign_in(&h, "alice", &authorize).await;
        let pairs = as_refs(&form(&code));
        let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = post(&h.app, "/token", &pairs, Some(("web", "wrong"))).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.error(), "invalid_client");
        assert!(
            reply.headers[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .starts_with("Basic")
        );

        // Two methods at once.
        let mut both = pairs.clone();
        both.push(("client_secret", WEB_SECRET));
        let reply = post(&h.app, "/token", &both, Some(("web", WEB_SECRET))).await;
        assert_eq!(reply.error(), "invalid_request");

        // No credentials at all for a confidential client.
        let mut none = pairs.clone();
        none.push(("client_id", "web"));
        assert_eq!(
            post(&h.app, "/token", &none, None).await.error(),
            "invalid_client"
        );

        // client_secret_basic works; the ID token is RS256 as registered.
        let reply = post(&h.app, "/token", &pairs, Some(("web", WEB_SECRET))).await;
        assert_eq!(reply.status, StatusCode::OK);
        let (header, id) = verify(&h, reply.json()["id_token"].as_str().unwrap(), "web");
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
        assert!(
            id.get("name").is_none(),
            "no profile scope, no profile claims"
        );
        let (_, at) = verify(&h, reply.json()["access_token"].as_str().unwrap(), "web");
        assert_eq!(
            at["aud"], "web",
            "a client without audiences gets itself as audience"
        );

        // client_secret_post works too.
        let code = sign_in(&h, "alice", &authorize).await;
        let pairs = as_refs(&form(&code));
        let mut pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        pairs.extend([("client_id", "web"), ("client_secret", WEB_SECRET)]);
        assert_eq!(
            post(&h.app, "/token", &pairs, None).await.status,
            StatusCode::OK
        );

        // A public client must not send a secret; unknown clients are rejected.
        let reply = post(
            &h.app,
            "/token",
            &[("grant_type", "refresh_token"), ("refresh_token", "x")],
            Some(("kubectl", "s")),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let reply = post(
            &h.app,
            "/token",
            &[("grant_type", "refresh_token"), ("client_id", "nobody")],
            None,
        )
        .await;
        assert_eq!(reply.error(), "invalid_client");
    }

    #[tokio::test]
    async fn code_is_single_use_and_reuse_revokes_what_it_issued() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let first = exchange(&h, &code).await;
        assert_eq!(first.status, StatusCode::OK);
        let refresh_token = first.json()["refresh_token"].as_str().unwrap().to_owned();

        let second = exchange(&h, &code).await;
        assert_eq!(second.status, StatusCode::BAD_REQUEST);
        assert_eq!(second.error(), "invalid_grant");
        // RFC 6749 §4.1.2: tokens issued from the reused code are revoked.
        assert_eq!(refresh(&h, &refresh_token).await.error(), "invalid_grant");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn exactly_one_concurrent_redemption_succeeds() {
        let h = Arc::new(harness().await);
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let barrier = Arc::new(Barrier::new(64));
        let tasks: Vec<_> = (0..64)
            .map(|_| {
                let (h, code, barrier) = (Arc::clone(&h), code.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    exchange(&h, &code).await.status
                })
            })
            .collect();
        let mut ok = 0;
        for task in tasks {
            if task.await.unwrap() == StatusCode::OK {
                ok += 1;
            }
        }
        assert_eq!(ok, 1);
    }

    #[tokio::test]
    async fn pkce_and_code_binding_are_enforced() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let base = [
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", "kubectl"),
        ];

        let wrong = [
            &base[..],
            &[(
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl",
            )],
        ]
        .concat();
        assert_eq!(
            post(&h.app, "/token", &wrong, None).await.error(),
            "invalid_grant"
        );
        assert_eq!(
            post(&h.app, "/token", &base, None).await.error(),
            "invalid_grant",
            "verifier required"
        );
        let other_redirect = [
            &base[..],
            &[
                ("code_verifier", VERIFIER),
                ("redirect_uri", "http://127.0.0.1:9/x"),
            ],
        ]
        .concat();
        assert_eq!(
            post(&h.app, "/token", &other_redirect, None).await.error(),
            "invalid_grant"
        );

        // Failed attempts did not consume the code: the legitimate client still succeeds.
        assert_eq!(exchange(&h, &code).await.status, StatusCode::OK);

        // Codes expire after 60 seconds.
        let late = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        h.clock.advance(61);
        assert_eq!(exchange(&h, &late).await.error(), "invalid_grant");

        // A code issued to one client is useless to another.
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let reply = post(
            &h.app,
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
            ],
            Some(("web", WEB_SECRET)),
        )
        .await;
        assert_eq!(reply.error(), "invalid_grant");
        assert_eq!(exchange(&h, "not-a-code").await.error(), "invalid_grant");
    }

    #[tokio::test]
    async fn refresh_rotates_and_reuse_revokes_the_family() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let first = exchange(&h, &code).await.json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();

        h.clock.advance(300);
        let reply = refresh(&h, &first).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        let second = reply.json()["refresh_token"].as_str().unwrap().to_owned();
        assert_ne!(first, second);
        let (_, id) = verify(&h, reply.json()["id_token"].as_str().unwrap(), "kubectl");
        assert_eq!(id["auth_time"], START, "auth_time is the original sign-in");
        assert!(id.get("nonce").is_none());

        let third = refresh(&h, &second).await.json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        // Someone replays the second token (already rotated): the whole family dies.
        assert_eq!(refresh(&h, &second).await.error(), "invalid_grant");
        assert_eq!(refresh(&h, &third).await.error(), "invalid_grant");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_reuse_of_a_refresh_token_revokes_the_family() {
        let h = Arc::new(harness().await);
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let token = exchange(&h, &code).await.json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        let barrier = Arc::new(Barrier::new(64));
        let tasks: Vec<_> = (0..64)
            .map(|_| {
                let (h, token, barrier) = (Arc::clone(&h), token.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    let reply = refresh(&h, &token).await;
                    (reply.status == StatusCode::OK)
                        .then(|| reply.json()["refresh_token"].as_str().unwrap().to_owned())
                })
            })
            .collect();
        let mut winners = Vec::new();
        for task in tasks {
            winners.extend(task.await.unwrap());
        }
        assert!(winners.len() <= 1, "at most one rotation succeeds");
        // The losers presented an already-rotated token, which revokes the family, including the
        // winner's new token.
        for winner in winners {
            assert_eq!(refresh(&h, &winner).await.error(), "invalid_grant");
        }
    }

    #[tokio::test]
    async fn refresh_rechecks_user_scope_and_lifetime() {
        let h = harness().await;
        let token = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();

        let reply = post(
            &h.app,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &token),
                ("client_id", "kubectl"),
                ("scope", "openid offline_access"),
            ],
            None,
        )
        .await;
        assert_eq!(
            reply.error(),
            "invalid_scope",
            "refresh cannot widen the scope"
        );
        let reply = post(
            &h.app,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &token),
                ("client_id", "kubectl"),
                ("scope", "openid"),
            ],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json()["scope"], "openid");
        let token = reply.json()["refresh_token"].as_str().unwrap().to_owned();

        // Another client presenting it kills the family.
        let reply = post(
            &h.app,
            "/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &token)],
            Some(("web", WEB_SECRET)),
        )
        .await;
        assert_eq!(reply.error(), "invalid_grant");
        assert_eq!(refresh(&h, &token).await.error(), "invalid_grant");

        // A deleted user gets nothing more.
        let token = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        h.server.directory.remove_user("alice");
        assert_eq!(refresh(&h, &token).await.error(), "invalid_grant");

        // A disabled user cannot redeem a code.
        let code = sign_in(&h, "bob", &kubectl_authorize(&[])).await;
        assert_eq!(exchange(&h, &code).await.error(), "invalid_grant");
    }

    #[tokio::test]
    async fn refresh_families_expire() {
        let h = harness().await;
        let token = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        h.clock.advance(4 * 3600);
        assert_eq!(
            refresh(&h, &token).await.error(),
            "invalid_grant",
            "idle lifetime"
        );

        // Even an active family ends at the absolute lifetime.
        let mut token = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        for _ in 0..3 {
            h.clock.advance(3 * 3600);
            let reply = refresh(&h, &token).await;
            assert_eq!(reply.status, StatusCode::OK);
            token = reply.json()["refresh_token"].as_str().unwrap().to_owned();
        }
        h.clock.advance(3 * 3600);
        assert_eq!(
            refresh(&h, &token).await.error(),
            "invalid_grant",
            "absolute lifetime"
        );
    }

    #[tokio::test]
    async fn authorization_endpoint_errors() {
        let h = harness().await;
        // Untrusted client or redirect URI: never redirected.
        let reply = get(
            &h.app,
            &format!(
                "/authorize?{}",
                query(&[("client_id", "nobody"), ("redirect_uri", KUBECTL_REDIRECT)])
            ),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = get(
            &h.app,
            &format!(
                "/authorize?{}",
                query(&[
                    ("client_id", "kubectl"),
                    ("redirect_uri", "https://evil.example/")
                ])
            ),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(reply.headers.get(header::LOCATION).is_none());
        // Repeated parameters.
        assert_eq!(
            get(&h.app, &format!("{}&state=again", kubectl_authorize(&[])))
                .await
                .status,
            StatusCode::BAD_REQUEST
        );

        // Other errors go back to the client with state and iss.
        let reply = get(&h.app, &kubectl_authorize(&[("prompt", "none")])).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let location = reply.location();
        assert!(location.starts_with(KUBECTL_REDIRECT));
        assert_eq!(param(&location, "error").as_deref(), Some("login_required"));
        assert_eq!(param(&location, "state").as_deref(), Some("state-1"));
        assert_eq!(param(&location, "iss").as_deref(), Some(ISSUER));
        let reply = get(
            &h.app,
            &kubectl_authorize(&[("resource", "https://other.example")]),
        )
        .await;
        assert_eq!(
            param(&reply.location(), "error").as_deref(),
            Some("invalid_target")
        );

        // A forged or expired flow cannot be completed.
        let auth = Authentication {
            user: "alice".into(),
            auth_time: h.clock.now(),
            amr: vec![],
        };
        assert!(complete_authorization(&h.server, "forged", auth.clone()).is_err());
        let reply = get(&h.app, &kubectl_authorize(&[])).await;
        h.clock.advance(601);
        assert!(complete_authorization(&h.server, &flow_cookie(&reply), auth).is_err());
    }

    #[tokio::test]
    async fn authorization_endpoint_accepts_post() {
        let h = harness().await;
        let form = kubectl_authorize(&[]);
        let form = form.strip_prefix("/authorize?").unwrap();
        let pairs: Vec<(String, String)> = form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect();
        let pairs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let reply = post(&h.app, "/authorize", &pairs, None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert_eq!(reply.location(), "/login");
    }

    #[tokio::test]
    async fn pushed_authorization_requests() {
        let h = harness().await;
        let pushed = [
            ("client_id", "kubectl"),
            ("redirect_uri", KUBECTL_REDIRECT),
            ("response_type", "code"),
            ("scope", "openid"),
            ("state", "pushed"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        let reply = post(&h.app, "/par", &pushed, None).await;
        assert_eq!(reply.status, StatusCode::CREATED);
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        let request_uri = reply.json()["request_uri"].as_str().unwrap().to_owned();
        assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
        assert_eq!(reply.json()["expires_in"], 60);

        let authorize = |client: &str| {
            format!(
                "/authorize?{}",
                query(&[("client_id", client), ("request_uri", &request_uri)])
            )
        };
        assert_eq!(
            get(&h.app, &authorize("web")).await.status,
            StatusCode::BAD_REQUEST,
            "bound to the client"
        );
        let reply = get(&h.app, &authorize("kubectl")).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let auth = Authentication {
            user: "alice".into(),
            auth_time: h.clock.now(),
            amr: vec![],
        };
        let location = complete_authorization(&h.server, &flow_cookie(&reply), auth).unwrap();
        assert_eq!(param(&location, "state").as_deref(), Some("pushed"));
        assert_eq!(
            get(&h.app, &authorize("kubectl")).await.status,
            StatusCode::BAD_REQUEST,
            "one-time use"
        );

        // Expiry, and invalid pushed requests.
        let request_uri = post(&h.app, "/par", &pushed, None).await.json()["request_uri"]
            .as_str()
            .unwrap()
            .to_owned();
        h.clock.advance(61);
        let reply = get(
            &h.app,
            &format!(
                "/authorize?{}",
                query(&[("client_id", "kubectl"), ("request_uri", &request_uri)])
            ),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = post(
            &h.app,
            "/par",
            &[
                ("client_id", "kubectl"),
                ("redirect_uri", "https://evil.example/"),
            ],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = post(
            &h.app,
            "/par",
            &[("client_id", "web"), ("client_secret", "wrong")],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn guessed_refresh_secrets_cannot_revoke_a_known_grant() {
        for wrong_client in [false, true] {
            for rotated in [false, true] {
                let h = harness().await;
                let first = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
                    .await
                    .json()["refresh_token"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let current = if rotated {
                    refresh(&h, &first).await.json()["refresh_token"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                } else {
                    first.clone()
                };
                let (grant, _) = first.split_once('.').unwrap();
                let guessed = format!("{grant}.{}", "A".repeat(43));
                assert_ne!(guessed, first);
                assert_ne!(guessed, current);
                let reply = if wrong_client {
                    post(
                        &h.app,
                        "/token",
                        &[("grant_type", "refresh_token"), ("refresh_token", &guessed)],
                        Some(("web", WEB_SECRET)),
                    )
                    .await
                } else {
                    post(
                        &h.app,
                        "/revoke",
                        &[("token", &guessed), ("client_id", "kubectl")],
                        None,
                    )
                    .await
                };
                if wrong_client {
                    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
                    assert_eq!(reply.error(), "invalid_grant");
                } else {
                    assert_eq!(reply.status, StatusCode::OK);
                    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
                }
                assert_eq!(refresh(&h, &current).await.status, StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn current_and_previous_refresh_secrets_authorize_family_revocation() {
        for wrong_client in [false, true] {
            for previous in [false, true] {
                let h = harness().await;
                let first = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
                    .await
                    .json()["refresh_token"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let current = refresh(&h, &first).await.json()["refresh_token"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let presented = if previous { &first } else { &current };
                let reply = if wrong_client {
                    post(
                        &h.app,
                        "/token",
                        &[
                            ("grant_type", "refresh_token"),
                            ("refresh_token", presented),
                        ],
                        Some(("web", WEB_SECRET)),
                    )
                    .await
                } else {
                    post(
                        &h.app,
                        "/revoke",
                        &[("token", presented), ("client_id", "kubectl")],
                        None,
                    )
                    .await
                };
                if wrong_client {
                    assert_eq!(reply.error(), "invalid_grant");
                } else {
                    assert_eq!(reply.status, StatusCode::OK);
                }
                assert_eq!(refresh(&h, &current).await.error(), "invalid_grant");
            }
        }
    }

    #[tokio::test]
    async fn revocation() {
        let h = harness().await;
        let body = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json();
        let token = body["refresh_token"].as_str().unwrap();

        // Another client cannot revoke it (but gets 200, RFC 7009 §2.2).
        let reply = post(
            &h.app,
            "/revoke",
            &[("token", token)],
            Some(("web", WEB_SECRET)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let token = refresh(&h, token).await.json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();

        let reply = post(
            &h.app,
            "/revoke",
            &[("token", &token), ("client_id", "kubectl")],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(refresh(&h, &token).await.error(), "invalid_grant");

        let reply = post(
            &h.app,
            "/revoke",
            &[
                ("token", body["access_token"].as_str().unwrap()),
                ("client_id", "kubectl"),
            ],
            None,
        )
        .await;
        assert_eq!(reply.error(), "unsupported_token_type");
        let reply = post(
            &h.app,
            "/revoke",
            &[("token", "garbage"), ("client_id", "kubectl")],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
    }

    const PASSKEY: &[&str] = &["swk", "mfa"];

    fn elevating() -> Lifetimes {
        Lifetimes {
            elevated_token: Some(Duration::from_mins(5)),
            ..Lifetimes::DEFAULT
        }
    }

    fn elevate_uri() -> String {
        kubectl_authorize(&[]).replace("scope=openid+profile+groups", "scope=openid+groups+elevate")
    }

    #[tokio::test]
    async fn elevation_issues_short_lived_tokens_without_refresh() {
        let h = harness_with(elevating()).await;
        let code = sign_in_with(&h, "alice", &elevate_uri(), PASSKEY).await;
        let reply = exchange(&h, &code).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.json());
        let tokens = reply.json();
        assert!(tokens.get("refresh_token").is_none(), "{tokens}");
        assert_eq!(tokens["expires_in"], 300);
        let (_, claims) = verify(&h, tokens["access_token"].as_str().unwrap(), "kubernetes");
        assert_eq!(
            claims["groups"],
            serde_json::json!(["admins", "elevated:cluster-admins"])
        );
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            300
        );
        assert!(claims["scope"].as_str().unwrap().contains("elevate"));
        // The ID token never outlives the elevated access token.
        let (_, id) = verify(&h, tokens["id_token"].as_str().unwrap(), "kubectl");
        assert!(id["exp"].as_u64().unwrap() - id["iat"].as_u64().unwrap() <= 300);
        // UserInfo reports base groups only.
        let info = userinfo(&h, tokens["access_token"].as_str()).await.json();
        assert_eq!(info["groups"], serde_json::json!(["admins"]));
    }

    #[tokio::test]
    async fn elevation_needs_the_feature_a_passkey_and_eligible_groups() {
        // Disabled: the scope is ignored like any unknown scope.
        let h = harness_with(Lifetimes {
            elevated_token: None,
            ..Lifetimes::DEFAULT
        })
        .await;
        let code = sign_in_with(&h, "alice", &elevate_uri(), PASSKEY).await;
        let tokens = exchange(&h, &code).await.json();
        assert!(tokens["refresh_token"].is_string());
        assert!(!tokens["scope"].as_str().unwrap().contains("elevate"));
        let (_, claims) = verify(&h, tokens["access_token"].as_str().unwrap(), "kubernetes");
        assert_eq!(claims["groups"], serde_json::json!(["admins"]));

        // Enabled, but signed in without a passkey (an upstream provider): refused.
        let h = harness_with(elevating()).await;
        let reply = get(&h.app, &elevate_uri()).await;
        let auth = Authentication {
            user: "alice".into(),
            auth_time: h.clock.now(),
            amr: vec![],
        };
        let error = complete_authorization(&h.server, &flow_cookie(&reply), auth).unwrap_err();
        assert_eq!(error.error.as_str(), "access_denied");

        // A user with no elevated groups gets invalid_scope.
        h.server.directory.put_user(User {
            name: "carol".into(),
            subject: "uid-carol".into(),
            username: "carol".into(),
            groups: vec!["dev".into()],
            ..User::default()
        });
        let code = sign_in_with(&h, "carol", &elevate_uri(), PASSKEY).await;
        assert_eq!(exchange(&h, &code).await.error(), "invalid_scope");

        // Refresh can never widen a normal grant to elevation.
        let code = sign_in_with(&h, "alice", &kubectl_authorize(&[]), PASSKEY).await;
        let tokens = exchange(&h, &code).await.json();
        let reply = post(
            &h.app,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
                ("client_id", "kubectl"),
                ("scope", "openid elevate"),
            ],
            None,
        )
        .await;
        assert_eq!(reply.error(), "invalid_scope");
    }

    fn kubectl_client(allow_elevation: bool) -> Client {
        Client {
            id: "kubectl".into(),
            display_name: None,
            kind: ClientType::Public,
            redirect_uris: vec![KUBECTL_REDIRECT.into()],
            audiences: vec!["kubernetes".into()],
            secret_hash: None,
            id_token_alg: Algorithm::Es256,
            allow_elevation,
        }
    }

    #[tokio::test]
    async fn elevation_needs_the_client_to_allow_it() {
        let h = harness_with(elevating()).await;
        h.server.directory.put_client(kubectl_client(false));

        // `/authorize`: invalid_scope, redirected with state.
        let reply = get(&h.app, &elevate_uri()).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let location = reply.location();
        assert_eq!(param(&location, "error").as_deref(), Some("invalid_scope"));
        assert_eq!(param(&location, "state").as_deref(), Some("state-1"));
        // The same client still signs users in normally.
        let code = sign_in_with(&h, "alice", &kubectl_authorize(&[]), PASSKEY).await;
        assert_eq!(exchange(&h, &code).await.status, StatusCode::OK);

        // `/par`: invalid_scope.
        let pushed = [
            ("client_id", "kubectl"),
            ("redirect_uri", KUBECTL_REDIRECT),
            ("response_type", "code"),
            ("scope", "openid elevate"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        let reply = post(&h.app, "/par", &pushed, None).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.error(), "invalid_scope");
        h.server.directory.put_client(kubectl_client(true));
        assert_eq!(
            post(&h.app, "/par", &pushed, None).await.status,
            StatusCode::CREATED
        );

        // Allowed at `/authorize`, taken away before `/token`: the code is refused.
        let code = sign_in_with(&h, "alice", &elevate_uri(), PASSKEY).await;
        h.server.directory.put_client(kubectl_client(false));
        assert_eq!(exchange(&h, &code).await.error(), "invalid_grant");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn an_elevated_code_is_redeemed_at_most_once_under_concurrency() {
        let h = Arc::new(harness_with(elevating()).await);
        let code = sign_in_with(&h, "alice", &elevate_uri(), PASSKEY).await;
        let barrier = Arc::new(Barrier::new(64));
        let tasks: Vec<_> = (0..64)
            .map(|_| {
                let (h, code, barrier) = (Arc::clone(&h), code.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    exchange(&h, &code).await.status
                })
            })
            .collect();
        let mut ok = 0;
        for task in tasks {
            if task.await.unwrap() == StatusCode::OK {
                ok += 1;
            }
        }
        assert_eq!(ok, 1);
    }

    async fn userinfo(h: &Harness, token: Option<&str>) -> Reply {
        let mut request = Request::builder().uri("/userinfo");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        send(&h.app, request.body(Body::empty()).unwrap()).await
    }

    #[tokio::test]
    async fn userinfo_returns_current_claims_for_access_tokens_only() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let tokens = exchange(&h, &code).await.json();
        let access = tokens["access_token"].as_str().unwrap();

        let reply = userinfo(&h, Some(access)).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        let claims = reply.json();
        assert_eq!(claims["sub"], "uid-alice");
        assert_eq!(claims["preferred_username"], "alice");
        assert_eq!(claims["name"], "alice example");
        assert_eq!(claims["groups"], serde_json::json!(["admins"]));

        // RFC 6750 §3: no token → a bare challenge; a bad one → invalid_token.
        let reply = userinfo(&h, None).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            reply.headers[header::WWW_AUTHENTICATE],
            r#"Bearer realm="genkan""#
        );
        let id_token = tokens["id_token"].as_str().unwrap();
        for bad in [id_token, "not-a-token", &format!("{access}x")] {
            let reply = userinfo(&h, Some(bad)).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{bad}");
            assert!(
                reply.headers[header::WWW_AUTHENTICATE]
                    .to_str()
                    .unwrap()
                    .contains(r#"error="invalid_token""#)
            );
        }

        // Without `profile` and `groups`, only `sub`.
        let code = sign_in(
            &h,
            "alice",
            &kubectl_authorize(&[]).replace("scope=openid+profile+groups", "scope=openid"),
        )
        .await;
        let narrow = exchange(&h, &code).await.json();
        let claims = userinfo(&h, narrow["access_token"].as_str()).await.json();
        assert_eq!(claims, serde_json::json!({ "sub": "uid-alice" }));

        // Without `openid`, UserInfo is out of scope.
        let code = sign_in(
            &h,
            "alice",
            &kubectl_authorize(&[]).replace("scope=openid+profile+groups", "scope=groups"),
        )
        .await;
        let plain = exchange(&h, &code).await.json();
        let reply = userinfo(&h, plain["access_token"].as_str()).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);

        // A user disabled after issuance, and an expired token, get nothing.
        h.server.directory.put_user(User {
            name: "alice".into(),
            subject: "uid-alice".into(),
            username: "alice".into(),
            disabled: true,
            ..User::default()
        });
        assert_eq!(
            userinfo(&h, Some(access)).await.status,
            StatusCode::UNAUTHORIZED
        );
        h.clock.advance(3600);
        assert_eq!(
            userinfo(&h, Some(access)).await.status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn userinfo_rejects_deleted_and_recreated_users() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let tokens = exchange(&h, &code).await.json();
        let access = tokens["access_token"].as_str().unwrap();
        assert_eq!(userinfo(&h, Some(access)).await.status, StatusCode::OK);

        h.server.directory.remove_user("alice");
        assert_eq!(
            userinfo(&h, Some(access)).await.status,
            StatusCode::UNAUTHORIZED
        );

        // Reusing the original name for a different UID must not expose its claims.
        h.server.directory.put_user(User {
            name: "alice".into(),
            subject: "uid-recreated".into(),
            username: "replacement".into(),
            ..User::default()
        });
        let reply = userinfo(&h, Some(access)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.body.as_slice(), b"");
    }

    #[tokio::test]
    async fn userinfo_rejects_unknown_and_ambiguous_subjects() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let tokens = exchange(&h, &code).await.json();
        let access = tokens["access_token"].as_str().unwrap();
        let (_, mut claims) = verify(&h, access, "kubernetes");
        let keys = h.server.keys.borrow().clone().unwrap();
        let key = keys.signer(Algorithm::Es256, h.clock.now()).unwrap();

        // An otherwise valid signed token for an absent subject never yields claims.
        claims["sub"] = serde_json::json!("uid-unknown");
        let unknown = genkan_keys::jws::sign_compact(&key, "at+jwt", &claims).unwrap();
        let reply = userinfo(&h, Some(&unknown)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.body.as_slice(), b"");

        // Ambiguous backend answers fail closed rather than choosing an arbitrary user.
        h.server.directory.put_user(User {
            name: "duplicate".into(),
            subject: "uid-alice".into(),
            username: "private-duplicate-username".into(),
            ..User::default()
        });
        let reply = userinfo(&h, Some(access)).await;
        assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(reply.body.as_slice(), b"");
    }

    #[tokio::test]
    async fn token_endpoint_rejects_malformed_requests() {
        let h = harness().await;
        let reply = post(
            &h.app,
            "/token",
            &[("grant_type", "password"), ("client_id", "kubectl")],
            None,
        )
        .await;
        assert_eq!(reply.error(), "unsupported_grant_type");
        let reply = post(&h.app, "/token", &[("client_id", "kubectl")], None).await;
        assert_eq!(reply.error(), "invalid_request");
        let request = Request::builder()
            .method(Method::POST)
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(send(&h.app, request).await.status, StatusCode::BAD_REQUEST);
    }
}

//! Upstream sign-in and account linking against fake GitHub and Google providers that answer in
//! process: PKCE is checked against the challenge sent, Google's ID token is signed with a test
//! key published in a test JWK set.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::http::{HeaderMap, Method, Request, Response, StatusCode, header};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use genkan_core::clock::{Clock, SystemClock};
    use genkan_core::config::BaseUrl;
    use genkan_core::crypto::{Sealer, hash_secret, sha256};
    use genkan_keys::Algorithm;
    use genkan_keys::jwk::JwkSet;
    use genkan_keys::jws::sign_compact;
    use genkan_keys::manager::KeyManager;
    use genkan_keys::rotation::RotationPolicy;
    use genkan_keys::signing::SigningKey;
    use genkan_keys::store::MemoryKeyStore;
    use genkan_oauth::endpoints::{self, FLOW_COOKIE};
    use genkan_oauth::{AuthorizationServer, Lifetimes, OneTimeIds};
    use genkan_signin::SignIn;
    use genkan_signin::passkeys::Passkeys;
    use genkan_signin::upstream::http::{HttpClient, HttpError};
    use genkan_signin::upstream::provider::{Endpoints, Kind, Provider};
    use genkan_signin::upstream::{self, UPSTREAM_COOKIE, Upstream};
    use genkan_store::{
        Client, ClientType, CredentialStore as _, MemoryCredentialStore, MemoryDirectory,
        MemoryGrantStore, MemorySetupStore, NewExternal, User, external_credential_name,
    };
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    const ISSUER: &str = "https://login.example.com";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const GITHUB_ID: u64 = 583_231;
    const GOOGLE_SUB: &str = "110169484474386276334";
    const INVITATION: &str = "inv-1.invitation-secret-with-plenty-of-entropy";

    /// What the fake providers know about the current attempt.
    #[derive(Default)]
    struct Fake {
        /// code → (PKCE challenge, nonce) the code was issued for.
        codes: Mutex<HashMap<String, (String, String)>>,
        /// Signs Google's ID tokens.
        google_key: Mutex<Option<Arc<SigningKey>>>,
        /// Published in Google's JWK set.
        published_key: Mutex<Option<Arc<SigningKey>>>,
        /// Overrides for Google's ID token claims.
        id_token_overrides: Mutex<Value>,
    }

    #[derive(Clone)]
    struct FakeHttp(Arc<Fake>);

    fn reply(status: StatusCode, body: &Value) -> Response<Bytes> {
        Response::builder()
            .status(status)
            .body(Bytes::from(body.to_string()))
            .unwrap()
    }

    /// Google's token response: an ID token with the fake's claims and overrides.
    fn google_token(fake: &Fake, nonce: &str) -> Response<Bytes> {
        let now = SystemClock.now().as_secs();
        let mut claims = json!({
            "iss": "https://accounts.google.com",
            "sub": GOOGLE_SUB,
            "aud": "google-client",
            "exp": now + 300,
            "iat": now,
            "nonce": nonce,
        });
        let overrides = fake.id_token_overrides.lock().unwrap().clone();
        if let Value::Object(map) = overrides {
            for (k, v) in map {
                claims[k] = v;
            }
        }
        let key = fake.google_key.lock().unwrap().clone().unwrap();
        let id_token = sign_compact(&key, "JWT", &claims).unwrap();
        reply(
            StatusCode::OK,
            &json!({ "access_token": "g", "id_token": id_token }),
        )
    }

    /// Google's JWK set: the published key only.
    fn google_jwks(fake: &Fake) -> Response<Bytes> {
        let key = fake.published_key.lock().unwrap().clone().unwrap();
        let set = JwkSet {
            keys: vec![key.jwk()],
        };
        reply(StatusCode::OK, &serde_json::to_value(set).unwrap())
    }

    impl HttpClient for FakeHttp {
        fn send(
            &self,
            request: Request<Bytes>,
        ) -> impl Future<Output = Result<Response<Bytes>, HttpError>> + Send {
            let uri = request.uri().to_string();
            std::future::ready(
                self.answer(&request)
                    .ok_or_else(|| HttpError(format!("unexpected request to {uri}"))),
            )
        }
    }

    impl FakeHttp {
        fn answer(&self, request: &Request<Bytes>) -> Option<Response<Bytes>> {
            let fake = &self.0;
            let uri = request.uri().to_string();
            let form: HashMap<String, String> = form_urlencoded::parse(request.body())
                .into_owned()
                .collect();
            let redeem = |form: &HashMap<String, String>| {
                let code = form.get("code")?;
                let (challenge, nonce) = fake.codes.lock().unwrap().remove(code)?;
                let verifier = form.get("code_verifier")?;
                (URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes())) == challenge).then_some(nonce)
            };
            Some(match uri.as_str() {
                "https://github.test/token" => match redeem(&form) {
                    Some(_)
                        if form.get("client_secret").map(String::as_str) == Some("gh-secret") =>
                    {
                        reply(StatusCode::OK, &json!({ "access_token": "gh-access" }))
                    }
                    _ => reply(
                        StatusCode::BAD_REQUEST,
                        &json!({ "error": "bad_verification_code" }),
                    ),
                },
                "https://api.github.test/user" => {
                    let authorized = request.headers()[header::AUTHORIZATION] == "Bearer gh-access"
                        && request.headers().contains_key(header::USER_AGENT);
                    if authorized {
                        reply(
                            StatusCode::OK,
                            &json!({ "id": GITHUB_ID, "login": "octocat" }),
                        )
                    } else {
                        reply(StatusCode::UNAUTHORIZED, &json!({}))
                    }
                }
                "https://google.test/token" => redeem(&form).map_or_else(
                    || {
                        reply(
                            StatusCode::BAD_REQUEST,
                            &json!({ "error": "invalid_grant" }),
                        )
                    },
                    |nonce| google_token(fake, &nonce),
                ),
                "https://google.test/jwks" => google_jwks(fake),
                _ => return None,
            })
        }
    }

    struct Harness {
        app: Router,
        fake: Arc<Fake>,
        service: Arc<
            Upstream<
                MemoryDirectory,
                MemoryGrantStore,
                SystemClock,
                MemoryCredentialStore,
                MemorySetupStore,
                FakeHttp,
            >,
        >,
    }

    async fn harness() -> Harness {
        let manager = KeyManager::new(
            MemoryKeyStore::default(),
            SystemClock,
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
        for (name, disabled) in [("alice", false), ("dana", false), ("zed", true)] {
            directory.put_user(User {
                name: name.into(),
                subject: format!("uid-{name}"),
                username: name.into(),
                groups: vec!["dev".into()],
                disabled,
                ..User::default()
            });
        }
        let issuer = BaseUrl::parse("issuer", ISSUER).unwrap();
        let oauth = Arc::new(AuthorizationServer {
            issuer: issuer.clone(),
            lifetimes: Lifetimes {
                elevated_token: Some(std::time::Duration::from_mins(5)),
                ..Lifetimes::DEFAULT
            },
            directory,
            grants: MemoryGrantStore::default(),
            clock: SystemClock,
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
            genkan_core::clock::UnixTime::from_secs(SystemClock.now().as_secs() + 3600),
        );
        let sign_in = Arc::new(SignIn {
            oauth: Arc::clone(&oauth),
            passkeys: Passkeys::new(&issuer).unwrap(),
            credentials: MemoryCredentialStore::default(),
            setup,
            used_ceremonies: OneTimeIds::default(),
        });
        let fake = Arc::new(Fake::default());
        let google_key = Arc::new(SigningKey::generate(Algorithm::Rs256).unwrap());
        *fake.google_key.lock().unwrap() = Some(Arc::clone(&google_key));
        *fake.published_key.lock().unwrap() = Some(google_key);
        let github = Provider::new(
            Kind::GitHub,
            "gh-client".into(),
            "gh-secret".into(),
            Endpoints {
                authorize: "https://github.test/authorize".into(),
                token: "https://github.test/token".into(),
                user: Some("https://api.github.test/user".into()),
                jwks: None,
                issuers: vec![],
            },
        );
        let google = Provider::new(
            Kind::Google,
            "google-client".into(),
            "google-secret".into(),
            Endpoints {
                authorize: "https://google.test/authorize".into(),
                token: "https://google.test/token".into(),
                user: None,
                jwks: Some("https://google.test/jwks".into()),
                issuers: Endpoints::google().issuers,
            },
        );
        let service = Arc::new(Upstream {
            sign_in: Arc::clone(&sign_in),
            providers: vec![github, google],
            http: FakeHttp(Arc::clone(&fake)),
            used_states: OneTimeIds::default(),
        });
        let app = endpoints::router(oauth)
            .merge(genkan_signin::router(sign_in))
            .merge(upstream::router(Arc::clone(&service)));
        Harness { app, fake, service }
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: String,
    }

    impl Reply {
        fn json(&self) -> Value {
            serde_json::from_str(&self.body).unwrap_or(Value::Null)
        }
        fn cookie(&self, name: &str) -> String {
            self.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .find_map(|v| {
                    let v = v.to_str().ok()?.strip_prefix(&format!("{name}="))?;
                    Some(v.split(';').next()?.to_owned())
                })
                .unwrap_or_else(|| panic!("no {name} cookie"))
        }
    }

    async fn call(app: &Router, request: Request<Body>) -> Reply {
        let response = app.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned(),
        }
    }

    async fn authorize(h: &Harness, scope: &str) -> String {
        let uri = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope={scope}&code_challenge={CHALLENGE}&code_challenge_method=S256&state=s"
        );
        let reply = call(&h.app, Request::get(uri).body(Body::empty()).unwrap()).await;
        reply.cookie(FLOW_COOKIE)
    }

    async fn start(h: &Harness, provider: &str, body: &Value, cookies: &str) -> Reply {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/upstream/{provider}/start"))
            .header(header::ORIGIN, ISSUER)
            .header(header::CONTENT_TYPE, "application/json");
        if !cookies.is_empty() {
            request = request.header(header::COOKIE, cookies);
        }
        call(&h.app, request.body(Body::from(body.to_string())).unwrap()).await
    }

    /// Plays the provider: reads the authorization URL, issues `code` for its challenge and
    /// nonce, and returns the callback query with the given state.
    fn provider_issues_code(h: &Harness, authorize_url: &str, code: &str) -> String {
        let query: HashMap<String, String> =
            form_urlencoded::parse(authorize_url.split_once('?').unwrap().1.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(query["code_challenge_method"], "S256");
        h.fake.codes.lock().unwrap().insert(
            code.to_owned(),
            (
                query["code_challenge"].clone(),
                query.get("nonce").cloned().unwrap_or_default(),
            ),
        );
        format!("code={code}&state={}", query["state"])
    }

    async fn callback(h: &Harness, provider: &str, query: &str, cookies: &str) -> Reply {
        call(
            &h.app,
            Request::get(format!("/upstream/{provider}/callback?{query}"))
                .header(header::COOKIE, cookies)
                .header(header::ACCEPT_LANGUAGE, "en")
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn link(h: &Harness, kind: Kind, subject: &str, user: &str) {
        h.service
            .sign_in
            .credentials
            .link(&NewExternal {
                name: external_credential_name(kind.issuer(), subject),
                user: user.into(),
                kind: kind.credential_type(),
                issuer: kind.issuer().into(),
                subject: subject.into(),
            })
            .await
            .unwrap();
    }

    /// Runs a sign-in with `provider` up to the callback; returns the callback reply.
    async fn sign_in(h: &Harness, provider: &str, code: &str) -> Reply {
        let flow = authorize(h, "openid").await;
        let started = start(h, provider, &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        assert_eq!(started.status, StatusCode::OK, "{}", started.body);
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        let query = provider_issues_code(h, &url, code);
        let cookies = format!(
            "{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={}",
            started.cookie(UPSTREAM_COOKIE)
        );
        callback(h, provider, &query, &cookies).await
    }

    #[tokio::test]
    async fn a_linked_github_account_signs_in_and_gets_a_code() {
        let h = harness().await;
        link(&h, Kind::GitHub, &GITHUB_ID.to_string(), "alice").await;
        let reply = sign_in(&h, "github", "code-1").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        let location = reply.headers[header::LOCATION].to_str().unwrap();
        assert!(
            location.starts_with("http://127.0.0.1:8000/?code="),
            "{location}"
        );

        let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let form = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("code_verifier", VERIFIER),
                ("client_id", "kubectl"),
            ])
            .finish();
        let tokens = call(
            &h.app,
            Request::post("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .json();
        let payload = tokens["access_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(claims["sub"], "uid-alice");
        // No passkey: no `amr`, and so never elevation.
        assert!(claims.get("amr").is_none(), "{claims}");
    }

    #[tokio::test]
    async fn unlinked_disabled_and_replayed_sign_ins_fail() {
        let h = harness().await;
        let reply = sign_in(&h, "github", "code-1").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(
            reply.body.contains("not linked to any user"),
            "{}",
            reply.body
        );

        link(&h, Kind::Google, GOOGLE_SUB, "zed").await;
        let reply = sign_in(&h, "google", "code-2").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "disabled user");

        // The same state twice: the second is refused.
        link(&h, Kind::GitHub, &GITHUB_ID.to_string(), "alice").await;
        let flow = authorize(&h, "openid").await;
        let started = start(&h, "github", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        let query = provider_issues_code(&h, &url, "code-3");
        let cookies = format!(
            "{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={}",
            started.cookie(UPSTREAM_COOKIE)
        );
        assert_eq!(
            callback(&h, "github", &query, &cookies).await.status,
            StatusCode::SEE_OTHER
        );
        assert_eq!(
            callback(&h, "github", &query, &cookies).await.status,
            StatusCode::BAD_REQUEST
        );

        // A forged state, or no cookie, is refused.
        let flow = authorize(&h, "openid").await;
        let started = start(&h, "github", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        provider_issues_code(&h, &url, "code-4");
        let cookies = format!(
            "{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={}",
            started.cookie(UPSTREAM_COOKIE)
        );
        let forged = callback(&h, "github", "code=code-4&state=forged", &cookies).await;
        assert_eq!(forged.status, StatusCode::BAD_REQUEST);
        let no_cookie = callback(&h, "github", "code=code-4&state=x", "").await;
        assert_eq!(no_cookie.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn start_requires_a_pending_request_and_refuses_elevation() {
        let h = harness().await;
        let reply = start(&h, "github", &json!({}), "").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let flow = authorize(&h, "openid+elevate").await;
        let reply = start(&h, "github", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
        let reply = start(&h, "gitlab", &json!({}), "").await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        // Cross-site requests are refused before anything else.
        let reply = call(
            &h.app,
            Request::post("/upstream/github/start")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_invitation_links_an_account_once() {
        let h = harness().await;
        let started = start(&h, "google", &json!({ "token": INVITATION }), "").await;
        assert_eq!(started.status, StatusCode::OK, "{}", started.body);
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        assert!(url.contains("scope=openid") && url.contains("nonce="));
        let query = provider_issues_code(&h, &url, "code-1");
        let cookies = format!("{UPSTREAM_COOKIE}={}", started.cookie(UPSTREAM_COOKIE));
        let reply = callback(&h, "google", &query, &cookies).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(reply.body.contains("Account linked"));
        let name = external_credential_name(Kind::Google.issuer(), GOOGLE_SUB);
        assert_eq!(
            h.service
                .sign_in
                .credentials
                .linked_user(&name)
                .await
                .unwrap()
                .as_deref(),
            Some("dana")
        );
        // The invitation is used up.
        let again = start(&h, "google", &json!({ "token": INVITATION }), "").await;
        assert_eq!(again.status, StatusCode::UNAUTHORIZED);

        // And the linked account now signs in as dana.
        let reply = sign_in(&h, "google", "code-2").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    }

    #[tokio::test]
    async fn google_id_tokens_are_validated() {
        let h = harness().await;
        link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
        let now = SystemClock.now().as_secs();
        for (claim, value) in [
            ("aud", json!("someone-else")),
            ("aud", json!(["google-client", "other"])),
            ("aud", json!([])),
            ("azp", json!("other")),
            ("iss", json!("https://evil.example")),
            ("exp", json!(now - 3600)),
            ("nonce", json!("replayed")),
            ("iat", json!(now + 3600)),
        ] {
            *h.fake.id_token_overrides.lock().unwrap() = json!({ claim: value });
            let reply = sign_in(&h, "google", &format!("code-{claim}")).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{claim}={value}");
        }
        // Another audience is refused even when azp names this client (OIDC Core §3.1.3.7 step 3).
        *h.fake.id_token_overrides.lock().unwrap() =
            json!({ "aud": ["google-client", "other"], "azp": "google-client" });
        assert_eq!(
            sign_in(&h, "google", "code-azp-other").await.status,
            StatusCode::BAD_REQUEST
        );
        // A one-element array naming this client, with a matching azp, is accepted.
        *h.fake.id_token_overrides.lock().unwrap() =
            json!({ "aud": ["google-client"], "azp": "google-client" });
        assert_eq!(
            sign_in(&h, "google", "code-azp").await.status,
            StatusCode::SEE_OTHER
        );

        // A token signed by a key outside the published set is refused.
        *h.fake.id_token_overrides.lock().unwrap() = json!({});
        let rogue = Arc::new(SigningKey::generate(Algorithm::Rs256).unwrap());
        *h.fake.google_key.lock().unwrap() = Some(rogue);
        let reply = sign_in(&h, "google", "code-rogue").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }
}

//! End to end on a real cluster: Genkan runs as a pod from its image, `kube-config` prepares
//! kube-apiserver, an admin enrols a passkey from a setup link and signs in, and kube-apiserver
//! accepts the resulting access token (`kubectl auth whoami`).
//!
//! Needs a k3s cluster whose kube-apiserver reads its `AuthenticationConfiguration` from a
//! directory on this machine, and the image loaded into the cluster. CI sets this up (see the
//! `kubernetes` job in `.github/workflows/ci.yml`):
//!
//! - `KUBECONFIG`: the cluster admin;
//! - `GENKAN_E2E_IMAGE`: the image name inside the cluster;
//! - `GENKAN_E2E_AUTHN_DIR`: the host directory mounted at kube-apiserver's configuration path.
//!
//! Run: `cargo nextest run --run-ignored only -E 'binary(e2e)'`

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use axum::body::Bytes;
    use axum::http::{HeaderMap, Method, Request, StatusCode, header};
    use genkan_core::clock::{Clock as _, SystemClock};
    use genkan_core::config::BaseUrl;
    use genkan_k8s::crd::client::{ClientType, OAuthClient, OAuthClientSpec};
    use genkan_k8s::crd::credential::Credential;
    use genkan_k8s::crd::{USER_LABEL, definitions};
    use genkan_k8s::kube_config::{self, DiscoveryMode, Distro};
    use genkan_k8s::setup::issue_setup_link;
    use genkan_k8s::{deployment, rbac};
    use genkan_oauth::endpoints::FLOW_COOKIE;
    use genkan_signin::CEREMONY_COOKIE;
    use genkan_test_support::{Device, device};
    use http_body_util::{BodyExt as _, Full};
    use hyper_util::rt::TokioIo;
    use k8s_openapi::api::apps::v1::Deployment;
    use k8s_openapi::api::core::v1::{Namespace, Node, Service, ServicePort, ServiceSpec};
    use kube::api::{
        Api, DeleteParams, DynamicObject, ListParams, ObjectMeta, Patch, PatchParams, PostParams,
    };
    use kube::config::Kubeconfig;
    use kube::core::GroupVersionKind;
    use kube::discovery::{Scope, pinned_kind};
    use kube::{Client, ResourceExt as _};
    use passkey::client::DefaultClientData;
    use passkey::types::webauthn::{CredentialCreationOptions, CredentialRequestOptions};
    use serde_json::{Value, json};
    use tokio::net::TcpStream;
    use url::Url;

    const ISSUER: &str = "https://genkan.e2e.invalid";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const REDIRECT: &str = "http://127.0.0.1:8000/";
    /// kube-apiserver re-reads the file about once a minute and then waits for discovery.
    const APISERVER_PICKUP: Duration = Duration::from_secs(180);
    const EMPTY_AUTHN: &str = "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\nanonymous:\n  enabled: false\njwt: []\n";

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set (see tests/e2e.rs)"))
    }

    /// Server-side apply of any object.
    async fn apply(client: &Client, value: Value) {
        let object: DynamicObject = serde_json::from_value(value).unwrap();
        let gvk = GroupVersionKind::try_from(object.types.as_ref().unwrap()).unwrap();
        let (resource, capabilities) = pinned_kind(client, &gvk).await.unwrap();
        let api: Api<DynamicObject> = match capabilities.scope {
            Scope::Namespaced => Api::namespaced_with(
                client.clone(),
                object.namespace().as_deref().unwrap(),
                &resource,
            ),
            Scope::Cluster => Api::all_with(client.clone(), &resource),
        };
        api.patch(
            &object.name_any(),
            &PatchParams::apply("genkan-e2e").force(),
            &Patch::Apply(&object),
        )
        .await
        .unwrap();
    }

    async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut check: F)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let deadline = Instant::now() + timeout;
        while !check().await {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Writes kube-apiserver's configuration atomically (it re-reads the file by path).
    fn write_authn(dir: &Path, contents: &str) {
        let staging = dir.join(".authn.yaml.tmp");
        std::fs::write(&staging, contents).unwrap();
        std::fs::rename(&staging, dir.join("authn.yaml")).unwrap();
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Reply {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).unwrap_or(Value::Null)
        }
        fn cookie(&self, name: &str) -> String {
            self.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .find_map(|v| {
                    let value = v.to_str().ok()?.strip_prefix(&format!("{name}="))?;
                    Some(value.split(';').next()?.to_owned())
                })
                .unwrap_or_else(|| panic!("no {name} cookie"))
        }
    }

    /// One HTTP/1.1 request to Genkan's public listener (`address` is the node's IP and the
    /// `NodePort`).
    async fn http(
        address: &str,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, String)>,
    ) -> Reply {
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(connection);
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, address);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let payload = match body {
            Some((content_type, payload)) => {
                request = request.header(header::CONTENT_TYPE, content_type);
                payload
            }
            None => String::new(),
        };
        let response = sender
            .send_request(request.body(Full::new(Bytes::from(payload))).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes(),
        }
    }

    async fn post_json(address: &str, path: &str, body: &Value, cookies: &str) -> Reply {
        let mut headers = vec![("origin", ISSUER)];
        if !cookies.is_empty() {
            headers.push(("cookie", cookies));
        }
        http(
            address,
            Method::POST,
            path,
            &headers,
            Some(("application/json", body.to_string())),
        )
        .await
    }

    /// A kubeconfig with the cluster from `KUBECONFIG` and only a bearer token: no client
    /// certificate that kube-apiserver could authenticate first.
    fn token_kubeconfig(dir: &Path, label: &str, token: &str) -> PathBuf {
        let admin = Kubeconfig::read().unwrap();
        let context = admin.current_context.clone().unwrap();
        let cluster_name = admin
            .contexts
            .iter()
            .find(|c| c.name == context)
            .and_then(|c| c.context.as_ref())
            .map(|c| c.cluster.clone())
            .unwrap();
        let cluster = admin
            .clusters
            .iter()
            .find(|c| c.name == cluster_name)
            .and_then(|c| c.cluster.clone())
            .unwrap();
        let config = json!({
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{ "name": "e2e", "cluster": {
                "server": cluster.server,
                "certificate-authority-data": cluster.certificate_authority_data,
            }}],
            "users": [{ "name": "e2e", "user": { "token": token } }],
            "contexts": [{ "name": "e2e", "context": { "cluster": "e2e", "user": "e2e" } }],
            "current-context": "e2e",
        });
        let path = dir.join(format!("genkan-e2e-{label}-{}.json", std::process::id()));
        std::fs::write(&path, config.to_string()).unwrap();
        path
    }

    fn kubectl(kubeconfig: &Path, args: &[&str]) -> Result<String, String> {
        let output = Command::new("kubectl")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .args(args)
            .output()
            .map_err(|error| format!("running kubectl: {error}"))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }

    /// `kubectl auth can-i`: "yes" or "no" (it exits non-zero for "no").
    fn can_i(kubeconfig: &Path, args: &[&str]) -> String {
        let output = Command::new("kubectl")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .args(["auth", "can-i"])
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// Signs in with `device` through Genkan's public listener, as kubectl's OIDC plugin would
    /// (authorization request, passkey, code, token), and returns the token response.
    async fn sign_in(address: &str, device: &mut Device, scope: &str) -> Value {
        let origin = Url::parse(ISSUER).unwrap();
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope={scope}&code_challenge={CHALLENGE}&code_challenge_method=S256&state=e2e"
        );
        let reply = http(address, Method::GET, &authorize, &[], None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let flow = reply.cookie(FLOW_COOKIE);
        let reply = post_json(address, "/login/options", &json!({}), "").await;
        let ceremony = reply.cookie(CEREMONY_COOKIE);
        let options: CredentialRequestOptions = serde_json::from_value(reply.json()).unwrap();
        let assertion = device
            .authenticate(&origin, options, DefaultClientData)
            .await
            .unwrap();
        let reply = post_json(
            address,
            "/login",
            &json!({ "credential": assertion }),
            &format!("{FLOW_COOKIE}={flow}; {CEREMONY_COOKIE}={ceremony}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let location = reply.json()["redirect_to"].as_str().unwrap().to_owned();
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
                ("redirect_uri", REDIRECT),
            ])
            .finish();
        let reply = http(
            address,
            Method::POST,
            "/token",
            &[],
            Some(("application/x-www-form-urlencoded", form)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        reply.json()
    }

    async fn refresh(address: &str, token: &str) -> Reply {
        let form = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "refresh_token"),
                ("client_id", "kubectl"),
                ("refresh_token", token),
            ])
            .finish();
        http(
            address,
            Method::POST,
            "/token",
            &[],
            Some(("application/x-www-form-urlencoded", form)),
        )
        .await
    }

    #[tokio::test]
    #[ignore = "needs a prepared k3s cluster and the image (see the file comment)"]
    #[expect(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
    async fn passkey_sign_in_then_kubectl_auth_whoami() {
        let image = env("GENKAN_E2E_IMAGE");
        let authn_dir = PathBuf::from(env("GENKAN_E2E_AUTHN_DIR"));
        let admin = Client::try_default().await.unwrap();
        let issuer = BaseUrl::parse("issuer", ISSUER).unwrap();
        let namespace = format!("genkan-e2e-{}", std::process::id());

        // Install: CRDs, then everything `genkanctl manifests` prints.
        for crd in definitions() {
            apply(&admin, serde_json::to_value(crd).unwrap()).await;
        }
        for object in deployment::manifests(
            &namespace,
            &issuer,
            &deployment::Options {
                image: image.clone(),
                ..deployment::Options::default()
            },
        )
        .unwrap()
        {
            apply(&admin, object).await;
        }
        let deployments: Api<Deployment> = Api::namespaced(admin.clone(), &namespace);
        wait_for(
            "Genkan to become ready",
            Duration::from_secs(180),
            || async {
                deployments
                    .get(rbac::NAME)
                    .await
                    .ok()
                    .and_then(|d| d.status)
                    .and_then(|s| s.ready_replicas)
                    == Some(1)
            },
        )
        .await;

        // kube-apiserver side, exactly as `genkanctl kube-config --distro k3s` does it.
        let prepared = kube_config::prepare(
            admin.clone(),
            &kube_config::Request {
                namespace: namespace.clone(),
                distro: Distro::K3s,
                issuer: issuer.clone(),
                discovery: DiscoveryMode::Internal,
                audiences: vec!["kubernetes".into()],
                max_token_lifetime: Duration::from_hours(1),
                max_elevated_token_lifetime: Duration::from_mins(5),
                renew: false,
                certificate_validity: Duration::from_hours(24),
                now: SystemClock.now(),
            },
        )
        .await
        .unwrap();
        assert!(prepared.issued_until.is_some());
        write_authn(&authn_dir, &prepared.configuration);

        // The kubectl client, and a setup link for the first admin.
        let clients: Api<OAuthClient> = Api::namespaced(admin.clone(), &namespace);
        clients
            .create(
                &PostParams::default(),
                &OAuthClient::new(
                    "kubectl",
                    OAuthClientSpec {
                        display_name: None,
                        kind: ClientType::Public,
                        redirect_uris: vec![REDIRECT.into()],
                        audiences: vec!["kubernetes".into()],
                        secret_hash: None,
                        id_token_signing_alg: None,
                    },
                ),
            )
            .await
            .unwrap();
        let link = issue_setup_link(
            admin.clone(),
            &namespace,
            &issuer,
            "admin",
            Duration::from_mins(10),
            false,
            SystemClock.now(),
        )
        .await
        .unwrap();
        let token = link.url.split_once("#token=").unwrap().1.to_owned();

        // Reach the public listener through a NodePort on the node's address.
        let services: Api<Service> = Api::namespaced(admin.clone(), &namespace);
        let node_port = services
            .create(
                &PostParams::default(),
                &Service {
                    metadata: ObjectMeta {
                        name: Some("genkan-e2e-nodeport".into()),
                        ..ObjectMeta::default()
                    },
                    spec: Some(ServiceSpec {
                        type_: Some("NodePort".into()),
                        selector: Some(
                            [("app.kubernetes.io/name".into(), rbac::NAME.into())].into(),
                        ),
                        ports: Some(vec![ServicePort {
                            port: 80,
                            target_port: Some(
                                k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(
                                    deployment::HTTP_PORT,
                                ),
                            ),
                            ..ServicePort::default()
                        }]),
                        ..ServiceSpec::default()
                    }),
                    ..Service::default()
                },
            )
            .await
            .unwrap()
            .spec
            .unwrap()
            .ports
            .unwrap()[0]
            .node_port
            .unwrap();
        let node = Api::<Node>::all(admin.clone())
            .list(&ListParams::default())
            .await
            .unwrap()
            .items
            .remove(0);
        let node_name = node.name_any();
        let node_ip = node
            .status
            .and_then(|s| s.addresses)
            .unwrap()
            .into_iter()
            .find(|a| a.type_ == "InternalIP")
            .unwrap()
            .address;
        let address = format!("{node_ip}:{node_port}");
        wait_for(
            "the NodePort to accept connections",
            Duration::from_secs(60),
            || {
                let address = address.clone();
                async move { TcpStream::connect(&address).await.is_ok() }
            },
        )
        .await;
        let origin = Url::parse(ISSUER).unwrap();

        // Enrol a passkey from the link.
        let mut device = device();
        let reply = post_json(&address, "/setup/options", &json!({ "token": token }), "").await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let options: CredentialCreationOptions = serde_json::from_value(reply.json()).unwrap();
        let credential = device
            .register(&origin, options, DefaultClientData)
            .await
            .unwrap();
        let ceremony = reply.cookie(CEREMONY_COOKIE);
        let reply = post_json(
            &address,
            "/setup",
            &json!({ "token": token, "credential": credential, "label": "e2e" }),
            &format!("{CEREMONY_COOKIE}={ceremony}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);

        // Sign in as kubectl would: authorization request, passkey, code, token.
        let tokens = sign_in(&address, &mut device, "openid").await;
        assert!(tokens["refresh_token"].is_string());
        let access_token = tokens["access_token"].as_str().unwrap();
        let id_token = tokens["id_token"].as_str().unwrap();

        // kube-apiserver accepts the access token once it has loaded the configuration.
        let scratch = std::env::temp_dir();
        let as_user = token_kubeconfig(&scratch, "access", access_token);
        let mut whoami = String::new();
        wait_for(
            "kube-apiserver to accept the token",
            APISERVER_PICKUP,
            || {
                let result = kubectl(&as_user, &["auth", "whoami", "-o", "json"]);
                if let Ok(output) = &result {
                    whoami.clone_from(output);
                }
                async move { result.is_ok() }
            },
        )
        .await;
        let user = &serde_json::from_str::<Value>(&whoami).unwrap()["status"]["userInfo"];
        assert_eq!(user["username"], "genkan:admin", "{user}");
        let groups = user["groups"].as_array().unwrap();
        assert!(groups.contains(&json!("genkan:admins")), "{user}");
        assert!(groups.contains(&json!("system:authenticated")), "{user}");
        assert!(
            !groups
                .iter()
                .any(|g| g.as_str().unwrap().starts_with("system:masters"))
        );
        assert_eq!(
            user["extra"]["genkan.engawahq.dev/client-id"],
            json!(["kubectl"])
        );
        assert_eq!(
            user["extra"]["genkan.engawahq.dev/amr"],
            json!(["swk", "mfa"])
        );
        assert!(user["uid"].as_str().is_some_and(|uid| !uid.is_empty()));

        // Least privilege: a normal token can read, not administer.
        assert_eq!(
            can_i(&as_user, &["list", "pods", "--all-namespaces"]),
            "yes"
        );
        assert_eq!(can_i(&as_user, &["*", "*", "--all-namespaces"]), "no");

        // Elevation: another passkey sign-in with `elevate` yields a 5-minute token, without a
        // refresh token, in which the user is `genkan:elevated:admins`, bound to cluster-admin.
        let elevated = sign_in(&address, &mut device, "openid+elevate").await;
        assert!(elevated.get("refresh_token").is_none(), "{elevated}");
        assert_eq!(elevated["expires_in"], 300);
        let as_admin = token_kubeconfig(
            &scratch,
            "elevated",
            elevated["access_token"].as_str().unwrap(),
        );
        let whoami = kubectl(&as_admin, &["auth", "whoami", "-o", "json"]).unwrap();
        let groups =
            &serde_json::from_str::<Value>(&whoami).unwrap()["status"]["userInfo"]["groups"];
        assert!(
            groups
                .as_array()
                .unwrap()
                .contains(&json!("genkan:elevated:admins")),
            "{groups}"
        );
        assert_eq!(can_i(&as_admin, &["*", "*", "--all-namespaces"]), "yes");

        // ID tokens are for the client, not for the cluster.
        let as_id_token = token_kubeconfig(&scratch, "id", id_token);
        assert!(kubectl(&as_id_token, &["auth", "whoami"]).is_err());

        // Memory as the kubelet sees it (working set), after a full sign-in. The budget is
        // 30 MiB; the value is also written for CI's job summary.
        let summary: Value = serde_json::from_str(
            &admin
                .request_text(
                    Request::get(format!("/api/v1/nodes/{node_name}/proxy/stats/summary"))
                        .body(Vec::new())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        let working_set = summary["pods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|pod| pod["podRef"]["namespace"] == namespace.as_str())
            .and_then(|pod| pod["memory"]["workingSetBytes"].as_u64())
            .unwrap();
        if let Ok(path) = std::env::var("GENKAN_E2E_MEASUREMENTS") {
            std::fs::write(
                path,
                json!({ "pod_working_set_bytes": working_set }).to_string(),
            )
            .unwrap();
        }
        assert!(
            working_set <= 30 * 1024 * 1024,
            "working set {working_set} bytes exceeds 30 MiB"
        );

        // A partial reset can remove credentials while leaving a usable refresh-token family.
        // Prove the family's current token works, then retry reset with no credentials left.
        let refreshed = refresh(&address, tokens["refresh_token"].as_str().unwrap()).await;
        assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
        let refreshed = refreshed.json();
        let current_refresh = refreshed["refresh_token"].as_str().unwrap();
        let credentials: Api<Credential> = Api::namespaced(admin.clone(), &namespace);
        let selector = ListParams::default().labels(&format!("{USER_LABEL}=admin"));
        credentials
            .delete_collection(&DeleteParams::default(), &selector)
            .await
            .unwrap();
        assert!(credentials.list(&selector).await.unwrap().items.is_empty());
        issue_setup_link(
            admin.clone(),
            &namespace,
            &issuer,
            "admin",
            Duration::from_mins(10),
            true,
            SystemClock.now(),
        )
        .await
        .unwrap();
        let denied = refresh(&address, current_refresh).await;
        assert_eq!(denied.status, StatusCode::BAD_REQUEST, "{:?}", denied.body);
        assert_eq!(denied.json()["error"], "invalid_grant");

        // Clean up: forget the issuer, remove the namespace.
        write_authn(&authn_dir, EMPTY_AUTHN);
        for file in [as_user, as_admin, as_id_token] {
            drop(std::fs::remove_file(file));
        }
        Api::<Namespace>::all(admin)
            .delete(&namespace, &DeleteParams::background())
            .await
            .unwrap();
    }
}

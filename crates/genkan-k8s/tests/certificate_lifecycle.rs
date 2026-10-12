//! The admin client and actual TLS consumers, with a scripted HTTP API.
//! The fixture checks CAS request handling and ambiguous responses, not apiserver semantics;
//! the ignored cluster test exercises concurrent prepare against the real API.

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use genkan_core::clock::{Clock as _, SystemClock};
    use genkan_core::config::BaseUrl;
    use genkan_core::crypto::{hex, sha256};
    use genkan_k8s::internal_tls;
    use genkan_k8s::kube_config::{self, CertificateAction, DiscoveryMode, Distro, Request};
    use genkan_tls::listener::{Resolver, TlsListener, server_config};
    use k8s_openapi::api::core::v1::Secret;
    use kube::{Client, Config};
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsConnector;

    type Shared = Arc<Mutex<Fixture>>;

    #[derive(Default)]
    struct Fixture {
        secret: Option<Secret>,
        writes: u64,
        lose_response: bool,
        conflict: bool,
        api_url: String,
    }

    fn emitted_ca(configuration: &str) -> String {
        let document: Value = serde_saphyr::from_str(configuration).unwrap();
        document
            .get("jwt")
            .unwrap()
            .as_array()
            .unwrap()
            .first()
            .unwrap()
            .get("issuer")
            .unwrap()
            .get("certificateAuthority")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn status(code: StatusCode, reason: &str) -> (StatusCode, Json<Value>) {
        (
            code,
            Json(
                json!({"kind":"Status", "apiVersion":"v1", "status":"Failure", "reason":reason, "code":code.as_u16()}),
            ),
        )
    }

    async fn read(State(fixture): State<Shared>) -> (StatusCode, Json<Value>) {
        fixture.lock().await.secret.as_ref().map_or_else(
            || status(StatusCode::NOT_FOUND, "NotFound"),
            |secret| (StatusCode::OK, Json(serde_json::to_value(secret).unwrap())),
        )
    }

    async fn write(
        State(fixture): State<Shared>,
        Json(mut secret): Json<Secret>,
    ) -> (StatusCode, Json<Value>) {
        let mut state = fixture.lock().await;
        if state.conflict {
            state.conflict = false;
            drop(state);
            return status(StatusCode::CONFLICT, "Conflict");
        }
        assert_eq!(
            secret.metadata.resource_version,
            state
                .secret
                .as_ref()
                .and_then(|s| s.metadata.resource_version.clone())
        );
        state.writes += 1;
        secret.metadata.resource_version = Some(state.writes.to_string());
        secret.metadata.uid = Some("fixture-uid".into());
        state.secret = Some(secret.clone());
        if state.lose_response {
            state.lose_response = false;
            drop(state);
            return status(StatusCode::INTERNAL_SERVER_ERROR, "LostResponse");
        }
        drop(state);
        (StatusCode::OK, Json(serde_json::to_value(secret).unwrap()))
    }

    async fn api() -> (Client, Shared, JoinHandle<()>) {
        let fixture = Arc::new(Mutex::new(Fixture::default()));
        let app = Router::new()
        .route("/api/v1/namespaces/ns/services/genkan", get(|| async {
            Json(json!({"kind":"Service", "apiVersion":"v1", "metadata":{"name":"genkan","namespace":"ns"}, "spec":{"clusterIP":"127.0.0.1"}}))
        }))
        .route("/api/v1/namespaces/ns/secrets/genkan-internal-tls", get(read).put(write))
        .route("/api/v1/namespaces/ns/secrets", post(write))
        .with_state(Arc::clone(&fixture));
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        fixture.lock().await.api_url = format!("http://{address}");
        let task = tokio::spawn(async move {
            axum::serve(tcp, app).await.unwrap();
        });
        let client =
            Client::try_from(Config::new(format!("http://{address}").parse().unwrap())).unwrap();
        (client, fixture, task)
    }

    fn request() -> Request {
        Request {
            namespace: "ns".into(),
            distro: Distro::Generic,
            issuer: BaseUrl::parse("issuer", "https://login.example.com").unwrap(),
            discovery: DiscoveryMode::Internal,
            audiences: vec!["kubernetes".into()],
            max_token_lifetime: Duration::from_hours(1),
            max_elevated_token_lifetime: Duration::from_mins(5),
            certificate_action: CertificateAction::Current,
            rotation_id: None,
            certificate_validity: Duration::from_hours(24),
            now: SystemClock.now(),
        }
    }

    async fn tls(secret: &Secret) -> (SocketAddr, Arc<Resolver>, JoinHandle<()>) {
        let resolver = Arc::new(Resolver::default());
        resolver.set(internal_tls::parse(secret).unwrap().key);
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let listener =
            TlsListener::new(tcp, server_config(Arc::clone(&resolver)).unwrap()).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/", get(|| async { "ok" })))
                .await
                .unwrap();
        });
        (address, resolver, task)
    }

    async fn fetch(address: SocketAddr, ca: &str) -> std::io::Result<String> {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let tcp = TcpStream::connect(address).await?;
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(
                ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
                tcp,
            )
            .await?;
        let fingerprint = hex(&sha256(
            tls.get_ref()
                .1
                .peer_certificates()
                .unwrap()
                .first()
                .unwrap()
                .as_ref(),
        ));
        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = String::new();
        tls.read_to_string(&mut response).await?;
        assert!(response.starts_with("HTTP/1.1 200"));
        Ok(fingerprint)
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one trust transition observed through HTTP and actual TLS"
    )]
    async fn prepare_activation_retry_overlap_rollback_and_finish_preserve_trust() {
        let (client, fixture, api_task) = api().await;
        let mut request = request();
        let initial = kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        let old = fixture.lock().await.secret.clone().unwrap();
        let old_ca = emitted_ca(&initial.configuration);
        let (old_address, _, old_task) = tls(&old).await;
        assert_eq!(
            fetch(old_address, &old_ca).await.unwrap(),
            initial.serving_leaf_sha256.unwrap()
        );

        request.certificate_action = CertificateAction::Prepare;
        fixture.lock().await.lose_response = true;
        assert!(
            kube_config::prepare(client.clone(), &request)
                .await
                .is_err()
        );
        let staged = fixture.lock().await.secret.clone().unwrap();
        assert_eq!(
            old.data.as_ref().unwrap()["tls.crt"],
            staged.data.as_ref().unwrap()["tls.crt"]
        );
        // A new invocation after the committed write recovers solely from persisted state.
        let prepared = kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        let rotation = prepared.rotation.unwrap();
        assert_eq!(rotation.phase, "prepared");
        assert_eq!(
            fixture.lock().await.writes,
            2,
            "retry uses the persisted candidate"
        );
        let bundle = emitted_ca(&prepared.configuration);
        assert!(fetch(old_address, &old_ca).await.is_ok());
        assert!(fetch(old_address, &bundle).await.is_ok());
        let candidate_digest = prepared.candidate_leaf_sha256.unwrap();
        assert_ne!(
            rotation.id, candidate_digest,
            "rotation id is not a certificate fingerprint"
        );

        request.certificate_action = CertificateAction::Activate;
        request.rotation_id = Some("wrong-generation".into());
        assert!(
            kube_config::prepare(client.clone(), &request)
                .await
                .is_err()
        );
        request.rotation_id = Some(rotation.id.clone());
        fixture.lock().await.conflict = true;
        assert!(
            kube_config::prepare(client.clone(), &request)
                .await
                .is_err()
        );
        assert_eq!(
            fixture
                .lock()
                .await
                .secret
                .as_ref()
                .unwrap()
                .data
                .as_ref()
                .unwrap()["tls.crt"],
            old.data.as_ref().unwrap()["tls.crt"]
        );
        fixture.lock().await.lose_response = true;
        assert!(
            kube_config::prepare(client.clone(), &request)
                .await
                .is_err()
        );
        let active = fixture.lock().await.secret.clone().unwrap();
        let writes = fixture.lock().await.writes;
        let activated = kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        assert_eq!(
            fixture.lock().await.writes,
            writes,
            "ambiguous activation retry is idempotent"
        );
        assert_eq!(
            activated.serving_leaf_sha256.as_deref(),
            Some(candidate_digest.as_str())
        );
        let activated_bundle = emitted_ca(&activated.configuration);
        let (new_address, resolver, new_task) = tls(&active).await;
        assert!(fetch(new_address, &old_ca).await.is_err());
        assert_eq!(fetch(new_address, &bundle).await.unwrap(), candidate_digest);
        assert!(
            fetch(old_address, &bundle).await.is_ok(),
            "overlap trusts both rollout generations"
        );
        assert!(fetch(old_address, &activated_bundle).await.is_ok());
        assert_eq!(
            fetch(new_address, &activated_bundle).await.unwrap(),
            candidate_digest
        );

        request.certificate_action = CertificateAction::Rollback;
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        resolver.set(
            internal_tls::parse(fixture.lock().await.secret.as_ref().unwrap())
                .unwrap()
                .key,
        );
        assert!(fetch(new_address, &old_ca).await.is_ok());
        assert!(fetch(new_address, &bundle).await.is_ok());
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        request.certificate_action = CertificateAction::Activate;
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        resolver.set(
            internal_tls::parse(fixture.lock().await.secret.as_ref().unwrap())
                .unwrap()
                .key,
        );
        request.certificate_action = CertificateAction::Finish;
        let finished = kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        let final_ca = emitted_ca(&finished.configuration);
        assert_eq!(
            fetch(new_address, &final_ca).await.unwrap(),
            candidate_digest
        );
        assert!(fetch(old_address, &final_ca).await.is_err());
        assert_eq!(finished.rotation.unwrap().phase, "finished");
        kube_config::prepare(client, &request).await.unwrap();
        assert!(
            !fixture
                .lock()
                .await
                .secret
                .as_ref()
                .unwrap()
                .data
                .as_ref()
                .unwrap()
                .keys()
                .any(|key| key.starts_with("next.") || key.starts_with("previous."))
        );
        old_task.abort();
        new_task.abort();
        api_task.abort();
    }

    #[tokio::test]
    async fn cancellation_expiry_and_external_ownership_do_not_silently_replace_trust() {
        let (client, fixture, api_task) = api().await;
        let mut request = request();
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        let old = fixture.lock().await.secret.clone().unwrap();
        request.certificate_action = CertificateAction::Prepare;
        let prepared = kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        request.rotation_id = Some(prepared.rotation.unwrap().id);
        request.certificate_action = CertificateAction::Activate;
        request.now = request.now.saturating_add(Duration::from_hours(25));
        assert!(
            kube_config::prepare(client.clone(), &request)
                .await
                .is_err()
        );
        request.certificate_action = CertificateAction::Cancel;
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        assert_eq!(old.data, fixture.lock().await.secret.as_ref().unwrap().data);
        request.certificate_action = CertificateAction::Current;
        request.rotation_id = None;
        let writes = fixture.lock().await.writes;
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        assert_eq!(
            fixture.lock().await.writes,
            writes,
            "expiry cannot silently change trust"
        );
        fixture
            .lock()
            .await
            .secret
            .as_mut()
            .unwrap()
            .metadata
            .labels = None;
        let external = fixture.lock().await.secret.clone().unwrap();
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        request.certificate_action = CertificateAction::Prepare;
        assert!(kube_config::prepare(client, &request).await.is_err());
        assert_eq!(fixture.lock().await.secret, Some(external));
        api_task.abort();
    }

    #[tokio::test]
    async fn mismatched_candidate_key_and_invalid_rendering_fail_before_activation() {
        let (client, fixture, api_task) = api().await;
        let mut request = request();
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        let old = fixture.lock().await.secret.clone().unwrap();
        request.certificate_action = CertificateAction::Prepare;
        let prepared = kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        request.rotation_id = Some(prepared.rotation.unwrap().id);
        fixture
            .lock()
            .await
            .secret
            .as_mut()
            .unwrap()
            .data
            .as_mut()
            .unwrap()
            .insert(
                "next.tls.key".into(),
                old.data.as_ref().unwrap()["tls.key"].clone(),
            );
        request.certificate_action = CertificateAction::Activate;
        assert!(
            kube_config::prepare(client.clone(), &request)
                .await
                .is_err()
        );
        assert_eq!(
            old.data.as_ref().unwrap()["tls.crt"],
            fixture
                .lock()
                .await
                .secret
                .as_ref()
                .unwrap()
                .data
                .as_ref()
                .unwrap()["tls.crt"]
        );
        request.audiences = vec!["invalid audience".into()];
        let writes = fixture.lock().await.writes;
        assert!(kube_config::prepare(client, &request).await.is_err());
        assert_eq!(fixture.lock().await.writes, writes);
        api_task.abort();
    }

    #[tokio::test]
    #[ignore = "needs a disposable Kubernetes cluster and cluster-admin kubeconfig"]
    async fn real_apiserver_prepare_race_retains_one_generation_and_rejects_stale_activation() {
        use genkan_core::crypto::random;
        use k8s_openapi::api::core::v1::{Namespace, Service};
        use kube::api::{Api, DeleteParams, PostParams};
        use tokio::sync::Barrier;

        let client = Client::try_default().await.unwrap();
        let namespace = format!("genkan-ca-{}", hex(&random::<8>().unwrap()));
        let namespaces: Api<Namespace> = Api::all(client.clone());
        namespaces
            .create(
                &PostParams::default(),
                &Namespace {
                    metadata: kube::api::ObjectMeta {
                        name: Some(namespace.clone()),
                        ..Default::default()
                    },
                    ..Namespace::default()
                },
            )
            .await
            .unwrap();
        let services: Api<Service> = Api::namespaced(client.clone(), &namespace);
        let service = serde_json::from_value(json!({
            "metadata": {"name":"genkan","namespace":namespace},
            "spec": {"ports":[{"port":443,"targetPort":8443}]}
        }))
        .unwrap();
        services
            .create(&PostParams::default(), &service)
            .await
            .unwrap();
        let mut request = request();
        request.namespace = namespace.clone();
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        let secrets: Api<Secret> = Api::namespaced(client.clone(), &namespace);
        let original = secrets.get(internal_tls::SECRET).await.unwrap();
        request.certificate_action = CertificateAction::Prepare;
        let barrier = Arc::new(Barrier::new(64));
        let tasks: Vec<_> = (0..64)
            .map(|_| {
                let (client, request, barrier) =
                    (client.clone(), request.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    kube_config::prepare(client, &request).await
                })
            })
            .collect();
        let mut ids = Vec::new();
        for task in tasks {
            match task.await.unwrap() {
                Ok(prepared) => ids.push(prepared.rotation.unwrap().id),
                Err(kube_config::KubeConfigError::Kubernetes(kube::Error::Api(error)))
                    if error.code == 409 => {}
                Err(error) => panic!("unexpected prepare failure: {error}"),
            }
        }
        let staged = secrets.get(internal_tls::SECRET).await.unwrap();
        assert_eq!(
            original.data.as_ref().unwrap()["tls.crt"],
            staged.data.as_ref().unwrap()["tls.crt"]
        );
        let prepared = kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        let id = prepared.rotation.unwrap().id;
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.as_slice(), std::slice::from_ref(&id));
        request.rotation_id = Some(id);
        request.certificate_action = CertificateAction::Activate;
        kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        assert!(matches!(
            secrets.replace(internal_tls::SECRET, &PostParams::default(), &staged).await,
            Err(kube::Error::Api(error)) if error.code == 409
        ));
        let active = secrets.get(internal_tls::SECRET).await.unwrap();
        assert_ne!(
            original.data.as_ref().unwrap()["tls.crt"],
            active.data.as_ref().unwrap()["tls.crt"]
        );
        namespaces
            .delete(&namespace, &DeleteParams::background())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn expiry_warning_follows_the_active_certificate_at_the_inclusive_boundary() {
        let (client, fixture, api_task) = api().await;
        let mut request = request();
        request.certificate_validity = Duration::from_hours(60 * 24);
        let initial = kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        let until = initial.issued_until.unwrap();
        assert_eq!(initial.expiry_warning, None);
        request.now = until
            .saturating_sub(Duration::from_hours(30 * 24))
            .saturating_sub(Duration::from_secs(1));
        assert_eq!(
            kube_config::prepare(client.clone(), &request)
                .await
                .unwrap()
                .expiry_warning,
            None
        );
        request.now = request.now.saturating_add(Duration::from_secs(1));
        assert_eq!(
            kube_config::prepare(client.clone(), &request)
                .await
                .unwrap()
                .expiry_warning,
            Some(until)
        );
        request.now = until.saturating_add(Duration::from_secs(1));
        assert_eq!(
            kube_config::prepare(client.clone(), &request)
                .await
                .unwrap()
                .expiry_warning,
            Some(until)
        );
        assert_eq!(
            fixture.lock().await.writes,
            1,
            "warning never replaces active trust"
        );
        request.certificate_action = CertificateAction::Prepare;
        let staged = kube_config::prepare(client.clone(), &request)
            .await
            .unwrap();
        assert_eq!(
            staged.expiry_warning,
            Some(until),
            "a fresh candidate is not the active leaf"
        );
        request.rotation_id = Some(staged.rotation.unwrap().id);
        request.certificate_action = CertificateAction::Activate;
        let active = kube_config::prepare(client, &request).await.unwrap();
        assert_eq!(
            active.expiry_warning, None,
            "activation changes which expiry is reported"
        );
        api_task.abort();
    }

    async fn cli_output(
        binary: &std::path::Path,
        kubeconfig: &std::path::Path,
        action: &str,
        rotation_id: Option<&str>,
    ) -> std::process::Output {
        let (binary, kubeconfig, owned_action, rotation_id) = (
            binary.to_owned(),
            kubeconfig.to_owned(),
            action.to_owned(),
            rotation_id.map(str::to_owned),
        );
        let output = tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(binary);
            command.env("KUBECONFIG", kubeconfig).args([
                "kube-config",
                "--issuer",
                "https://login.example.com",
                "--distro",
                "generic",
                "--namespace",
                "ns",
                "--certificate-validity",
                "24h",
                "--certificate-action",
                &owned_action,
            ]);
            if let Some(id) = rotation_id {
                command.args(["--rotation-id", &id]);
            }
            command.output().unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(path) = std::env::var_os("GENKAN_CA_SMOKE_DIAGNOSTICS") {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap();
            writeln!(
                file,
                "{}",
                json!({
                    "action": action,
                    "stderr": String::from_utf8_lossy(&output.stderr),
                })
            )
            .unwrap();
        }
        output
    }

    async fn cli(
        binary: &std::path::Path,
        kubeconfig: &std::path::Path,
        action: &str,
        rotation_id: Option<&str>,
    ) -> String {
        String::from_utf8(
            cli_output(binary, kubeconfig, action, rotation_id)
                .await
                .stdout,
        )
        .unwrap()
    }

    fn advised_actions(stderr: &[u8]) -> Vec<String> {
        let diagnostics = String::from_utf8_lossy(stderr);
        let mut words = diagnostics.split_whitespace();
        let mut actions = Vec::new();
        while let Some(word) = words.next() {
            if word == "--certificate-action"
                && let Some(action) = words.next()
            {
                actions.push(
                    action
                        .trim_matches(|character: char| !character.is_ascii_alphabetic())
                        .to_owned(),
                );
            }
        }
        actions
    }

    fn reports_expiry(stderr: &[u8], expiry: genkan_core::clock::UnixTime) -> bool {
        String::from_utf8_lossy(stderr)
            .split_whitespace()
            .any(|word| {
                word.trim_matches(|character: char| !character.is_ascii_digit())
                    .parse::<u64>()
                    .ok()
                    == Some(expiry.as_secs())
            })
    }

    /// Runs the real CLI executable, parses stdout as an `AuthenticationConfiguration`, and
    /// consumes its trust through actual TLS. The HTTP fixture is not an external-host reload
    /// proof; the real-apiserver test separately exercises CAS semantics.
    /// Set `GENKAN_CA_SMOKE_DIAGNOSTICS` to record actual human stderr for operator inspection.
    /// Assertions use dynamic expiry dates and public CLI action values, never exact prose.
    #[tokio::test]
    #[ignore = "build genkanctl and set GENKANCTL_BIN to its absolute executable path"]
    #[expect(
        clippy::too_many_lines,
        reason = "one actual CLI and TLS lifecycle including operator diagnostics"
    )]
    async fn actual_cli_emitted_trust_supports_old_overlap_and_new_only_tls() {
        use genkan_core::crypto::random;

        let binary = std::path::PathBuf::from(
            std::env::var_os("GENKANCTL_BIN").expect("GENKANCTL_BIN is required"),
        );
        let (_, fixture, api_task) = api().await;
        let directory =
            std::env::temp_dir().join(format!("genkan-cli-ca-{}", hex(&random::<8>().unwrap())));
        std::fs::create_dir(&directory).unwrap();
        let kubeconfig = directory.join("kubeconfig.json");
        let api_url = fixture.lock().await.api_url.clone();
        std::fs::write(
            &kubeconfig,
            serde_json::to_vec(&json!({
                "apiVersion":"v1", "kind":"Config", "current-context":"smoke",
                "clusters":[{"name":"smoke","cluster":{"server":api_url}}],
                "users":[{"name":"smoke","user":{}}],
                "contexts":[{"name":"smoke","context":{"cluster":"smoke","user":"smoke"}}]
            }))
            .unwrap(),
        )
        .unwrap();

        let initial = cli(&binary, &kubeconfig, "current", None).await;
        let old_ca = emitted_ca(&initial);
        let old = fixture.lock().await.secret.clone().unwrap();
        let repeated_current = cli_output(&binary, &kubeconfig, "current", None).await;
        let expiry = internal_tls::parse(&old).unwrap().not_after.unwrap();
        assert!(reports_expiry(&repeated_current.stderr, expiry));
        let (old_address, _, old_task) = tls(&old).await;
        let old_fingerprint = fetch(old_address, &old_ca).await.unwrap();
        let prepared = cli(&binary, &kubeconfig, "prepare", None).await;
        let overlap = emitted_ca(&prepared);
        let staged = fixture.lock().await.secret.clone().unwrap();
        assert_eq!(
            old.data.as_ref().unwrap()["tls.crt"],
            staged.data.as_ref().unwrap()["tls.crt"]
        );
        assert_eq!(fetch(old_address, &overlap).await.unwrap(), old_fingerprint);
        let id =
            staged.metadata.annotations.as_ref().unwrap()["genkan.engawahq.dev/tls-rotation-id"]
                .clone();
        let retry = cli(&binary, &kubeconfig, "prepare", None).await;
        let retry_overlap = emitted_ca(&retry);
        assert_eq!(
            fetch(old_address, &retry_overlap).await.unwrap(),
            old_fingerprint
        );
        let activated = cli(&binary, &kubeconfig, "activate", Some(&id)).await;
        let activated_overlap = emitted_ca(&activated);
        let active = fixture.lock().await.secret.clone().unwrap();
        let (new_address, _, new_task) = tls(&active).await;
        let new_fingerprint = fetch(new_address, &overlap).await.unwrap();
        assert_ne!(old_fingerprint, new_fingerprint);
        assert!(fetch(new_address, &old_ca).await.is_err());
        assert!(fetch(old_address, &activated_overlap).await.is_ok());
        assert_eq!(
            fetch(new_address, &activated_overlap).await.unwrap(),
            new_fingerprint
        );
        let finished = cli_output(&binary, &kubeconfig, "finish", Some(&id)).await;
        assert!(
            !advised_actions(&finished.stderr)
                .iter()
                .any(|action| action == "activate" || action == "finish")
        );
        let new_ca = emitted_ca(&String::from_utf8(finished.stdout).unwrap());
        assert_eq!(fetch(new_address, &new_ca).await.unwrap(), new_fingerprint);
        assert!(fetch(old_address, &new_ca).await.is_err());
        cli(&binary, &kubeconfig, "prepare", None).await;
        let cancellation_id = fixture
            .lock()
            .await
            .secret
            .as_ref()
            .unwrap()
            .metadata
            .annotations
            .as_ref()
            .unwrap()["genkan.engawahq.dev/tls-rotation-id"]
            .clone();
        let cancelled = cli_output(&binary, &kubeconfig, "cancel", Some(&cancellation_id)).await;
        assert!(
            !advised_actions(&cancelled.stderr)
                .iter()
                .any(|action| action == "activate" || action == "finish")
        );
        assert_eq!(
            fetch(
                new_address,
                &emitted_ca(&String::from_utf8(cancelled.stdout).unwrap())
            )
            .await
            .unwrap(),
            new_fingerprint
        );
        let expired = genkan_tls::certificate::issue(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[],
            SystemClock.now().saturating_sub(Duration::from_hours(48)),
            Duration::from_hours(24),
        )
        .unwrap();
        fixture.lock().await.secret = Some(internal_tls::secret(
            "ns",
            &expired,
            &internal_tls::internal_url(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap(),
        ));
        let writes = fixture.lock().await.writes;
        let expired_current = cli_output(&binary, &kubeconfig, "current", None).await;
        assert!(reports_expiry(&expired_current.stderr, expired.not_after));
        assert_eq!(
            fixture.lock().await.writes,
            writes,
            "expired Current invocation must not replace trust"
        );
        old_task.abort();
        new_task.abort();
        api_task.abort();
        std::fs::remove_dir_all(directory).unwrap();
    }
}

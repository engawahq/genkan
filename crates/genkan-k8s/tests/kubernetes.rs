//! Integration tests against a real Kubernetes API server.
//!
//! They need a cluster in `KUBECONFIG` where the caller is cluster-admin (CI uses k3d). Every
//! test creates its own namespace, installs Genkan's RBAC there, and talks to the API as
//! Genkan's service account through impersonation, so the tests also prove the Role is
//! sufficient and nothing more is needed.
//!
//! Run: `cargo nextest run --run-ignored only -E 'binary(kubernetes)'`

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use genkan_core::clock::SystemClock;
    use genkan_k8s::crd::client::{ClientType, OAuthClient, OAuthClientSpec};
    use genkan_k8s::crd::grant::{Grant, GrantSpec, GrantStatus};
    use genkan_k8s::crd::user::{User, UserSpec};
    use genkan_k8s::crd::{EXPIRES_AT_ANNOTATION, EXPIRY_BUCKET_LABEL, definitions};
    use genkan_k8s::keys::SecretKeyStore;
    use genkan_k8s::objects::{
        CreateOutcome, DeleteOutcome, ReplaceOutcome, create_once, delete_if_unchanged,
        replace_status_if_unchanged,
    };
    use genkan_k8s::{KEY_SECRET, gc, rbac};
    use genkan_keys::manager::KeyManager;
    use genkan_keys::rotation::RotationPolicy;
    use k8s_openapi::api::core::v1::{Namespace, Secret, ServiceAccount};
    use k8s_openapi::api::rbac::v1::{Role, RoleBinding};
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, PostParams};
    use kube::{Client, Config, ResourceExt as _};
    use tokio::sync::{Barrier, watch};

    const RACERS: usize = 64;

    struct Env {
        admin: Client,
        genkan: Client,
        namespace: String,
    }

    impl Env {
        async fn new() -> Self {
            let admin = Client::try_default()
                .await
                .expect("KUBECONFIG must point at a test cluster");
            install_crds(&admin).await;

            let mut suffix = [0_u8; 4];
            aws_lc_rs::rand::fill(&mut suffix).unwrap();
            let namespace = format!("genkan-it-{}", hex(&suffix));
            install_rbac(&admin, &namespace).await;

            let mut config = Config::infer().await.unwrap();
            config.auth_info.impersonate =
                Some(format!("system:serviceaccount:{namespace}:{}", rbac::NAME));
            let genkan = Client::try_from(config).unwrap();
            Self {
                admin,
                genkan,
                namespace,
            }
        }

        fn genkan_api<K>(&self) -> Api<K>
        where
            K: kube::Resource<Scope = kube::core::NamespaceResourceScope, DynamicType = ()>,
        {
            Api::namespaced(self.genkan.clone(), &self.namespace)
        }

        fn admin_api<K>(&self) -> Api<K>
        where
            K: kube::Resource<Scope = kube::core::NamespaceResourceScope, DynamicType = ()>,
        {
            Api::namespaced(self.admin.clone(), &self.namespace)
        }

        async fn cleanup(self) {
            let namespaces: Api<Namespace> = Api::all(self.admin);
            namespaces
                .delete(&self.namespace, &DeleteParams::background())
                .await
                .unwrap();
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").unwrap();
            out
        })
    }

    async fn install_crds(admin: &Client) {
        let crds: Api<CustomResourceDefinition> = Api::all(admin.clone());
        for crd in definitions() {
            let name = crd.name_any();
            // Tests run in parallel processes; retry when another one wrote first.
            for attempt in 0.. {
                let result = match crds.get_opt(&name).await.unwrap() {
                    Some(existing) => {
                        let mut desired = crd.clone();
                        desired.metadata.resource_version = existing.metadata.resource_version;
                        crds.replace(&name, &PostParams::default(), &desired)
                            .await
                            .map(drop)
                    }
                    None => crds.create(&PostParams::default(), &crd).await.map(drop),
                };
                match result {
                    Ok(()) => break,
                    Err(error) if status_code(&error) == Some(409) && attempt < 20 => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(error) => panic!("installing {name}: {error}"),
                }
            }
            // Wait until the API server serves the new kind.
            for _ in 0..50 {
                let established = crds
                    .get(&name)
                    .await
                    .unwrap()
                    .status
                    .and_then(|s| s.conditions)
                    .is_some_and(|c| {
                        c.iter()
                            .any(|c| c.type_ == "Established" && c.status == "True")
                    });
                if established {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    async fn install_rbac(admin: &Client, namespace: &str) {
        for value in rbac::manifests(namespace).unwrap() {
            let pp = PostParams::default();
            match value["kind"].as_str().unwrap() {
                "Namespace" => {
                    Api::<Namespace>::all(admin.clone())
                        .create(&pp, &serde_json::from_value(value).unwrap())
                        .await
                        .unwrap();
                }
                "ServiceAccount" => {
                    Api::<ServiceAccount>::namespaced(admin.clone(), namespace)
                        .create(&pp, &serde_json::from_value(value).unwrap())
                        .await
                        .unwrap();
                }
                "Role" => {
                    Api::<Role>::namespaced(admin.clone(), namespace)
                        .create(&pp, &serde_json::from_value(value).unwrap())
                        .await
                        .unwrap();
                }
                "RoleBinding" => {
                    Api::<RoleBinding>::namespaced(admin.clone(), namespace)
                        .create(&pp, &serde_json::from_value(value).unwrap())
                        .await
                        .unwrap();
                }
                "Secret" => {
                    Api::<Secret>::namespaced(admin.clone(), namespace)
                        .create(&pp, &serde_json::from_value(value).unwrap())
                        .await
                        .unwrap();
                }
                "ClusterRoleBinding" => {
                    // Cluster-scoped and identical for every test namespace: create once.
                    let binding: k8s_openapi::api::rbac::v1::ClusterRoleBinding =
                        serde_json::from_value(value).unwrap();
                    if let Err(error) =
                        Api::<k8s_openapi::api::rbac::v1::ClusterRoleBinding>::all(admin.clone())
                            .create(&pp, &binding)
                            .await
                    {
                        assert_eq!(status_code(&error), Some(409), "{error}");
                    }
                }
                other => panic!("unexpected kind {other}"),
            }
        }
    }

    fn grant(name: &str, expires_at: Option<u64>) -> Grant {
        let mut grant = Grant::new(
            name,
            GrantSpec {
                user: "alice".into(),
                client: "kubectl".into(),
                audience: "kubernetes".into(),
                auth_time: 1_700_000_000,
                amr: vec!["hwk".into()],
                expires_at: 4_000_000_000,
                scopes: vec!["openid".into()],
                initial_idle_expires_at: 4_000_000_000,
                initial_hash: format!("sha256:{}", "0".repeat(64)),
            },
        );
        if let Some(expires_at) = expires_at {
            grant.metadata.labels = Some(BTreeMap::from([(
                EXPIRY_BUCKET_LABEL.to_owned(),
                (expires_at / 3600).to_string(),
            )]));
            grant.metadata.annotations = Some(BTreeMap::from([(
                EXPIRES_AT_ANNOTATION.to_owned(),
                expires_at.to_string(),
            )]));
        }
        grant
    }

    fn user_object(name: &str) -> User {
        User::new(
            name,
            UserSpec {
                username: name.into(),
                ..UserSpec::default()
            },
        )
    }

    fn status_code(error: &kube::Error) -> Option<u16> {
        if let kube::Error::Api(status) = error {
            Some(status.code)
        } else {
            None
        }
    }

    fn now() -> u64 {
        genkan_core::clock::Clock::now(&SystemClock).as_secs()
    }

    #[tokio::test]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    async fn usernames_are_dns_subdomains_with_at_most_63_characters() {
        let env = Env::new().await;
        let users: Api<User> = env.admin_api();
        let pp = PostParams::default();

        for username in [
            "a".to_owned(),
            "0".to_owned(),
            "alice".to_owned(),
            "alice-smith".to_owned(),
            "alice.example.com".to_owned(),
            "a-b.c-d".to_owned(),
            "a".repeat(63),
        ] {
            users
                .create(&pp, &user_object(&username))
                .await
                .unwrap_or_else(|error| panic!("valid username {username:?}: {error}"));
        }

        for username in [
            "",
            "Alice",
            "alice@example.com",
            "alice+ops",
            "alice_smith",
            "-alice",
            "alice-",
            ".alice",
            "alice.",
            "alice..smith",
            "alice.-smith",
            "alice-.smith",
            "alice\n",
            &"a".repeat(64),
        ] {
            // Keep metadata.name valid so rejection proves the username schema, not
            // Kubernetes' independent object-name validation.
            let mut user = user_object("invalid-username");
            user.spec.username = username.into();
            let error = users.create(&pp, &user).await.unwrap_err();
            assert_eq!(status_code(&error), Some(422), "{username:?}: {error}");
            let kube::Error::Api(status) = error else {
                panic!("expected an admission error");
            };
            assert!(
                status.message.contains("spec.username"),
                "{username:?}: {}",
                status.message
            );
        }

        env.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    #[expect(
        clippy::too_many_lines,
        reason = "one table-driven test per kind reads best in one place"
    )]
    async fn admission_rejects_invalid_objects() {
        let env = Env::new().await;
        let users: Api<User> = env.admin_api();
        let pp = PostParams::default();

        let user = |name: &str, username: &str, groups: &[&str]| {
            User::new(
                name,
                UserSpec {
                    username: username.into(),
                    display_name: None,
                    groups: groups.iter().map(|g| (*g).into()).collect(),
                    disabled: false,
                    ..UserSpec::default()
                },
            )
        };
        let created = users
            .create(&pp, &user("alice", "alice", &["admins", "team/dev"]))
            .await
            .unwrap();

        for (name, username, groups) in [
            ("u1", "Alice", &[][..]),
            ("u2", "-alice", &[][..]),
            ("u3", "bob", &["system:masters"][..]),
            ("u4", "bob", &["elevated:admins"][..]),
        ] {
            let error = users
                .create(&pp, &user(name, username, groups))
                .await
                .unwrap_err();
            assert_eq!(status_code(&error), Some(422), "{name}: {error}");
        }

        let mut renamed = created;
        renamed.spec.username = "mallory".into();
        let error = users.replace("alice", &pp, &renamed).await.unwrap_err();
        assert_eq!(
            status_code(&error),
            Some(422),
            "username must be immutable: {error}"
        );

        let clients: Api<OAuthClient> = env.admin_api();
        let client = |name: &str, kind, uris: &[&str], secret: Option<&str>| {
            OAuthClient::new(
                name,
                OAuthClientSpec {
                    display_name: None,
                    kind,
                    redirect_uris: uris.iter().map(|u| (*u).into()).collect(),
                    audiences: vec![],
                    secret_hash: secret.map(Into::into),
                    id_token_signing_alg: None,
                },
            )
        };
        let hash = format!("sha256:{}", "a".repeat(64));
        clients
            .create(
                &pp,
                &client(
                    "kubectl",
                    ClientType::Public,
                    &["http://127.0.0.1:8000/", "http://[::1]/cb"],
                    None,
                ),
            )
            .await
            .unwrap();
        clients
            .create(
                &pp,
                &client(
                    "web",
                    ClientType::Confidential,
                    &["https://app.example.com/cb"],
                    Some(&hash),
                ),
            )
            .await
            .unwrap();
        for (name, kind, uris, secret) in [
            (
                "c1",
                ClientType::Public,
                &["http://app.example.com/cb"][..],
                None,
            ),
            (
                "c2",
                ClientType::Public,
                &["https://app.example.com/cb#x"][..],
                None,
            ),
            ("c3", ClientType::Public, &[][..], None),
            (
                "c4",
                ClientType::Public,
                &["https://app.example.com/cb"][..],
                Some(hash.as_str()),
            ),
            (
                "c5",
                ClientType::Confidential,
                &["https://app.example.com/cb"][..],
                None,
            ),
            (
                "c6",
                ClientType::Confidential,
                &["https://app.example.com/cb"][..],
                Some("plaintext-secret"),
            ),
        ] {
            let error = clients
                .create(&pp, &client(name, kind, uris, secret))
                .await
                .unwrap_err();
            assert_eq!(status_code(&error), Some(422), "{name}: {error}");
        }

        let grants: Api<Grant> = env.admin_api();
        let mut stored = grants.create(&pp, &grant("g", None)).await.unwrap();
        stored.spec.user = "mallory".into();
        let error = grants.replace("g", &pp, &stored).await.unwrap_err();
        assert_eq!(
            status_code(&error),
            Some(422),
            "grant spec must be immutable: {error}"
        );

        env.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    async fn service_account_has_least_privilege() {
        let env = Env::new().await;
        let secrets: Api<Secret> = env.genkan_api();
        // Allowed: its own key Secret.
        secrets.get(KEY_SECRET).await.unwrap();
        // Denied: listing Secrets, reading or creating any other Secret.
        assert_eq!(
            status_code(&secrets.list(&ListParams::default()).await.unwrap_err()),
            Some(403)
        );
        let other = Secret {
            metadata: ObjectMeta {
                name: Some("other".into()),
                ..ObjectMeta::default()
            },
            ..Secret::default()
        };
        assert_eq!(
            status_code(
                &secrets
                    .create(&PostParams::default(), &other)
                    .await
                    .unwrap_err()
            ),
            Some(403)
        );
        Api::<Secret>::namespaced(env.admin.clone(), &env.namespace)
            .create(&PostParams::default(), &other)
            .await
            .unwrap();
        assert_eq!(
            status_code(&secrets.get("other").await.unwrap_err()),
            Some(403)
        );
        // Denied: changing RBAC, which could grant anyone anything.
        let bindings: Api<RoleBinding> = env.genkan_api();
        let binding: RoleBinding = serde_json::from_value(serde_json::json!({
            "metadata": {"name": "escalate"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "Group", "name": "system:authenticated"}]
        }))
        .unwrap();
        assert_eq!(
            status_code(
                &bindings
                    .create(&PostParams::default(), &binding)
                    .await
                    .unwrap_err()
            ),
            Some(403)
        );
        // Denied: writing users' spec (only status).
        let users: Api<User> = env.genkan_api();
        let user = User::new(
            "bob",
            UserSpec {
                username: "bob".into(),
                display_name: None,
                groups: vec![],
                disabled: false,
                ..UserSpec::default()
            },
        );
        assert_eq!(
            status_code(
                &users
                    .create(&PostParams::default(), &user)
                    .await
                    .unwrap_err()
            ),
            Some(403)
        );
        // Denied: anything in another namespace.
        let elsewhere: Api<Grant> = Api::namespaced(env.genkan.clone(), "default");
        assert_eq!(
            status_code(&elsewhere.list(&ListParams::default()).await.unwrap_err()),
            Some(403)
        );
        env.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    async fn signing_keys_persist_and_only_one_writer_wins() {
        let env = Env::new().await;
        let store = || SecretKeyStore::new(env.genkan_api(), KEY_SECRET);
        let kids = |manager: &KeyManager<SecretKeyStore, SystemClock>| {
            let published = manager.subscribe().borrow().clone().unwrap();
            let set: serde_json::Value = serde_json::from_slice(&published.jwks()).unwrap();
            let mut kids: Vec<String> = set["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k["kid"].as_str().unwrap().to_owned())
                .collect();
            kids.sort();
            kids
        };

        // Many replicas start at once against the empty, installer-created Secret.
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let barrier = Arc::clone(&barrier);
            let manager = KeyManager::new(store(), SystemClock, RotationPolicy::DEFAULT);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                // Losers see a conflict and succeed on the retry, reading the winner's keys.
                for _ in 0..5 {
                    if manager.reconcile().await.is_ok() {
                        return manager;
                    }
                }
                panic!("reconcile kept failing");
            }));
        }
        let mut managers = Vec::new();
        for task in tasks {
            managers.push(task.await.unwrap());
        }
        let first = kids(&managers[0]);
        assert_eq!(first.len(), 2);
        for manager in &managers {
            assert_eq!(
                kids(manager),
                first,
                "every replica publishes the winner's keys"
            );
        }

        // A restarted process loads the same keys.
        let restarted = KeyManager::new(store(), SystemClock, RotationPolicy::DEFAULT);
        restarted.reconcile().await.unwrap();
        assert_eq!(kids(&restarted), first);

        // The stored form contains no plaintext key material outside the Secret's data.
        let secret: Secret = env.admin_api::<Secret>().get(KEY_SECRET).await.unwrap();
        assert_eq!(secret.type_.as_deref(), Some(genkan_k8s::keys::SECRET_TYPE));
        env.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    async fn exactly_one_racer_wins_each_primitive() {
        let env = Env::new().await;
        let grants: Api<Grant> = env.genkan_api();

        // create_once: one Created, the rest AlreadyExists.
        let barrier = Arc::new(Barrier::new(RACERS));
        let tasks: Vec<_> = (0..RACERS)
            .map(|_| {
                let (grants, barrier) = (grants.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    create_once(&grants, &grant("race", None)).await.unwrap()
                })
            })
            .collect();
        let mut created = 0;
        for task in tasks {
            match task.await.unwrap() {
                CreateOutcome::Created(_) => created += 1,
                CreateOutcome::AlreadyExists => {}
            }
        }
        assert_eq!(created, 1);

        // replace_status_if_unchanged: one Replaced from the same resourceVersion.
        let base = grants.get("race").await.unwrap();
        let barrier = Arc::new(Barrier::new(RACERS));
        let tasks: Vec<_> = (0..RACERS)
            .map(|i| {
                let (grants, barrier, mut object) =
                    (grants.clone(), Arc::clone(&barrier), base.clone());
                tokio::spawn(async move {
                    object.status = Some(GrantStatus {
                        rotation: 1,
                        current_hash: format!("sha256:{i:064x}"),
                        previous_hash: None,
                        idle_expires_at: 0,
                    });
                    barrier.wait().await;
                    replace_status_if_unchanged(&grants, &object).await.unwrap()
                })
            })
            .collect();
        let (mut replaced, mut conflicts) = (0, 0);
        for task in tasks {
            match task.await.unwrap() {
                ReplaceOutcome::Replaced(_) => replaced += 1,
                ReplaceOutcome::Conflict => conflicts += 1,
                ReplaceOutcome::NotFound => panic!("object vanished"),
            }
        }
        assert_eq!((replaced, conflicts), (1, RACERS - 1));

        // delete_if_unchanged: a stale version does not delete; the current one deletes once.
        let current = grants.get("race").await.unwrap();
        let uid = current.uid().unwrap();
        let stale = base.resource_version().unwrap();
        assert_eq!(
            delete_if_unchanged(&grants, "race", &uid, &stale)
                .await
                .unwrap(),
            DeleteOutcome::Changed
        );
        let rv = current.resource_version().unwrap();
        let barrier = Arc::new(Barrier::new(RACERS));
        let tasks: Vec<_> = (0..RACERS)
            .map(|_| {
                let (grants, barrier, uid, rv) = (
                    grants.clone(),
                    Arc::clone(&barrier),
                    uid.clone(),
                    rv.clone(),
                );
                tokio::spawn(async move {
                    barrier.wait().await;
                    delete_if_unchanged(&grants, "race", &uid, &rv).await
                })
            })
            .collect();
        // k3s (kine on SQLite) answers some losing deletes with `500 unexpected end of JSON
        // input` instead of 404/409. Such an ambiguous answer is an error for the caller, who
        // must fail closed; what matters is that exactly one delete reports success.
        let (mut deleted, mut ambiguous) = (0, 0);
        for task in tasks {
            match task.await.unwrap() {
                Ok(DeleteOutcome::Deleted) => deleted += 1,
                Ok(DeleteOutcome::NotFound | DeleteOutcome::Changed) => {}
                Err(error) => {
                    assert_eq!(status_code(&error), Some(500), "{error}");
                    ambiguous += 1;
                }
            }
        }
        eprintln!("delete race: {deleted} deleted, {ambiguous} ambiguous of {RACERS}");
        assert_eq!(deleted, 1);
        assert!(grants.get_opt("race").await.unwrap().is_none());

        // A new object with the same name is not deleted by the old object's preconditions.
        create_once(&grants, &grant("race", None)).await.unwrap();
        assert_eq!(
            delete_if_unchanged(&grants, "race", &uid, &rv)
                .await
                .unwrap(),
            DeleteOutcome::Changed
        );
        env.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    async fn garbage_collector_deletes_expired_objects_only() {
        let env = Env::new().await;
        let grants: Api<Grant> = env.genkan_api();
        let t0 = now();
        for (name, expires) in [
            ("expired", Some(t0 - 10)),
            ("soon", Some(t0 + 4)),
            ("extended", Some(t0 + 4)),
            ("later", Some(t0 + 3600)),
            ("unlabelled", None),
        ] {
            create_once(&grants, &grant(name, expires)).await.unwrap();
        }

        let (stop, shutdown) = watch::channel(false);
        let collector = tokio::spawn({
            let (client, namespace) = (env.genkan.clone(), env.namespace.clone());
            async move { gc::run::<Grant, _>(client, &namespace, SystemClock, shutdown).await }
        });

        // A refresh extends "extended" before it expires; the collector must notice.
        let mut extended = grants.get("extended").await.unwrap();
        extended
            .annotations_mut()
            .insert(EXPIRES_AT_ANNOTATION.to_owned(), (t0 + 3600).to_string());
        grants
            .replace("extended", &PostParams::default(), &extended)
            .await
            .unwrap();

        let exists = |name: &'static str| {
            let grants = grants.clone();
            async move { grants.get_opt(name).await.unwrap().is_some() }
        };
        let mut gone_expired = None;
        let mut gone_soon = None;
        for tick in 0..100 {
            if gone_expired.is_none() && !exists("expired").await {
                gone_expired = Some(tick);
            }
            if gone_soon.is_none() && !exists("soon").await {
                gone_soon = Some(now());
            }
            if gone_expired.is_some() && gone_soon.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            gone_expired.is_some(),
            "an already expired object is collected"
        );
        let soon_at = gone_soon.expect("an object is collected once it expires");
        assert!(
            soon_at >= t0 + 4,
            "never before its expiry ({soon_at} < {})",
            t0 + 4
        );

        tokio::time::sleep(Duration::from_secs(2)).await;
        for name in ["extended", "later", "unlabelled"] {
            assert!(exists(name).await, "{name} must survive");
        }
        stop.send_replace(true);
        collector.await.unwrap();
        env.cleanup().await;
    }

    fn new_grant(name: &str, now: u64) -> genkan_store::NewGrant {
        genkan_store::NewGrant {
            name: name.to_owned(),
            user: "alice".into(),
            client: "kubectl".into(),
            audience: "kubernetes".into(),
            scopes: vec!["openid".into()],
            auth_time: genkan_core::clock::UnixTime::from_secs(now),
            amr: vec!["hwk".into()],
            expires_at: genkan_core::clock::UnixTime::from_secs(now + 3600),
            initial_hash: genkan_core::crypto::hash_secret(b"token-0"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    async fn grant_rotation_is_linearizable() {
        use genkan_core::clock::UnixTime;
        use genkan_core::crypto::hash_secret;
        use genkan_k8s::grants::KubeGrantStore;
        use genkan_store::{CreateGrant, GrantStore, Rotation};

        let env = Env::new().await;
        env.admin_api::<User>()
            .create(&PostParams::default(), &user_object("alice"))
            .await
            .unwrap();
        let store = KubeGrantStore::new(env.genkan_api());
        let t0 = now();
        let idle = UnixTime::from_secs(t0 + 1800);
        let name = format!("g-{}", "1".repeat(64));
        assert_eq!(
            store.create(&new_grant(&name, t0), idle).await.unwrap(),
            CreateGrant::Created
        );
        assert_eq!(
            store.create(&new_grant(&name, t0), idle).await.unwrap(),
            CreateGrant::AlreadyExists
        );

        // 64 holders of the same token rotate at once: one wins, every other one is a replay.
        let barrier = Arc::new(Barrier::new(RACERS));
        let tasks: Vec<_> = (0..RACERS)
            .map(|i| {
                let (store, name, barrier) = (store.clone(), name.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    let next = hash_secret(format!("token-1-{i}").as_bytes());
                    store
                        .rotate(
                            &name,
                            &hash_secret(b"token-0"),
                            &next,
                            UnixTime::from_secs(t0),
                            idle,
                        )
                        .await
                })
            })
            .collect();
        let (mut rotated, mut replays, mut errors) = (0, 0, 0);
        for task in tasks {
            match task.await.unwrap() {
                Ok(Rotation::Rotated(_)) => rotated += 1,
                Ok(Rotation::Replay) => replays += 1,
                Ok(other) => panic!("unexpected {other:?}"),
                // Heavy contention may exhaust the retries; callers fail closed.
                Err(_) => errors += 1,
            }
        }
        eprintln!("rotation race: {rotated} rotated, {replays} replays, {errors} errors");
        assert_eq!(rotated, 1);
        assert_eq!(rotated + replays + errors, RACERS);

        let grant = store.get(&name).await.unwrap().unwrap();
        assert_eq!(grant.rotation, 1);
        assert_eq!(
            grant.previous_hash.as_deref(),
            Some(hash_secret(b"token-0").as_str())
        );
        let presented = grant.current_hash.clone();
        assert!(matches!(
            store
                .rotate(
                    &name,
                    "sha256:unknown",
                    &presented,
                    UnixTime::from_secs(t0),
                    idle
                )
                .await
                .unwrap(),
            Rotation::Invalid
        ));
        assert!(matches!(
            store
                .rotate(
                    &name,
                    &grant.current_hash,
                    &hash_secret(b"late"),
                    UnixTime::from_secs(t0 + 7200),
                    idle
                )
                .await
                .unwrap(),
            Rotation::Expired
        ));
        store.revoke(&name).await.unwrap();
        store.revoke(&name).await.unwrap();
        assert!(store.get(&name).await.unwrap().is_none());
        env.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    #[expect(
        clippy::too_many_lines,
        reason = "one end-to-end scenario reads best top to bottom"
    )]
    async fn oauth_flow_on_kubernetes_storage() {
        use genkan_core::config::BaseUrl;
        use genkan_core::crypto::Sealer;
        use genkan_k8s::directory::KubeDirectory;
        use genkan_k8s::grants::KubeGrantStore;
        use genkan_oauth::authorize::Authentication;
        use genkan_oauth::endpoints::{FLOW_COOKIE, complete_authorization, router};
        use genkan_oauth::{AuthorizationServer, Lifetimes, OneTimeIds};

        let env = Env::new().await;
        let pp = PostParams::default();
        env.admin_api::<User>()
            .create(
                &pp,
                &User::new(
                    "alice",
                    UserSpec {
                        username: "alice".into(),
                        display_name: None,
                        groups: vec!["admins".into()],
                        disabled: false,
                        ..UserSpec::default()
                    },
                ),
            )
            .await
            .unwrap();
        env.admin_api::<OAuthClient>()
            .create(
                &pp,
                &OAuthClient::new(
                    "kubectl",
                    OAuthClientSpec {
                        display_name: None,
                        kind: ClientType::Public,
                        redirect_uris: vec!["http://127.0.0.1:8000/".into()],
                        audiences: vec!["kubernetes".into()],
                        secret_hash: None,
                        id_token_signing_alg: None,
                    },
                ),
            )
            .await
            .unwrap();

        let manager = KeyManager::new(
            SecretKeyStore::new(env.genkan_api(), KEY_SECRET),
            SystemClock,
            RotationPolicy::DEFAULT,
        );
        manager.reconcile().await.unwrap();
        let server = Arc::new(AuthorizationServer {
            issuer: BaseUrl::parse("issuer", "https://login.example.com").unwrap(),
            lifetimes: Lifetimes::DEFAULT,
            directory: KubeDirectory::new(env.genkan_api(), env.genkan_api()),
            grants: KubeGrantStore::new(env.genkan_api()),
            clock: SystemClock,
            keys: manager.subscribe(),
            sealer: Sealer::ephemeral().unwrap(),
            used_codes: OneTimeIds::default(),
            used_request_uris: OneTimeIds::default(),
        });
        let app = router(Arc::clone(&server));
        let call = |request: axum::http::Request<axum::body::Body>| {
            let app = app.clone();
            async move {
                use http_body_util::BodyExt as _;
                use tower::ServiceExt as _;
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let headers = response.headers().clone();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (status, headers, body)
            }
        };
        let form = |pairs: &[(&str, &str)]| {
            axum::http::Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(
                    form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(pairs)
                        .finish(),
                ))
                .unwrap()
        };

        let authorize = "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";
        let (status, headers, _) = call(
            axum::http::Request::get(authorize)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, 303);
        let cookie = headers["set-cookie"].to_str().unwrap();
        let flow = cookie
            .strip_prefix(&format!("{FLOW_COOKIE}="))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let auth = Authentication {
            user: "alice".into(),
            auth_time: genkan_core::clock::Clock::now(&SystemClock),
            amr: vec!["hwk".into()],
        };
        let location = complete_authorization(&server, flow, auth).unwrap();
        let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (status, _, body) = call(form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", verifier),
            ("client_id", "kubectl"),
        ]))
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let first = tokens["refresh_token"].as_str().unwrap().to_owned();
        let grant_name = first.split('.').next().unwrap().to_owned();
        let stored = env.admin_api::<Grant>().get(&grant_name).await.unwrap();
        assert!(
            stored.status.is_none(),
            "creating a family is a single write"
        );
        assert!(
            !serde_json::to_string(&stored)
                .unwrap()
                .contains(first.split('.').nth(1).unwrap()),
            "only hashes are stored"
        );

        let (status, _, body) = call(form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &first),
            ("client_id", "kubectl"),
        ]))
        .await;
        assert_eq!(status, 200);
        let second = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();

        // Replay of the first token deletes the Grant object.
        let (status, ..) = call(form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &first),
            ("client_id", "kubectl"),
        ]))
        .await;
        assert_eq!(status, 400);
        assert!(
            env.admin_api::<Grant>()
                .get_opt(&grant_name)
                .await
                .unwrap()
                .is_none()
        );
        let (status, ..) = call(form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &second),
            ("client_id", "kubectl"),
        ]))
        .await;
        assert_eq!(status, 400);
        env.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    #[expect(clippy::too_many_lines, reason = "one User lifecycle scenario")]
    async fn user_recreation_collects_only_the_original_users_dependents() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use genkan_core::clock::UnixTime;
        use genkan_core::config::BaseUrl;
        use genkan_k8s::crd::credential::Credential;
        use genkan_k8s::crd::invitation::Invitation;
        use genkan_k8s::credentials::KubeCredentialStore;
        use genkan_k8s::grants::KubeGrantStore;
        use genkan_k8s::invitations::{Invitee, invite};
        use genkan_k8s::setup::{SETUP_SECRET, issue_setup_link};
        use genkan_store::{
            CredentialStore as _, CredentialType, GrantStore as _, NewExternal, NewPasskey,
            external_credential_name, passkey_credential_name,
        };

        let env = Env::new().await;
        let users: Api<User> = env.admin_api();
        let credentials: Api<Credential> = env.genkan_api();
        let grants: Api<Grant> = env.genkan_api();
        let invitations: Api<Invitation> = env.genkan_api();
        let secrets: Api<Secret> = env.genkan_api();
        let credential_store = KubeCredentialStore::new(credentials.clone());
        let grant_store = KubeGrantStore::new(grants.clone());
        let user = user_object("alice");
        let pp = PostParams::default();
        let mut uid = users.create(&pp, &user).await.unwrap().uid().unwrap();
        let issuer = BaseUrl::parse("issuer", "https://login.example.com").unwrap();
        let t0 = now();
        let time = UnixTime::from_secs(t0);
        let valid_for = Duration::from_hours(1);
        let invitee = Invitee {
            username: "alice".into(),
            display_name: None,
            groups: vec![],
            elevated_groups: vec![],
        };

        // Setup precedes credentials; only GC, never reset, removes these dependents.
        issue_setup_link(
            env.admin.clone(),
            &env.namespace,
            &issuer,
            "alice",
            valid_for,
            false,
            time,
        )
        .await
        .unwrap();
        assert_eq!(
            secrets.get(SETUP_SECRET).await.unwrap().owner_references()[0].uid,
            uid
        );

        let mut original = None;
        for (generation, digit) in [("old", "1"), ("fresh", "2")] {
            let passkey = NewPasskey {
                name: passkey_credential_name(generation.as_bytes()),
                user: "alice".into(),
                credential_id: URL_SAFE_NO_PAD.encode(generation.as_bytes()),
                record: "{}".into(),
                label: None,
            };
            credential_store.create(&passkey).await.unwrap();
            let external = NewExternal {
                name: external_credential_name("https://github.com", generation),
                user: "alice".into(),
                kind: CredentialType::GitHub,
                issuer: "https://github.com".into(),
                subject: generation.into(),
            };
            credential_store.link(&external).await.unwrap();
            let grant = format!("g-{}", digit.repeat(64));
            grant_store
                .create(&new_grant(&grant, t0), UnixTime::from_secs(t0 + 1800))
                .await
                .unwrap();
            let invitation = invite(
                env.admin.clone(),
                &env.namespace,
                &issuer,
                &invitee,
                valid_for,
                time,
            )
            .await
            .unwrap();
            let metadata = [
                credentials.get(&passkey.name).await.unwrap().metadata,
                credentials.get(&external.name).await.unwrap().metadata,
                grants.get(&grant).await.unwrap().metadata,
                invitations.get(&invitation.name).await.unwrap().metadata,
            ];
            for object in metadata {
                assert_eq!(object.owner_references.unwrap()[0].uid, uid);
            }
            if generation == "old" {
                original = Some((passkey.name, external.name, grant, invitation.name));
                users
                    .delete("alice", &DeleteParams::background())
                    .await
                    .unwrap();
                // Recreate immediately, without waiting for GC of the original dependents.
                let replacement = users.create(&pp, &user).await.unwrap().uid().unwrap();
                assert_ne!(replacement, uid);
                uid = replacement;
            } else {
                // Wait for all old objects together; fresh ones must remain after collection.
                let (old_passkey, old_external, old_grant, old_invitation) =
                    original.as_ref().unwrap();
                tokio::time::timeout(Duration::from_secs(120), async {
                    loop {
                        if credentials.get_opt(old_passkey).await.unwrap().is_none()
                            && credentials.get_opt(old_external).await.unwrap().is_none()
                            && grants.get_opt(old_grant).await.unwrap().is_none()
                            && invitations.get_opt(old_invitation).await.unwrap().is_none()
                            && secrets.get_opt(SETUP_SECRET).await.unwrap().is_none()
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                })
                .await
                .expect("the original User's dependents were not garbage-collected");
                assert_eq!(users.get("alice").await.unwrap().uid().unwrap(), uid);
                assert_eq!(
                    credentials.get(&passkey.name).await.unwrap().spec.user,
                    "alice"
                );
                assert_eq!(
                    credentials.get(&external.name).await.unwrap().spec.user,
                    "alice"
                );
                assert_eq!(grants.get(&grant).await.unwrap().spec.user, "alice");
                assert_eq!(
                    invitations.get(&invitation.name).await.unwrap().spec.user,
                    "alice"
                );
            }
        }
        env.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    #[expect(
        clippy::too_many_lines,
        reason = "one end-to-end scenario reads best top to bottom"
    )]
    async fn setup_link_is_single_use_and_replaceable() {
        use genkan_core::config::BaseUrl;
        use genkan_k8s::setup::{KubeSetupStore, SETUP_SECRET, SetupLinkError, issue_setup_link};
        use genkan_store::{Consume, SetupStore};

        let env = Env::new().await;
        let issuer = BaseUrl::parse("issuer", "https://login.example.com").unwrap();
        let t0 = genkan_core::clock::UnixTime::from_secs(now());
        let link = issue_setup_link(
            env.admin.clone(),
            &env.namespace,
            &issuer,
            "root",
            Duration::from_mins(60),
            false,
            t0,
        )
        .await
        .unwrap();
        assert!(
            link.url
                .starts_with("https://login.example.com/setup#token=")
        );
        let user = env.admin_api::<User>().get("root").await.unwrap();
        assert_eq!(user.spec.groups, ["admins"]);

        // Genkan reads the token; the Secret holds only its hash.
        let store = KubeSetupStore::new(env.genkan_api());
        let raw = link.url.split("#token=").nth(1).unwrap();
        let token = store.load(raw).await.unwrap().unwrap();
        assert_eq!(
            token.token_hash,
            genkan_core::crypto::hash_secret(raw.as_bytes())
        );
        let secret: Secret = env.admin_api::<Secret>().get(SETUP_SECRET).await.unwrap();
        assert!(!serde_json::to_string(&secret).unwrap().contains(raw));

        // Regenerating invalidates what was read before.
        issue_setup_link(
            env.admin.clone(),
            &env.namespace,
            &issuer,
            "root",
            Duration::from_mins(60),
            false,
            t0,
        )
        .await
        .unwrap();
        assert_eq!(store.consume(&token).await.unwrap(), Consume::AlreadyUsed);

        // 64 concurrent redemptions of the current token: exactly one consumes it.
        let token = store.load(raw).await.unwrap().unwrap();
        let barrier = Arc::new(Barrier::new(RACERS));
        let tasks: Vec<_> = (0..RACERS)
            .map(|_| {
                let (store, token, barrier) = (store.clone(), token.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    store.consume(&token).await
                })
            })
            .collect();
        let mut consumed = 0;
        for task in tasks {
            if task.await.unwrap() == Ok(Consume::Consumed) {
                consumed += 1;
            }
        }
        assert_eq!(consumed, 1);
        assert!(store.load(raw).await.unwrap().is_none());

        // Genkan cannot mint a setup token itself.
        let forged = Secret {
            metadata: ObjectMeta {
                name: Some(SETUP_SECRET.into()),
                ..ObjectMeta::default()
            },
            ..Secret::default()
        };
        assert_eq!(
            status_code(
                &env.genkan_api::<Secret>()
                    .create(&PostParams::default(), &forged)
                    .await
                    .unwrap_err()
            ),
            Some(403)
        );

        // A user who already has passkeys needs an explicit reset.
        let credentials: Api<genkan_k8s::crd::credential::Credential> = env.genkan_api();
        let store_creds = genkan_k8s::credentials::KubeCredentialStore::new(credentials.clone());
        genkan_store::CredentialStore::create(
            &store_creds,
            &genkan_store::NewPasskey {
                name: genkan_store::passkey_credential_name(b"cred"),
                user: "root".into(),
                credential_id: "Y3JlZA".into(),
                record: "{}".into(),
                label: None,
            },
        )
        .await
        .unwrap();
        let error = issue_setup_link(
            env.admin.clone(),
            &env.namespace,
            &issuer,
            "root",
            Duration::from_mins(60),
            false,
            t0,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, SetupLinkError::HasCredentials { count: 1, .. }),
            "{error}"
        );
        issue_setup_link(
            env.admin.clone(),
            &env.namespace,
            &issuer,
            "root",
            Duration::from_mins(60),
            true,
            t0,
        )
        .await
        .unwrap();
        assert!(
            credentials
                .list(&ListParams::default())
                .await
                .unwrap()
                .items
                .is_empty(),
            "--reset removed the passkey"
        );
        env.cleanup().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    async fn invitations_are_single_use_and_admin_only() {
        use genkan_k8s::crd::invitation::{Invitation, InvitationSpec};
        use genkan_k8s::invitations::{Invitee, invite};
        use genkan_k8s::setup::KubeSetupStore;
        use genkan_store::{Consume, SetupStore as _};

        let env = Env::new().await;
        let issuer =
            genkan_core::config::BaseUrl::parse("issuer", "https://login.example.com").unwrap();
        let t0 = genkan_core::clock::UnixTime::from_secs(now());
        let invitee = Invitee {
            username: "eve".into(),
            display_name: Some("Eve".into()),
            groups: vec!["dev".into()],
            elevated_groups: vec![],
        };
        let first = invite(
            env.admin.clone(),
            &env.namespace,
            &issuer,
            &invitee,
            Duration::from_hours(1),
            t0,
        )
        .await
        .unwrap();
        assert!(first.created_user);
        let token = first.url.split("#token=").nth(1).unwrap().to_owned();
        assert!(token.starts_with(&format!("{}.", first.name)));

        let store = KubeSetupStore::new(env.genkan_api()).with_invitations(env.genkan_api());
        let loaded = store.load(&token).await.unwrap().unwrap();
        assert_eq!(loaded.user, "eve");
        assert_eq!(
            loaded.token_hash,
            genkan_core::crypto::hash_secret(token.as_bytes())
        );
        // Without invitations enabled, the same token refers to nothing.
        assert!(
            KubeSetupStore::new(env.genkan_api())
                .load(&token)
                .await
                .unwrap()
                .is_none()
        );

        let barrier = Arc::new(Barrier::new(RACERS));
        let tasks: Vec<_> = (0..RACERS)
            .map(|_| {
                let (store, loaded, barrier) =
                    (store.clone(), loaded.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    store.consume(&loaded).await
                })
            })
            .collect();
        let mut consumed = 0;
        for task in tasks {
            if task.await.unwrap() == Ok(Consume::Consumed) {
                consumed += 1;
            }
        }
        assert_eq!(consumed, 1);
        assert!(store.load(&token).await.unwrap().is_none());

        // Genkan's service account cannot mint invitations; admission rejects malformed ones.
        let forged = Invitation::new(
            "inv-forged",
            InvitationSpec {
                user: "eve".into(),
                token_hash: format!("sha256:{}", "a".repeat(64)),
                expires_at: 0,
            },
        );
        let error = env
            .genkan_api::<Invitation>()
            .create(&PostParams::default(), &forged)
            .await
            .unwrap_err();
        assert_eq!(status_code(&error), Some(403), "{error}");
        let malformed = Invitation::new(
            "inv-bad",
            InvitationSpec {
                token_hash: "sha256:not-a-hash".into(),
                ..forged.spec.clone()
            },
        );
        let error = env
            .admin_api::<Invitation>()
            .create(&PostParams::default(), &malformed)
            .await
            .unwrap_err();
        assert_eq!(status_code(&error), Some(422), "{error}");
        env.cleanup().await;
    }

    /// Runs `kubectl` with `stdin`; returns whether it succeeded and its stderr.
    fn kubectl(args: &[&str], stdin: &str) -> (bool, String) {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut child = Command::new("kubectl")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("kubectl must be on PATH");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// The RBAC and admission policy in `docs/provisioning-users.md`, applied as written (with
    /// this test's namespace), bound a sync tool that writes with server-side apply and merge
    /// patches: PATCH reaches admission as CREATE or UPDATE.
    #[tokio::test]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG)"]
    #[expect(
        clippy::too_many_lines,
        reason = "one end-to-end scenario reads best top to bottom"
    )]
    async fn provisioning_guide_policy_bounds_the_sync_tool() {
        let env = Env::new().await;
        let ns = env.namespace.clone();
        let policy = format!("genkan-user-sync-{ns}");
        let guide = include_str!("../../../docs/provisioning-users.md");
        let manifests = guide
            .split("```yaml\n")
            .skip(1)
            .filter_map(|block| block.split("\n```").next())
            .collect::<Vec<_>>()
            .join("\n---\n")
            .replace("genkan-system", &ns)
            .replace("genkan-user-sync", &policy);
        let (ok, stderr) = kubectl(&["apply", "-f", "-"], &manifests);
        assert!(ok, "{stderr}");

        // A user created by an admin, outside the tool's reach.
        env.admin_api::<User>()
            .create(
                &PostParams::default(),
                &User::new(
                    "root",
                    UserSpec {
                        username: "root".into(),
                        groups: vec!["admins".into()],
                        ..UserSpec::default()
                    },
                ),
            )
            .await
            .unwrap();

        let as_tool = format!("--as=system:serviceaccount:{ns}:user-sync");
        let user = |name: &str, username: &str, labelled: bool, spec: &str| {
            let labels = if labelled {
                "\n  labels: {genkan.engawahq.dev/source: directory}"
            } else {
                ""
            };
            format!(
                "apiVersion: genkan.engawahq.dev/v1alpha1\nkind: User\nmetadata:\n  name: {name}\n  namespace: {ns}{labels}\nspec: {{username: {username}{spec}}}\n"
            )
        };

        // `--force-conflicts`, as a compromised tool would: field ownership is not the boundary,
        // admission is.
        let apply = |manifest: &str| {
            kubectl(
                &[
                    "apply",
                    "--server-side",
                    "--force-conflicts",
                    "--field-manager=user-sync",
                    &as_tool,
                    "-f",
                    "-",
                ],
                manifest,
            )
        };

        // The policy takes a moment to reach the admission plugin: wait until it refuses.
        let mallory = user("mallory", "mallory", true, ", elevatedGroups: [admins]");
        let mut refused = None;
        for _ in 0..60 {
            let (ok, stderr) = apply(&mallory);
            if !ok {
                refused = Some(stderr);
                break;
            }
            kubectl(&["-n", &ns, "delete", "gkuser", "mallory"], "");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let refused = refused.expect("the policy never took effect");
        assert!(
            refused.contains("never assigns or changes elevated groups"),
            "{refused}"
        );

        // Server-side apply: create (CREATE) and change (UPDATE) a managed user.
        let (ok, stderr) = apply(&user("ana", "ana", true, ", groups: [dev]"));
        assert!(ok, "{stderr}");
        let (ok, stderr) = apply(&user(
            "ana",
            "ana",
            true,
            ", groups: [dev, ops], disabled: true",
        ));
        assert!(ok, "{stderr}");

        for (manifest, message) in [
            (
                user("ana", "ana", true, ", groups: [admins]"),
                "only assign allowlisted groups",
            ),
            (
                user("ana", "ana", false, ", groups: [dev]"),
                "must keep the label",
            ),
            (user("bob", "bob", false, ""), "must keep the label"),
            (user("eve", "root", true, ""), "must equal the username"),
            (
                user("root", "root", true, ", groups: [dev]"),
                "only change users it created",
            ),
        ] {
            let (ok, stderr) = apply(&manifest);
            assert!(!ok && stderr.contains(message), "{manifest}\n{stderr}");
        }

        // A merge patch is admitted as UPDATE too.
        let (ok, stderr) = kubectl(
            &[
                "-n",
                &ns,
                "patch",
                "gkuser",
                "root",
                &as_tool,
                "--type=merge",
                "-p",
                r#"{"spec":{"disabled":true}}"#,
            ],
            "",
        );
        assert!(
            !ok && stderr.contains("only change users it created"),
            "{stderr}"
        );
        let (ok, stderr) = kubectl(
            &[
                "-n",
                &ns,
                "patch",
                "gkuser",
                "ana",
                &as_tool,
                "--type=merge",
                "-p",
                r#"{"spec":{"elevatedGroups":["admins"]}}"#,
            ],
            "",
        );
        assert!(
            !ok && stderr.contains("never assigns or changes elevated groups"),
            "{stderr}"
        );

        // Elevated groups an admin adds to a managed user survive the tool's updates, which may
        // neither drop nor change them.
        let (ok, stderr) = kubectl(
            &[
                "-n",
                &ns,
                "patch",
                "gkuser",
                "ana",
                "--type=merge",
                "-p",
                r#"{"spec":{"elevatedGroups":["admins"]}}"#,
            ],
            "",
        );
        assert!(ok, "{stderr}");
        let (ok, stderr) = apply(&user("ana", "ana", true, ", groups: [dev]"));
        assert!(ok, "{stderr}");
        for manifest in [
            user("ana", "ana", true, ", groups: [dev], elevatedGroups: []"),
            user(
                "ana",
                "ana",
                true,
                ", groups: [dev], elevatedGroups: [admins, ops]",
            ),
        ] {
            let (ok, stderr) = apply(&manifest);
            assert!(
                !ok && stderr.contains("never assigns or changes elevated groups"),
                "{manifest}\n{stderr}"
            );
        }

        // RBAC: no delete, nothing but users.
        for args in [
            vec!["-n", &ns, "delete", "gkuser", "ana", &as_tool],
            vec!["-n", &ns, "get", "gkcred", &as_tool],
            vec!["-n", &ns, "get", "gkinvite", &as_tool],
            vec!["-n", &ns, "get", "secrets", &as_tool],
        ] {
            let (ok, stderr) = kubectl(&args, "");
            assert!(!ok && stderr.contains("Forbidden"), "{args:?}\n{stderr}");
        }

        let root = env.admin_api::<User>().get("root").await.unwrap();
        assert!(!root.spec.disabled);
        let ana = env.admin_api::<User>().get("ana").await.unwrap();
        assert_eq!(ana.spec.groups, ["dev"]);
        assert_eq!(ana.spec.elevated_groups, ["admins"]);

        for kind in [
            "validatingadmissionpolicybinding",
            "validatingadmissionpolicy",
        ] {
            kubectl(&["delete", kind, &policy], "");
        }
        env.cleanup().await;
    }
}

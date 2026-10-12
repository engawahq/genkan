# Get started: k3s in a VM, kubectl with a passkey

This guide builds a single-node k3s cluster in a Linux VM, installs the components the
[recommendations catalog](https://github.com/engawa/recommendations) marks as recommended for
ingress, certificates, metrics and node updates, installs Genkan, and signs `kubectl` on a Mac
in with a passkey. It takes about half an hour, most of it downloads and one Rust build.

The cluster admin's kubeconfig never leaves the VM. The Mac only gets the cluster's CA
certificate and an OIDC configuration; every request it makes carries a short-lived token
issued after a passkey sign-in.

```text
Mac                                         VM (k3s)
 browser ──https://genkan-k3s.shared──▶ Traefik :443 ──▶ genkan (genkan-system)
 kubectl ──https://genkan-k3s.shared:6443──▶ kube-apiserver
                                              │ verifies tokens itself; discovery and keys
                                              └─▶ https://<genkan ClusterIP> (internal TLS)
```

The example uses a Parallels VM on an Apple silicon Mac; any Linux VM the Mac can reach works.
Names used throughout:

| Name | Value here |
|---|---|
| VM host name, as the Mac resolves it | `genkan-k3s.shared` (Parallels adds it to `/etc/hosts`) |
| Issuer | `https://genkan-k3s.shared` |
| VM user | `parallels`, with `sudo` |

## What you need

- **Mac:** Nix, `kubectl`, and the [mkcert](https://github.com/FiloSottile/mkcert) local CA
  trusted (`nix shell nixpkgs#mkcert -c mkcert -install`; it asks for your password once).
  Firefox needs `nss` as well; Safari and Chrome use the system trust store.
- **VM:** Ubuntu (24.04 or later), 4 CPUs, 8 GiB memory, 30 GiB free disk, Docker, Nix with
  flakes, and SSH access from the Mac. The VM user must be in the `docker` group.
- Checkouts of `genkan` and `recommendations` side by side on the Mac.

## 1. Create the VM

Clone a base image instead of changing it, then give the clone its own identity: a clone
shares the base's machine ID (and so its DHCP identity and journal directory) and SSH host keys.

```sh
prlctl clone engawa-actions-runner-base --name genkan-k3s
prlctl start genkan-k3s
prlctl exec genkan-k3s 'rm -f /etc/machine-id /var/lib/dbus/machine-id && systemd-machine-id-setup \
  && rm -f /etc/ssh/ssh_host_* && ssh-keygen -A && systemctl restart ssh systemd-journald'
ssh parallels@genkan-k3s.shared true    # accept the new host key
```

Copy both repositories to the VM:

```sh
rsync -a --delete --exclude target genkan/ parallels@genkan-k3s.shared:genkan/
rsync -a --delete --exclude out recommendations/ parallels@genkan-k3s.shared:recommendations/
```

The first `nix develop` in each checkout downloads its toolchain (about 1–2 GB for Genkan). On
a slow connection this is the longest step.

## 2. Install k3s

On the VM, as root. Traefik and metrics-server are disabled so that both come from the
catalog's charts. kube-apiserver gets its `AuthenticationConfiguration` from a file that starts
with no issuer; Genkan's comes later and is picked up without a restart.

```sh
sudo mkdir -p /etc/rancher/k3s/genkan /etc/rancher/k3s/config.yaml.d
printf 'apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\nanonymous:\n  enabled: false\njwt: []\n' \
  | sudo tee /etc/rancher/k3s/genkan/authn.yaml >/dev/null
sudo tee /etc/rancher/k3s/config.yaml >/dev/null <<'EOF'
# Traefik and metrics-server come from the recommendations catalog instead.
disable: [traefik, metrics-server]
# The name the Mac uses for the API server.
tls-san: [genkan-k3s.shared]
EOF
sudo tee /etc/rancher/k3s/config.yaml.d/50-genkan.yaml >/dev/null <<'EOF'
kube-apiserver-arg:
  - "authentication-config=/etc/rancher/k3s/genkan/authn.yaml"
EOF
curl -sfL https://get.k3s.io | sudo INSTALL_K3S_VERSION=v1.36.5+k3s1 sh -

install -d -m 700 ~/.kube
sudo install -o "$USER" -m 600 /etc/rancher/k3s/k3s.yaml ~/.kube/config
```

`~/.kube/config` is the cluster-admin credential. Keep it on the VM; it is only for installing
things.

From here on, run `kubectl` inside `nix develop` (either checkout provides it). The `kubectl`
that k3s installs reads `/etc/rancher`, which only root can, and warns on every call.

## 3. Install the recommended components

The catalog is data, not an installer, so this short script installs one component's releases
in order: Helm charts with the shared values plus one profile's, or upstream manifests. Save it
as `~/install-component.sh` on the VM and make it executable.

```bash
#!/usr/bin/env bash
# Installs one component of the recommendations catalog, its releases in order.
# Run from the recommendations checkout inside `nix develop` (helm, kubectl, yq).
#   install-component.sh <profile> capabilities/<capability>/<upstream>.yaml
set -euo pipefail

profile="${1:?usage: install-component.sh <profile> <file>}"
file="${2:?usage: install-component.sh <profile> <file>}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

count=$(yq '.releases | length' "$file")
for ((i = 0; i < count; i++)); do
  r=".releases[$i]"
  name=$(yq "$r.name" "$file")
  ns=$(yq "$r.namespace" "$file")
  version=$(yq "$r.version" "$file")

  skip=$(yq "$r.skipIfPresent // [] | .[]" "$file")
  if [ -n "$skip" ] && kubectl get crd $skip >/dev/null 2>&1; then
    echo "skip $name: $skip already present"
    continue
  fi

  if [ "$(yq "$r | has(\"chart\")" "$file")" = true ]; then
    chart=$(yq "$r.chart" "$file")
    repo=$(yq "$r.repo // \"\"" "$file")
    yq "$r.values // \"\"" "$file" > "$work/values.yaml"
    yq "$r.profiles[\"$profile\"] // \"\"" "$file" > "$work/profile.yaml"
    echo "helm $name $chart $version"
    helm upgrade --install "$name" "$chart" ${repo:+--repo "$repo"} --version "$version" \
      --namespace "$ns" --create-namespace \
      -f "$work/values.yaml" -f "$work/profile.yaml" --wait --timeout 10m
  else
    kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    for url in $(yq "$r.urls // [] | .[]" "$file"); do
      url="${url//\{version\}/$version}"
      echo "apply $name $url"
      kubectl apply --server-side -n "$ns" -f "$url"
    done
    if [ "$(yq "$r | has(\"manifests\")" "$file")" = true ]; then
      yq "$r.manifests" "$file" | kubectl apply --server-side -n "$ns" -f -
    fi
  fi
done
```

It does not handle a component's `inputs` or `contributes`; the four below have neither. Install
them in dependency order (cert-manager depends on ingress for the Gateway API CRDs):

```sh
cd ~/recommendations && nix develop
for c in ingress/traefik certificates/cert-manager metrics/metrics-server node-updates/system-upgrade-controller; do
  ~/install-component.sh single-node capabilities/$c.yaml
done
kubectl get gatewayclass traefik          # ACCEPTED True
kubectl top nodes                         # metrics-server answers after about a minute
```

The catalog also recommends VictoriaMetrics and VictoriaLogs for single-node clusters. They are
left out here to keep the cluster small; install them the same way
(`observability-operator/victoria-metrics-operator`, then `metrics/victoria-metrics` and
`logs/victoria-logs`) once you have checked their `inputs`.

## 4. Build and install Genkan

Genkan has no published image yet, so build it on the VM (Linux, same architecture as the
node) and import it into k3s's containerd:

```sh
cd ~/genkan && nix develop
./scripts/build-image.sh genkan:dev                       # about 20 MB
docker save genkan:dev | sudo k3s ctr images import -
cargo build --release -p genkanctl && alias genkanctl=$PWD/target/release/genkanctl

ISSUER=https://genkan-k3s.shared
genkanctl crds | kubectl apply --server-side -f -
genkanctl manifests --issuer $ISSUER --image docker.io/library/genkan:dev | kubectl apply --server-side -f -
kubectl -n genkan-system rollout status deploy/genkan
```

Everything Genkan owns lives in the `genkan-system` namespace.

## 5. Publish the issuer over HTTPS

Passkeys need a secure context, so the browser must trust the sign-in page's certificate. On
the Mac, issue a certificate for the issuer's host name from the mkcert CA. Only the leaf
certificate and its key go to the VM; the CA key stays on the Mac.

```sh
# Mac
mkcert -cert-file genkan.crt -key-file genkan.key genkan-k3s.shared
ssh parallels@genkan-k3s.shared 'install -d -m 700 ~/genkan-tls'
scp genkan.crt genkan.key parallels@genkan-k3s.shared:genkan-tls/
rm genkan.key
```

On the VM, store it as a Secret and route the host name to Genkan through Traefik's Gateway
API support. Traefik's HTTPS entry point listens on 8443 in the pod; k3s's ServiceLB exposes it
on the node's port 443.

```sh
kubectl -n genkan-system create secret tls genkan-tls \
  --cert=$HOME/genkan-tls/genkan.crt --key=$HOME/genkan-tls/genkan.key
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: genkan, namespace: genkan-system}
spec:
  gatewayClassName: traefik
  listeners:
  - name: https
    protocol: HTTPS
    port: 8443
    hostname: genkan-k3s.shared
    tls:
      certificateRefs: [{name: genkan-tls}]
    allowedRoutes: {namespaces: {from: Same}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: genkan, namespace: genkan-system}
spec:
  parentRefs: [{name: genkan}]
  hostnames: [genkan-k3s.shared]
  rules:
  - backendRefs: [{name: genkan, port: 80}]
EOF
kubectl -n genkan-system wait gateway/genkan --for=condition=Programmed
```

Check from the Mac with the system `curl` (Nix's `curl` does not read the macOS keychain):

```sh
/usr/bin/curl https://genkan-k3s.shared/.well-known/openid-configuration
```

With a real domain, use a cert-manager `ClusterIssuer` (ACME) and a `Certificate` for the
Secret instead of mkcert.

## 6. Let kube-apiserver trust Genkan

`genkanctl kube-config` issues the certificate of Genkan's internal listener, which
kube-apiserver reaches through the Service's ClusterIP, and prints the
`AuthenticationConfiguration`. Replace the file atomically (kube-apiserver re-reads it by path
about once a minute):

```sh
genkanctl kube-config --issuer $ISSUER --distro k3s > ~/authn.yaml
sudo install -m 600 ~/authn.yaml /etc/rancher/k3s/genkan/.authn.yaml.tmp
sudo mv /etc/rancher/k3s/genkan/.authn.yaml.tmp /etc/rancher/k3s/genkan/authn.yaml
```

Verify the successful load on each control plane, connecting to that API server directly
rather than a load balancer. For reloads, the success counter/timestamp must advance from its
value before replacement; `last_config_info` must name `sha256:<sha256sum of the exact file
bytes>` with value `1`. A counter that was already nonzero does not prove this file loaded.

```sh
# Repeat using an admin context that points directly at each control plane.
sha256sum ~/authn.yaml
kubectl get --raw /metrics | grep '^apiserver_authentication_config_controller_'
# automatic_reloads_total{...,status="success"} increases on successful reload
# automatic_reload_last_timestamp_seconds{...,status="success"} advances
# last_config_info{...,hash="sha256:<file digest>"} 1
```

The hash metric records a successfully applied file, including the initial load after
restart; it is not a host-file presence check or proof that every API server behind a load
balancer loaded it. The metric definitions and success path are in Kubernetes
[authenticationconfig metrics](https://github.com/kubernetes/kubernetes/blob/v1.37.1/staging/src/k8s.io/apiserver/pkg/server/options/authenticationconfig/metrics/metrics.go)
and [authentication options](https://github.com/kubernetes/kubernetes/blob/v1.37.1/pkg/kubeapiserver/options/authentication.go).

### Renew the built-in internal CA without dropping trust

The initial install remains a plain `kube-config` invocation. The built-in CA private key is
discarded after issuance, so renewal requires distributing new trust **before** changing the
serving leaf. `--renew-certificate` is removed: it replaced the leaf before that distribution.
Plain invocation now reuses existing material even near expiry; it warns rather than replacing
trust. Start renewal while the old certificate remains valid. Unusable or differently addressed
existing material is an error, not an excuse to overwrite it. An external issuer retains
ownership and renews its own material; this procedure is a complete built-in renewal path.

1. Prepare the candidate. Keep the same issuer, namespace, audiences and distribution options
   in **every** invocation. stdout is the overlap configuration; stderr reports the opaque
   rotation id and the active/candidate **SHA-256 DER leaf** fingerprints. Save all three.

   ```sh
   genkanctl kube-config --issuer $ISSUER --distro k3s \
     --certificate-action prepare > ~/authn-overlap.yaml
   ```

   The active `tls.crt`/`tls.key` are unchanged. `ca.crt` contains old+new trust, and candidate
   material is persisted in the same Secret. Repeating prepare, including after a lost response
   or CLI restart, returns that same candidate instead of issuing another. A `409 Conflict`
   does not activate anything; rerun the command to read the winning persisted generation.

2. Atomically install the **exact overlap file** on every control-plane host using the
   distribution's instructions above. Before activation, verify the per-control-plane successful
   authentication reload counter/timestamp and exact-file hash metric as described above, and
   authenticate an access token directly against each API server. A sleep, existing nonzero
   counter, or success through one load-balanced endpoint is not evidence for the other hosts.
   The CLI has no access to external host configuration and cannot perform or certify these checks.

3. Activate only after those checks, supplying the saved id:

   ```sh
   ROTATION_ID=<opaque-id-from-prepare>
   genkanctl kube-config --issuer $ISSUER --distro k3s \
     --certificate-action activate --rotation-id "$ROTATION_ID" > ~/authn-overlap.yaml
   ```

   Activation changes the serving pair with a `resourceVersion` compare-and-swap and retains
   overlap plus the previous pair. It is retry-safe after an ambiguous response, but is not an
   instantaneous rollout: running Genkan pods load it on their next Secret poll. Existing TLS
   connections may still use the old leaf. Overlap verifies either generation.

4. Verify **each Genkan pod's actual served leaf**, not just the load-balanced Service or its
   Secret. From a control-plane host that can route to each pod, use the old+new `ca.crt` as the
   trust file and the Service IP as the certificate identity:

   ```sh
   # Public trust certificates only; keep this overlap file through rollout/rollback.
   kubectl -n genkan-system get secret genkan-internal-tls \
     -o jsonpath='{.data.ca\.crt}' | base64 -d > overlap-ca.pem
   SERVICE_IP=$(kubectl -n genkan-system get service genkan -o jsonpath='{.spec.clusterIP}')
   kubectl -n genkan-system get pods -l app.kubernetes.io/name=genkan -o wide
   set -o pipefail
   # Repeat with every pod IP, including any old/draining generation still serving.
   POD_IP=<pod-ip>
   openssl s_client -connect "$POD_IP:8443" -verify_ip "$SERVICE_IP" \
     -verify_return_error -CAfile overlap-ca.pem </dev/null 2>/dev/null \
     | openssl x509 -outform DER | sha256sum
   ```

   Require the lowercase hex digest to equal the saved **candidate leaf fingerprint** on every
   pod. The opaque rotation id is not a fingerprint. Also check discovery/JWKS reachability and
   access-token authentication directly on every control plane; a matching leaf alone does not
   prove authentication is configured correctly.

5. Finish only once no serving pod presents the old leaf:

   ```sh
   genkanctl kube-config --issuer $ISSUER --distro k3s \
     --certificate-action finish --rotation-id "$ROTATION_ID" > ~/authn-new-only.yaml
   ```

   Finish removes previous/candidate keys and prints new-only trust. It is the **one-way door**
   for built-in rollback. Atomically install that file on all control planes and again verify
   successful reload and its exact hash per host. Finished/cancelled id/phase markers remain
   for safe retries until the next prepare creates a new id.

Before finish, `--certificate-action rollback --rotation-id "$ROTATION_ID"` restores the
previous **unexpired** serving pair while retaining overlap; wait for the actual old leaf on
every pod, not a fixed timer. Retry rollback safely or reactivate the same candidate. To abandon
a prepared or fully rolled-back rotation, use `--certificate-action cancel --rotation-id
"$ROTATION_ID"` and distribute its old-only output after verifying all pods serve the old leaf.
Cancel does not rewind an activated rollout; roll back and verify it first. Neither rollback
nor cancel can undo TLS connections already established, and finish permanently deletes the
old rollback pair. Back up the Secret securely if your operational policy requires recovery
outside this lifecycle; it contains serving private keys, never a built-in CA signing key.

## 7. Register kubectl and enrol the first passkey

kubectl's OIDC plugin ([kubelogin](https://github.com/int128/kubelogin)) is a public client
that receives the code on a loopback redirect:

```sh
kubectl apply -f - <<'EOF'
apiVersion: genkan.engawahq.dev/v1alpha1
kind: OAuthClient
metadata: {name: kubectl, namespace: genkan-system}
spec:
  type: Public
  redirectUris: ["http://127.0.0.1:8000/"]
  audiences: [kubernetes]
EOF
genkanctl setup-link --issuer $ISSUER --username admin
```

Open the printed link on the Mac and create a passkey. The link works once and expires in 60
minutes; run the command again for a new one.

## 8. kubectl on the Mac

Get the cluster's CA certificate (public; it only lets the Mac verify the API server):

```sh
CA=$(ssh parallels@genkan-k3s.shared "grep certificate-authority-data ~/.kube/config | awk '{print \$2}'")
```

Write `~/.kube/genkan-k3s.yaml`, with `$CA` substituted. It has two users: a normal one, and
one that asks for the `elevate` scope and caches its tokens separately.

```yaml
apiVersion: v1
kind: Config
clusters:
- name: genkan-k3s
  cluster:
    server: https://genkan-k3s.shared:6443
    certificate-authority-data: <CA>
users:
- name: passkey
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: IfAvailable
      command: nix
      args: [shell, "nixpkgs#kubelogin-oidc", -c, kubectl-oidc_login, get-token,
        --oidc-issuer-url=https://genkan-k3s.shared,
        --oidc-client-id=kubectl,
        --oidc-use-access-token,
        --listen-address=127.0.0.1:8000,
        --oidc-redirect-url=http://127.0.0.1:8000/]
- name: passkey-elevated
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: IfAvailable
      command: nix
      args: [shell, "nixpkgs#kubelogin-oidc", -c, kubectl-oidc_login, get-token,
        --oidc-issuer-url=https://genkan-k3s.shared,
        --oidc-client-id=kubectl,
        --oidc-use-access-token,
        --oidc-extra-scope=elevate,
        --token-cache-dir=~/.kube/cache/oidc-login-elevated,
        --listen-address=127.0.0.1:8000,
        --oidc-redirect-url=http://127.0.0.1:8000/]
contexts:
- {name: genkan-k3s, context: {cluster: genkan-k3s, user: passkey}}
- {name: genkan-k3s-admin, context: {cluster: genkan-k3s, user: passkey-elevated}}
current-context: genkan-k3s
```

`--oidc-use-access-token` is required: kube-apiserver accepts only access tokens (they carry
`client_id`) and rejects ID tokens.

## 9. Try it

```sh
export KUBECONFIG=~/.kube/genkan-k3s.yaml
kubectl auth whoami                      # opens the browser; user genkan:admin, group genkan:admins
kubectl get pods -A                      # allowed: genkan:admins has the built-in view role
kubectl create namespace demo            # Forbidden: a normal token cannot change anything
kubectl --context genkan-k3s-admin create namespace demo
                                         # a fresh passkey sign-in; the token lasts at most
                                         # 5 minutes, cannot be refreshed, and carries
                                         # genkan:elevated:admins (cluster-admin)
kubectl --context genkan-k3s-admin auth whoami
```

Things to notice:

- Normal tokens last 10 minutes and are refreshed silently for up to 12 hours; the elevated one
  asks for the passkey again every time it expires.
- `kubectl auth whoami` shows `genkan.engawahq.dev/jti` and `client_id` in its extra fields, so
  audit events tie each request to one token issuance.
- Users, passkeys and sessions are custom resources:
  `kubectl -n genkan-system get users,credentials,grants` (as cluster admin on the VM).

## Next

- [Sign in with GitHub](github-sign-in.md) as an alternative to the passkey for ordinary
  access.

## Troubleshooting

- **Browser shows a certificate error, or no passkey prompt:** the mkcert CA is not trusted
  (`mkcert -install`), or the certificate's name does not match the issuer host.
- **`kubectl` gets `Unauthorized`:** check the reload metric in step 6. Validation errors make
  kube-apiserver skip a file until it changes. On k3s, its log is
  `sudo journalctl -u k3s | grep -i "authentication config"`.
- **`journalctl` finds no journal files on a cloned VM:** the machine ID changed; restart
  `systemd-journald`.
- **Port 8000 in use:** kubelogin listens there for the redirect. Change `--listen-address`,
  `--oidc-redirect-url` and the client's `redirectUris` together.

## Clean up

```sh
prlctl stop genkan-k3s && prlctl delete genkan-k3s
rm ~/.kube/genkan-k3s.yaml; rm -rf ~/.kube/cache/oidc-login ~/.kube/cache/oidc-login-elevated
```

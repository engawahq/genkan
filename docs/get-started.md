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

### Limit unauthenticated traffic at the ingress

Apply per-source-IP rate limits to `/authorize`, `/token`, `/par`, `/revoke`, `/login*`,
`/setup*` and `/upstream/*` before exposing Genkan publicly. Genkan normally sees the ingress address,
not the browser's address; it does not trust arbitrary forwarded headers or implement
in-process per-IP limiting. At the ingress, preserve the source IP and, when another proxy
is in front, configure forwarded-header trust only for that proxy's addresses. Otherwise
all users may share a bucket, or forged headers may bypass it.

For the Traefik Gateway above, enable its Kubernetes CRD provider and install its Middleware
CRDs, then apply this additional route. Its specific paths take precedence over the
catch-all route; discovery and keys remain outside the rate limit.

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata: {name: genkan-rate-limit, namespace: genkan-system}
spec:
  rateLimit:
    average: 10
    period: 1s
    burst: 20
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: genkan-rate-limited, namespace: genkan-system}
spec:
  parentRefs: [{name: genkan}]
  hostnames: [genkan-k3s.shared]
  rules:
  - matches:
    - path: {type: Exact, value: /authorize}
    - path: {type: Exact, value: /token}
    - path: {type: Exact, value: /par}
    - path: {type: Exact, value: /revoke}
    - path: {type: PathPrefix, value: /login}
    - path: {type: PathPrefix, value: /setup}
    - path: {type: PathPrefix, value: /upstream}
    filters:
    - type: ExtensionRef
      extensionRef: {group: traefik.io, kind: Middleware, name: genkan-rate-limit}
    backendRefs: [{name: genkan, port: 80}]
```

These are starting values, not a security guarantee: tune for users sharing NAT and expected
sign-in bursts. Traefik's default bucket key is the remote address; each Traefik replica has
its own buckets unless distributed rate limiting is configured. See the
[RateLimit options](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/)
and [Gateway middleware prerequisites](https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/gateway-api/#extensionref-filters).

Genkan additionally limits each business route/method service to 64 concurrent requests.
Full services immediately return `503` with `Retry-After: 1`, without queuing ahead of the
ten-second handler timeout. Health/readiness probes and discovery/keys do not share those
slots. These are per-process concurrency limits, not per-IP rate limits. Structured
`request_overload` events expose cumulative rejection counts at power-of-two milestones, not
one warning per rejection. `kubernetes_directory_lookup` events sample the first and every
64th directory GET attempt, exposing resource, operation, outcome, process-wide `lookup_total`
and API latency in milliseconds instead of writing an INFO event for each GET.
Aggregate them in your log backend.

Kubernetes directory metadata is watched before the public listener starts. Unknown client
names are rejected locally, including a flood of distinct random IDs; known clients still
use a direct GET so secret, redirect URI and audience changes take effect on the next request.
UserInfo resolves `sub` from watched user metadata and directly reads the user to verify its
UID and enabled state. Access-token claims do not change. New client names and UserInfo subjects
become visible after their watch events arrive; watch lag can delay those lookups, never authorize
stale client/user data. Unknown entries in these indexes never fall back to per-ID API reads.
Name-based user lookups used by setup, sign-in and refresh remain uncached direct GETs after
initial synchronization, including absent names; they do not await individual user watch events.

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

Wait for a successful reload:

```sh
kubectl get --raw /metrics | grep '^apiserver_authentication_config_controller_automatic_reloads_total'
# ...{status="success"} 1
```

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

# Get started: k3s on an Ubuntu server, kubectl with a passkey

By the end of this guide you will run `kubectl get pods` on your computer, confirm with your
passkey, and get into a k3s cluster without an admin kubeconfig on your computer. It takes
about half an hour, most of it spent on downloads and one Rust build.

You will:

1. install k3s on an Ubuntu server;
2. add an ingress, cert-manager and a few other basics from the
   [recommendations catalog](https://github.com/engawahq/recommendations);
3. build and install Genkan, and publish its sign-in page over HTTPS;
4. tell kube-apiserver to trust Genkan's tokens;
5. create your passkey and point `kubectl` on your computer at the cluster.

The guide talks about two machines:

- **Your computer** runs the browser and `kubectl`. It can run macOS, Linux or Windows. The
  commands are written for a POSIX shell; on Windows, use WSL.
- **The server** runs k3s and Genkan. Any Ubuntu machine your computer can reach over the
  network works: a VPS, a homelab box, a spare PC or a local VM.

The cluster's admin kubeconfig stays on the server, where you use it only to install things. Your
computer gets the cluster's CA certificate and a kubeconfig that signs in through Genkan. Every
request it sends carries a token that expires within minutes.

```text
Your computer                               server (k3s)
 browser ──https://genkan.example.test──▶ Traefik :443 ──▶ genkan (genkan-system)
 kubectl ──https://genkan.example.test:6443──▶ kube-apiserver
                                              │ verifies tokens itself; discovery and keys
                                              └─▶ https://<genkan ClusterIP> (internal TLS)
```

The examples use these names. Replace them with yours as you go:

| Name | In the examples |
|---|---|
| The server's host name | `genkan.example.test` |
| Issuer (Genkan's public URL) | `https://genkan.example.test` |
| SSH login to the server | `ubuntu@genkan.example.test`, a user with `sudo` |

The host name must lead your computer to the server. With a domain of your own, add a DNS
record. Names under `.test` never resolve on the internet, so for those add a line to your
hosts file instead (`/etc/hosts`, or `C:\Windows\System32\drivers\etc\hosts` on Windows).

## What you need

On **your computer**:

- `kubectl`;
- [kubelogin](https://github.com/int128/kubelogin), the `kubectl` plugin that opens the browser
  to sign in. Install it with Homebrew (`brew install int128/kubelogin/kubelogin`), Nix
  (`nixpkgs#kubelogin-oidc`), or [krew](https://krew.sigs.k8s.io/docs/user-guide/setup/install/)
  (`kubectl krew install oidc-login`, after installing krew itself);
- [mkcert](https://github.com/FiloSottile/mkcert), with its local CA trusted where your browser
  runs: run `mkcert -install` once (it may ask for your password). Firefox also needs NSS's
  `certutil`; see mkcert's README. With WSL, the browser runs on Windows, so use the Windows
  build of mkcert, both here and in step 5.
- `ssh` access to the server.

On **the server**: Ubuntu 24.04 or later, 4 CPUs, 8 GiB memory, 30 GiB free disk, Docker, and
Nix with flakes. Your user must be in the `docker` group. Use a machine that runs nothing else
important: this guide installs k3s and changes its configuration.

Keep two terminals open: one on your computer, and one logged in to the server. Each step says
which one to use. In the terminal on your computer, set the SSH login so later commands can use
it:

```sh
SERVER=ubuntu@genkan.example.test
```

## 1. Get the code

Log in to the server from your computer:

```sh
ssh "$SERVER"
```

In that server shell, clone both repositories into your home directory:

```sh
git clone https://github.com/engawahq/genkan.git ~/genkan
git clone https://github.com/engawahq/recommendations.git ~/recommendations
```

The first `nix develop` in each checkout downloads its toolchain (about 1–2 GB for Genkan). On
a slow connection, this is the longest step.

## 2. Install k3s

Run this on the server. Before installing k3s, it:

- turns off k3s's built-in Traefik and metrics-server, because step 3 installs them from the
  catalog;
- adds `genkan.example.test` to the API server's certificate, so your computer can connect by
  that name;
- points kube-apiserver at an authentication file that is empty for now. Step 6 fills it in,
  and kube-apiserver picks up the change without a restart.

```sh
sudo mkdir -p /etc/rancher/k3s/genkan /etc/rancher/k3s/config.yaml.d
sudo tee /etc/rancher/k3s/genkan/authn.yaml >/dev/null <<'EOF'
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
anonymous:
  enabled: false
jwt: []
EOF
sudo tee /etc/rancher/k3s/config.yaml >/dev/null <<'EOF'
# Traefik and metrics-server come from the recommendations catalog instead.
disable: [traefik, metrics-server]
# The name your computer uses for the API server.
tls-san: [genkan.example.test]
EOF
sudo tee /etc/rancher/k3s/config.yaml.d/50-genkan.yaml >/dev/null <<'EOF'
kube-apiserver-arg:
  - "authentication-config=/etc/rancher/k3s/genkan/authn.yaml"
EOF
curl -sfL https://get.k3s.io | sudo INSTALL_K3S_VERSION=v1.36.5+k3s1 sh -

install -d -m 700 ~/.kube
sudo install -o "$USER" -m 600 /etc/rancher/k3s/k3s.yaml ~/.kube/config
```

`~/.kube/config` is the cluster-admin credential. Keep it on the server, and use it only to install
things.

From here on, run `kubectl` on the server inside `nix develop` (either checkout provides it). The
`kubectl` that comes with k3s tries to read `/etc/rancher`, which only root can read, and warns
on every call.

## 3. Install the recommended components

The catalog lists components but does not install them. This short script installs one
component: it applies the component's Helm charts or manifests in order, using the shared
values plus those of one profile. Save it as `~/install-component.sh` on the server.

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

```sh
chmod +x ~/install-component.sh
```

Install these four components in this order; cert-manager needs the Gateway API CRDs that the
ingress installs. (The script does not handle a component's `inputs` or `contributes`; these
four have neither.)

```sh
cd ~/recommendations && nix develop
for c in ingress/traefik certificates/cert-manager metrics/metrics-server node-updates/system-upgrade-controller; do
  ~/install-component.sh single-node capabilities/$c.yaml
done
kubectl get gatewayclass traefik          # ACCEPTED True
kubectl top nodes                         # metrics-server answers after about a minute
```

The catalog also recommends VictoriaMetrics and VictoriaLogs for single-node clusters. This
guide leaves them out to keep the cluster small. To add them later, install
`observability-operator/victoria-metrics-operator`, then `metrics/victoria-metrics` and
`logs/victoria-logs` the same way, after checking their `inputs`.

## 4. Build and install Genkan

Genkan has no published image yet, so build one on the server and load it into k3s. Building on
the server gives you a Linux image for the node's CPU architecture. You also build `genkanctl`,
the admin tool you use for the rest of the guide.

```sh
cd ~/genkan && nix develop
./scripts/build-image.sh genkan:dev                       # about 20 MB
docker save genkan:dev | sudo k3s ctr images import -
cargo build --release -p genkanctl && alias genkanctl=$PWD/target/release/genkanctl
```

Now install it. `genkanctl` reads the issuer from `GENKAN_ISSUER`, so the commands do not need
`--issuer`. Keep using this server shell for the rest of the guide: the `genkanctl` alias,
`GENKAN_ISSUER` and the `nix develop` environment last only as long as the shell. In a new shell,
run `cd ~/genkan && nix develop` and the `alias` and `export` lines again.

```sh
export GENKAN_ISSUER=https://genkan.example.test
genkanctl crds | kubectl apply --server-side -f -
genkanctl manifests --image docker.io/library/genkan:dev \
  --serve-arg=--invitations | kubectl apply --server-side -f -
kubectl -n genkan-system rollout status deploy/genkan
```

Everything Genkan owns lives in the `genkan-system` namespace. `--serve-arg=--invitations`
turns on invitation links, which you use later to [add people](managing-users.md#add-someone).

## 5. Publish the sign-in page over HTTPS

Browsers offer passkeys only on pages they trust, so Genkan's sign-in page needs a certificate
your browser accepts. This guide uses mkcert's local CA. With a real domain, use a cert-manager
`ClusterIssuer` (ACME) and a `Certificate` instead.

On your computer, issue a certificate for the issuer's host name and copy it to the server. Only the
certificate and its key leave your computer; the CA's key stays.

```sh
mkcert -cert-file genkan.crt -key-file genkan.key genkan.example.test
ssh "$SERVER" 'install -d -m 700 ~/genkan-tls'
scp genkan.crt genkan.key "$SERVER":genkan-tls/
rm genkan.key
```

On the server, store it as a Secret and route the host name to Genkan through Traefik. (Traefik
listens on 8443 inside its pod; k3s exposes that as port 443 on the node.)

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
    hostname: genkan.example.test
    tls:
      certificateRefs: [{name: genkan-tls}]
    allowedRoutes: {namespaces: {from: Same}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: genkan, namespace: genkan-system}
spec:
  parentRefs: [{name: genkan}]
  hostnames: [genkan.example.test]
  rules:
  - backendRefs: [{name: genkan, port: 80}]
EOF
kubectl -n genkan-system wait gateway/genkan --for=condition=Programmed
```

Check it from your computer. You should get a JSON document whose `issuer` is
`https://genkan.example.test`:

```sh
curl --cacert "$(mkcert -CAROOT)/rootCA.pem" \
  https://genkan.example.test/.well-known/openid-configuration
```

With WSL and the Windows mkcert, `mkcert -CAROOT` prints a Windows path. Convert it first:

```sh
curl --cacert "$(wslpath "$(mkcert.exe -CAROOT | tr -d '\r')")/rootCA.pem" \
  https://genkan.example.test/.well-known/openid-configuration
```

### Before going public: rate-limit sign-in

Skip this on a server only you can reach. Before you expose Genkan to the internet, limit how often one
address can call the sign-in endpoints. Genkan does not rate-limit by IP address itself; that
is the ingress's job, because only the ingress sees the browser's real address.

With the Traefik Gateway above, enable Traefik's Kubernetes CRD provider and install its
Middleware CRDs (see the [Gateway middleware prerequisites][traefik-extref]), then apply:

```sh
kubectl apply -f - <<'EOF'
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
  hostnames: [genkan.example.test]
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
EOF
```

This route takes precedence over the catch-all route for the listed paths. Discovery and keys
stay unlimited, because kube-apiserver and every client fetch them.

Treat the numbers as a starting point:

- People behind one NAT share one address, and so share one limit. Raise it if your office
  signs in at the same time each morning.
- If another proxy sits in front of Traefik, configure Traefik to trust forwarded headers from
  that proxy only. Otherwise everyone shares one bucket, or a forged header gets around it.
- Each Traefik replica keeps its own count unless you set up distributed rate limiting.

See Traefik's [RateLimit options][traefik-ratelimit] for the details.

[traefik-ratelimit]: https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/
[traefik-extref]: https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/gateway-api/#extensionref-filters

## 6. Let kube-apiserver trust Genkan

kube-apiserver checks Genkan's tokens itself. To do that, it fetches Genkan's signing keys over
an internal HTTPS connection. `genkanctl kube-config` creates the certificate for that
connection and prints the configuration kube-apiserver needs. It also prints k3s setup
instructions, including a one-time restart; step 2 already did that, so you can skip them.

kube-apiserver checks the file about once a minute. To know when it has picked up your change,
count its successful reloads before and after. Define two small helpers in the server shell:

```sh
# Successful reloads of the authentication configuration so far.
reloads() {
  kubectl get --raw /metrics |
    awk '/^apiserver_authentication_config_controller_automatic_reloads_total/ &&
      /status="success"/ { n += $NF } END { print n + 0 }'
}
# Waits up to three minutes for the count to pass $1; prints the k3s log if it never does.
wait_for_reload() {
  for _ in $(seq 1 36); do
    [ "$(reloads)" -gt "$1" ] && return 0
    sleep 5
  done
  echo "Authentication configuration did not reload; inspect k3s logs." >&2
  sudo journalctl -u k3s --since "5 minutes ago" --no-pager
  return 1
}
```

Then write the new configuration to a temporary file and move it into place in one step, so
kube-apiserver never reads a half-written file, and wait for the reload:

```sh
before=$(reloads)
genkanctl kube-config --distro k3s > ~/authn.yaml &&
  sudo install -m 600 ~/authn.yaml /etc/rancher/k3s/genkan/.authn.yaml.tmp &&
  sudo mv /etc/rancher/k3s/genkan/.authn.yaml.tmp /etc/rancher/k3s/genkan/authn.yaml &&
  wait_for_reload "$before"
```

The internal certificate is valid for a year. [Renew it](#once-a-year-renew-the-internal-certificate)
before then.

## 7. Register kubectl and create the first passkey

Every application that signs in through Genkan is registered as a client. Register `kubectl`
(through kubelogin, which receives the sign-in result on `127.0.0.1`). `--allow-elevation`
lets this client ask for admin rights:

```sh
genkanctl client create kubectl --type public --allow-elevation \
  --redirect-uri http://127.0.0.1:8000/ --audience kubernetes | kubectl apply -f -
```

Then get a one-time link for the first admin:

```sh
genkanctl setup-link --username admin
```

Open the printed link in the browser on your computer and create a passkey. The link works
once and expires after 60 minutes; run the command again if you need a new one.

## 8. Set up kubectl on your computer

Copy the cluster's CA certificate from the server. It is public; it only lets `kubectl` check that
it talks to the right API server.

```sh
CA=$(ssh "$SERVER" "grep certificate-authority-data ~/.kube/config | awk '{print \$2}'")
```

Then write a kubeconfig with two contexts:

- `genkan-k3s` for everyday work: read-only by default, and renews itself quietly;
- `genkan-k3s-admin` for changes: asks for your passkey every time, and keeps its tokens apart
  from the everyday ones.

```sh
mkdir -p ~/.kube
cat > ~/.kube/genkan-k3s.yaml <<EOF
apiVersion: v1
kind: Config
clusters:
- name: genkan-k3s
  cluster:
    server: https://genkan.example.test:6443
    certificate-authority-data: $CA
users:
- name: passkey
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: IfAvailable
      command: kubectl
      args: [oidc-login, get-token,
        --oidc-issuer-url=https://genkan.example.test,
        --oidc-client-id=kubectl,
        --oidc-use-access-token,
        --listen-address=127.0.0.1:8000,
        --oidc-redirect-url=http://127.0.0.1:8000/]
- name: passkey-elevated
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: IfAvailable
      command: kubectl
      args: [oidc-login, get-token,
        --oidc-issuer-url=https://genkan.example.test,
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
EOF
```

Krew and Nix install kubelogin as a `kubectl` plugin, so the file works as written. If you
installed it with Homebrew, set `command: kubelogin` and drop `oidc-login` from `args`.

With WSL, kubelogin runs inside Linux and does not see the CA that the Windows mkcert trusted.
Add the CA to both `args` lists, using the path from the WSL check in step 5:

```sh
wslpath "$(mkcert.exe -CAROOT | tr -d '\r')"   # e.g. /mnt/c/Users/you/AppData/Local/mkcert
```

```yaml
        --certificate-authority=/mnt/c/Users/you/AppData/Local/mkcert/rootCA.pem,
```

Keep `--oidc-use-access-token`: kube-apiserver accepts only Genkan's access tokens, not ID
tokens.

## 9. Try it

```sh
export KUBECONFIG=~/.kube/genkan-k3s.yaml
kubectl auth whoami                      # opens the browser; user genkan:admin, group genkan:admins
kubectl get pods -A                      # allowed: genkan:admins has the built-in view role
kubectl create namespace demo            # Forbidden: an everyday token cannot change anything
kubectl --context genkan-k3s-admin create namespace demo
                                         # asks for your passkey again; works for 5 minutes
kubectl --context genkan-k3s-admin auth whoami
                                         # now also in genkan:elevated:admins (cluster-admin)
```

What just happened:

- **Everyday tokens** last 10 minutes and renew without a prompt. You sign in again 12 hours
  after the first sign-in, or after 4 hours without using `kubectl`.
- **Admin tokens** last at most 5 minutes and never renew. When one expires, the admin context
  asks for your passkey again.
- **Each token is traceable.** `kubectl auth whoami` shows `genkan.engawahq.dev/jti` and
  `genkan.engawahq.dev/client-id`. They also appear in Kubernetes audit events, so each request maps to one sign-in.
- **People, passkeys and sessions are Kubernetes objects** in `genkan-system`: a passkey is a
  `Credential`, and a signed-in session is a `Grant`. On the server, list them with
  `kubectl -n genkan-system get users,credentials,grants`.
  [Managing users](managing-users.md) explains how to work with them.

## Next

- [Manage users](managing-users.md): invite people, add passkeys, sign people out or remove
  them.
- [Sign in with GitHub](github-sign-in.md) or [Google](google-sign-in.md) as an alternative
  to the passkey for everyday access.
- [Register more clients](clients.md), such as Grafana or Argo CD, so they sign people in
  through Genkan too.

## Once a year: renew the internal certificate

The certificate from step 6 is valid for 365 days. If it expires, kube-apiserver can no longer
fetch Genkan's keys, and every sign-in to the cluster fails. Running `genkanctl kube-config`
again replaces the certificate automatically when it has less than 30 days left;
`--renew-certificate` replaces it now.

On the server, in a shell set up as in step 4 (`nix develop`, the `genkanctl` alias and
`GENKAN_ISSUER`) and with the `reloads` and `wait_for_reload` helpers from step 6 defined:

```sh
before=$(reloads)
authn=$(mktemp) &&
  genkanctl kube-config --distro k3s --renew-certificate > "$authn" &&
  sudo install -m 600 "$authn" /etc/rancher/k3s/genkan/.authn.yaml.tmp &&
  sudo mv /etc/rancher/k3s/genkan/.authn.yaml.tmp /etc/rancher/k3s/genkan/authn.yaml &&
  rm "$authn" &&
  wait_for_reload "$before"
```

Renewal creates a new CA as well, so kube-apiserver needs the configuration this command
prints, not the one from step 6. Sign-ins can fail briefly while Genkan and kube-apiserver both
pick up the change (each within about a minute). Then run `kubectl auth whoami` on your
computer.

> [!WARNING]
> `genkanctl` switches Genkan to the new certificate as soon as it runs. If a later command in
> the chain fails, kube-apiserver still trusts the old CA, and sign-ins fail until you install
> a matching configuration. To recover, run the same commands again **without**
> `--renew-certificate`: `genkanctl` reuses the certificate it just created and prints the
> configuration that matches it.

To change the validity, use `--certificate-validity`; see the
[genkanctl README](../crates/genkanctl/README.md#configure-token-limits-and-certificates).

## Troubleshooting

- **The browser shows a certificate error, or offers no passkey:** mkcert's CA is not trusted
  where the browser runs (`mkcert -install`), or the certificate's name does not match the
  issuer's host name.
- **`kubectl` says `Unauthorized`:** kube-apiserver may not have loaded the configuration from
  step 6. If it finds an error in the file, it ignores the file until it changes. On k3s, look
  for the reason with `sudo journalctl -u k3s | grep -i "authentication config"`.
- **Port 8000 is in use:** kubelogin listens there for the browser's redirect. Change
  `--listen-address` and `--oidc-redirect-url` together; any port on `127.0.0.1` matches the
  registered redirect URI.

## Clean up

On the server, uninstall k3s. This removes the cluster, Genkan and everything else installed
in it:

```sh
sudo /usr/local/bin/k3s-uninstall.sh
rm -rf ~/genkan-tls ~/authn.yaml ~/install-component.sh
```

Then, on your computer:

```sh
rm ~/.kube/genkan-k3s.yaml
rm -rf ~/.kube/cache/oidc-login ~/.kube/cache/oidc-login-elevated
```

# Get started: k3s on an Ubuntu server, kubectl with a passkey

By the end of this guide, you will sign in to a k3s cluster with a passkey and run
`kubectl` from your computer.

You will download Genkan, install it on an Ubuntu server, then set up HTTPS and your first
admin account. The server uses the Traefik ingress included with k3s.

The guide talks about two machines:

- **Your computer** runs the browser and `kubectl`. It can run macOS, Linux or Windows. The
  commands are written for a POSIX shell; on Windows, use WSL.
- **The server** runs k3s and Genkan. Any Ubuntu machine your computer can reach over the
  network works: a VPS, a homelab box, a spare PC or a local VM.

The cluster's admin kubeconfig stays on the server, where you use it to install things and to
get back in if Genkan breaks; keep an encrypted copy offline too. Your computer gets the
cluster's CA certificate and a kubeconfig that signs in through Genkan. Every request it sends
carries a token that expires within minutes.

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
WSL copies the Windows hosts file when it starts, so after editing it run `wsl --shutdown` in
Windows and open a new WSL terminal.

## What you need

On **your computer**:

- `kubectl`;
- [kubelogin](https://github.com/int128/kubelogin), the `kubectl` plugin that opens the browser
  to sign in. Install it with Homebrew (`brew install int128/kubelogin/kubelogin`), Nix
  (`nixpkgs#kubelogin-oidc`), or [krew](https://krew.sigs.k8s.io/docs/user-guide/setup/install/)
  (`kubectl krew install oidc-login`, after installing krew itself);
- [mkcert](https://github.com/FiloSottile/mkcert), with its local CA trusted where your browser
  runs: run `mkcert -install` once (it may ask for your password). Firefox also needs NSS's
  `certutil`; see mkcert's README. With WSL, the browser runs on Windows, so install the
  Windows build (for example `winget install FiloSottile.mkcert`) and call it as `mkcert.exe`
  from WSL, both here and in step 4.
- `ssh` access to the server.

On **the server**: Ubuntu 24.04 or later on amd64 or arm64, 4 CPUs, 8 GiB memory and
30 GiB free disk. Install `curl` and [cosign 3.x](https://docs.sigstore.dev/cosign/system_config/installation/).
Allow your computer to reach TCP ports 443 (sign-in) and 6443 (Kubernetes API).
Use a spare machine or VM: this guide installs k3s and changes its configuration.

Keep two terminals open: one on your computer, and one logged in to the server. Each step says
which one to use. In the terminal on your computer, set the SSH login so later commands can use
it:

```sh
SERVER=ubuntu@genkan.example.test
```

## 1. Download Genkan

Log in to the server:

```sh
ssh "$SERVER"
```

Choose a version from [GitHub Releases](https://github.com/engawahq/genkan/releases).
The examples use `v0.0.1`. Set `arch` to `amd64` for x86_64 or `arm64` for aarch64:

```sh
version=v0.0.1
arch=arm64
mkdir -p ~/genkan-download
```

Download the CLI, its signed checksums and the image digests. This block verifies the files
before installing `genkanctl`:

```sh
(
  set -eu
  cd ~/genkan-download
  url="https://github.com/engawahq/genkan/releases/download/$version"
  archive="genkanctl-$version-linux-$arch.tar.gz"
  for file in "$archive" SHA256SUMS SHA256SUMS.sigstore.json image-digests.txt; do
    curl --fail --location "$url/$file" --output "$file"
  done
  identity="https://github.com/engawahq/genkan/.github/workflows/release.yml@refs/tags/$version"
  cosign verify-blob --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
  sha256sum --check --strict --ignore-missing SHA256SUMS
  tar -xzf "$archive"
  sudo install -m 0755 genkanctl /usr/local/bin/genkanctl
  genkanctl --version
)
```

Now verify the image and its SBOM (the list of dependencies shipped in it). `GENKAN_IMAGE`
holds the release's exact image digest, which you will use when installing:

```sh
GENKAN_IMAGE=$(awk '$1 == "index" {print $2}' ~/genkan-download/image-digests.txt)
export GENKAN_IMAGE
identity="https://github.com/engawahq/genkan/.github/workflows/release.yml@refs/tags/$version"
cosign verify --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$GENKAN_IMAGE"
cosign verify-attestation --type cyclonedx --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$GENKAN_IMAGE"
```

Continue once both commands succeed. See [Releases](releases.md) for the platform list and
the other files included in a release.

## 2. Install k3s

> [!IMPORTANT]
> Step 5 changes how kube-apiserver checks who you are. Keep the admin kubeconfig below and
> SSH access so you can recover. Read
> [Backup, recovery and emergency access](operations.md) before that step.

Run the following on the server. It adds your host name to the API server's certificate and
sets up an empty authentication file. Step 5 fills that file with Genkan's settings.

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
export KUBECONFIG="$HOME/.kube/config"
```

`~/.kube/config` is the cluster-admin credential. Use it to install things and to get back in
when Genkan is down, not for everyday work. Keep it on the server, and keep an encrypted copy
offline as described in
[Keep a way in that doesn't need Genkan](operations.md#keep-a-way-in-that-doesnt-need-genkan).

Check that the node and k3s's built-in ingress are ready:

```sh
kubectl wait --for=condition=Ready node --all --timeout=180s
kubectl -n kube-system wait --for=create deployment/traefik --timeout=180s
kubectl -n kube-system rollout status deployment/traefik --timeout=180s
```

## 3. Install Genkan

Run this in the same server shell:

```sh
export GENKAN_ISSUER=https://genkan.example.test
genkanctl crds | kubectl apply --server-side -f -
kubectl wait --for=condition=Established --timeout=90s \
  crd/users.genkan.engawahq.dev crd/credentials.genkan.engawahq.dev \
  crd/oauthclients.genkan.engawahq.dev crd/grants.genkan.engawahq.dev \
  crd/invitations.genkan.engawahq.dev
genkanctl manifests --image "$GENKAN_IMAGE" \
  --serve-arg=--invitations | kubectl apply --server-side -f -
kubectl -n genkan-system rollout status deploy/genkan --timeout=180s
```

The generated manifests include RBAC, the Service and the Deployment. Everything Genkan
owns lives in `genkan-system`. `--invitations` enables the links you will use to
[invite people](managing-users.md#add-someone).

Keep using this server shell. If you open a new one, restore these settings:

```sh
export KUBECONFIG="$HOME/.kube/config"
export GENKAN_ISSUER=https://genkan.example.test
GENKAN_IMAGE=$(kubectl -n genkan-system get deployment genkan -o jsonpath='{.spec.template.spec.containers[0].image}')
export GENKAN_IMAGE
```

## 4. Publish the sign-in page over HTTPS

Browsers need a trusted HTTPS connection to create passkeys. This guide uses mkcert for
your test machine. For a public service, use a certificate from a public CA, for example
through [cert-manager](https://cert-manager.io/docs/).

On your computer, issue a certificate for the issuer's host name and copy it to the server. Only the
certificate and its key leave your computer; the CA's key stays. With WSL, write `mkcert.exe`
instead of `mkcert`.

```sh
mkcert -cert-file genkan.crt -key-file genkan.key genkan.example.test
ssh "$SERVER" 'install -d -m 700 ~/genkan-tls'
scp genkan.crt genkan.key "$SERVER":genkan-tls/
rm genkan.key
```

On the server, store the certificate as a Secret and create an Ingress. K3s's Traefik
accepts HTTPS on port 443 and forwards requests to Genkan:

```sh
kubectl -n genkan-system create secret tls genkan-tls \
  --cert=$HOME/genkan-tls/genkan.crt --key=$HOME/genkan-tls/genkan.key
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: genkan
  namespace: genkan-system
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  ingressClassName: traefik
  tls:
  - hosts: [genkan.example.test]
    secretName: genkan-tls
  rules:
  - host: genkan.example.test
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: genkan
            port: {number: 80}
EOF
```

Give Traefik a few seconds to load the route and certificate, then check from your computer.
You should get a JSON document whose `issuer` is `https://genkan.example.test`:

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

For a public server, limit requests to the sign-in endpoints by client IP address.
You can skip this section on a server only you can reach.

First, preserve each visitor's address through k3s's load balancer. On the server, set
Traefik's `externalTrafficPolicy` to `Local` so visitors get separate rate-limit counters:

```sh
kubectl apply -f - <<'EOF'
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata: {name: traefik, namespace: kube-system}
spec:
  valuesContent: |-
    service:
      spec:
        externalTrafficPolicy: Local
EOF
```

This uses k3s's [Traefik configuration](https://docs.k3s.io/helm/#customizing-packaged-components-with-helmchartconfig).
On a cluster with several nodes, `Local` means only nodes with a Traefik pod accept traffic.

Then add a rate limit to the sign-in routes:

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
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: genkan-rate-limited
  namespace: genkan-system
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
    traefik.ingress.kubernetes.io/router.middlewares: genkan-system-genkan-rate-limit@kubernetescrd
spec:
  ingressClassName: traefik
  tls:
  - hosts: [genkan.example.test]
    secretName: genkan-tls
  rules:
  - host: genkan.example.test
    http:
      paths:
      - {path: /authorize, pathType: Exact, backend: {service: {name: genkan, port: {number: 80}}}}
      - {path: /token, pathType: Exact, backend: {service: {name: genkan, port: {number: 80}}}}
      - {path: /par, pathType: Exact, backend: {service: {name: genkan, port: {number: 80}}}}
      - {path: /revoke, pathType: Exact, backend: {service: {name: genkan, port: {number: 80}}}}
      - {path: /login, pathType: Prefix, backend: {service: {name: genkan, port: {number: 80}}}}
      - {path: /setup, pathType: Prefix, backend: {service: {name: genkan, port: {number: 80}}}}
      - {path: /upstream, pathType: Prefix, backend: {service: {name: genkan, port: {number: 80}}}}
EOF
```

This route takes precedence over the catch-all route for the listed paths. Discovery and keys
stay unlimited, because kube-apiserver and every client fetch them.

To check it, send 60 requests at once from your computer. About 20 get `200`, the rest
`429 Too Many Requests`:

```sh
ca="$(mkcert -CAROOT)/rootCA.pem"
for i in $(seq 1 60); do
  curl -s -o /dev/null -w '%{http_code}\n' --cacert "$ca" https://genkan.example.test/login &
done | sort | uniq -c
```

Treat the numbers as a starting point:

- People behind one NAT share one address, and so share one limit. Raise it if your office
  signs in at the same time each morning.
- If another proxy sits in front of Traefik, configure Traefik to trust forwarded headers from
  that proxy only. Otherwise everyone shares one bucket, or a forged header gets around it.
- Each Traefik replica keeps its own count unless you set up distributed rate limiting.

See Traefik's [RateLimit options][traefik-ratelimit] for the details.

[traefik-ratelimit]: https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/

## 5. Let kube-apiserver trust Genkan

First make sure you can get back in without Genkan. On the server, check that the admin
kubeconfig from step 2 works:

```sh
sudo k3s kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml auth whoami
sudo k3s kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get --raw=/readyz
```

If either fails, stop here and fix it. Save an encrypted copy offline if you haven't yet.

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

## 6. Register kubectl and create the first passkey

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

## 7. Set up kubectl on your computer

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
Add the CA to both `args` lists, using the path from the WSL check in step 4:

```sh
wslpath "$(mkcert.exe -CAROOT | tr -d '\r')"   # e.g. /mnt/c/Users/you/AppData/Local/mkcert
```

```yaml
        --certificate-authority=/mnt/c/Users/you/AppData/Local/mkcert/rootCA.pem,
```

kubelogin cannot open the Windows browser from WSL either. Instead it prints
`Please visit the following URL in your browser manually: http://127.0.0.1:8000/`. Open that
address in your browser, and the sign-in continues as usual.

Keep `--oidc-use-access-token`: kube-apiserver accepts only Genkan's access tokens, not ID
tokens.

## 8. Try it

```sh
export KUBECONFIG=~/.kube/genkan-k3s.yaml
kubectl auth whoami                      # opens the browser; user genkan:admin, group genkan:admins
kubectl get pods -A                      # allowed: genkan:admins has the built-in view role
kubectl -n default create configmap genkan-permission-check --from-literal=check=ok
# Forbidden: the everyday context is read-only.
kubectl --context genkan-k3s-admin -n default create configmap genkan-permission-check --from-literal=check=ok
# Asks for your passkey again, then creates the ConfigMap.
kubectl --context genkan-k3s-admin auth whoami
# Includes genkan:elevated:admins.
kubectl --context genkan-k3s-admin -n default delete configmap genkan-permission-check
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

- [Back up, recover and upgrade Genkan](operations.md), and get back in when Genkan or the
  sign-in page is down.
- [Manage users](managing-users.md): invite people, add passkeys, sign people out or remove
  them.
- [Sign in with GitHub](github-sign-in.md) or [Google](google-sign-in.md) as an alternative
  to the passkey for everyday access.
- [Register more clients](clients.md), such as Grafana or Argo CD, so they sign people in
  through Genkan too.

## Once a year: renew the internal certificate

The certificate from step 5 is valid for 365 days. If it expires, kube-apiserver can no longer
fetch Genkan's keys, and every sign-in to the cluster fails. Running `genkanctl kube-config`
again replaces the certificate automatically when it has less than 30 days left;
`--renew-certificate` replaces it now.

On the server, restore the environment from step 3 and define the `reloads` and
`wait_for_reload` helpers from step 5:

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
prints, not the one from step 5. Sign-ins can fail briefly while Genkan and kube-apiserver both
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
  step 5. If it finds an error in the file, it ignores the file until it changes. On k3s, look
  for the reason with `sudo journalctl -u k3s | grep -i "authentication config"`.
- **Port 8000 is in use:** kubelogin listens there for the browser's redirect. Change
  `--listen-address` and `--oidc-redirect-url` together; any port on `127.0.0.1` matches the
  registered redirect URI.

## Clean up

On the server, uninstall k3s. This removes the cluster, Genkan and everything else installed
in it:

```sh
sudo /usr/local/bin/k3s-uninstall.sh
rm -rf ~/genkan-tls ~/authn.yaml ~/genkan-download
```

Then, on your computer:

```sh
rm ~/.kube/genkan-k3s.yaml
rm -rf ~/.kube/cache/oidc-login ~/.kube/cache/oidc-login-elevated
```

# Registering clients

Every application that signs people in through Genkan, `kubectl` included, is an `OAuthClient`
object in Genkan's namespace. The object name is the `client_id`. `genkanctl client create`
checks your input, prints the object as JSON, and generates the secret when the client needs
one. The commands below assume the cluster from [get-started.md](get-started.md): namespace
`genkan-system`, run with the cluster admin's kubeconfig.

There are two kinds of client:

| Type | For | Authenticates with |
|---|---|---|
| `public` | `kubectl`, desktop and browser-only apps: anything that runs on the user's device | its `client_id` and PKCE |
| `confidential` | web apps with a server side (Grafana, Argo CD, Headlamp, …) | a secret, plus PKCE |

## Public clients

```sh
genkanctl client create kubectl --type public \
  --redirect-uri http://127.0.0.1:8000/ --audience kubernetes | kubectl apply -f -
```

A redirect URI is `https://` with a host name (`https://app.example.com/callback`), or
`http://127.0.0.1/…` or `http://[::1]/…` for apps that receive the code on the user's own
machine. For those loopback addresses any port matches, so `kubectl` still works when it has to
listen on a different port. Fragments, user information and plain `http` to other hosts are
rejected.

Genkan compares redirect URIs as exact strings, so `genkanctl` accepts a URI only in the form a
browser writes it: lowercase scheme and host, no default port, at least a `/` path
(`https://app.example.com/`, not `https://app.example.com`), `xn--` host names and
percent-encoded paths instead of non-ASCII, and every `%` followed by two hex digits. It also
rejects addresses a browser refuses, such as `999.1.1.1` or port `99999`.

`--audience` lists what the client may request tokens for. Add `kubernetes` (the audience
`genkanctl kube-config` configured) when the app calls the Kubernetes API as the signed-in user.

`--allow-elevation` lets the client request the `elevate` scope: a short token with the user's
elevated groups after a fresh passkey sign-in. Leave it off unless the client is meant for
administration, like the admin `kubectl` context in [get-started.md](get-started.md); see
[managing-users.md](managing-users.md) for elevated groups.

## Confidential clients

```sh
genkanctl client create grafana --type confidential --display-name Grafana \
  --redirect-uri https://grafana.example.com/login/generic_oauth | kubectl apply -f -
```

The object goes to stdout. The client secret goes to stderr, so it shows in your terminal but
never lands in the object, in `kubectl`'s input or in a GitOps repository. It is shown once:
the cluster keeps only its SHA-256 hash. Give it to the application right away, for example as
a Secret in the application's namespace. Pipe it in rather than passing it as an argument, which
other users can see in the process list:

```sh
read -rs CLIENT_SECRET     # paste the secret, then Enter
printf %s "$CLIENT_SECRET" | kubectl -n monitoring create secret generic grafana-oidc \
  --from-file=client-secret=/dev/stdin
unset CLIENT_SECRET
```

Configure the application with the issuer URL, the `client_id` (here `grafana`) and that
secret. It finds the endpoints through `/.well-known/openid-configuration` and sends the secret
with HTTP Basic (`client_secret_basic`) or in the form (`client_secret_post`).

### Never choose a secret yourself

Anyone who can read `OAuthClient` objects, or your GitOps repository, can read the hash. Genkan
hashes without a salt, which is safe only for long random secrets. A password that a person
picked can be recovered from its hash with a dictionary attack, and Genkan cannot notice because
it never sees the secret itself. Always let `genkanctl client create` generate it.

Without `genkanctl`, generate 32 random bytes and hash them yourself:

```sh
CLIENT_SECRET=$(openssl rand -hex 32)
printf 'sha256:%s\n' "$(printf %s "$CLIENT_SECRET" | sha256sum | cut -d' ' -f1)"   # secretHash
```

## Replace a secret

Run the same `genkanctl client create` command again and apply its output. The new hash
replaces the old one, and the old secret stops working right away, so update the application's
Secret in the same step.

## Change or remove a client

Edit the object like any other (`kubectl -n genkan-system edit oauthclient grafana`), or run
`genkanctl client create` with the new options and apply it. That also replaces the secret of a
confidential client.

```sh
kubectl -n genkan-system get oauthclients                  # short name: gkclient
kubectl -n genkan-system delete oauthclient grafana        # nobody can sign in to it any more
```

## GitOps

The printed object contains no secret, so you can commit it. Convert it to YAML if you prefer:

```sh
genkanctl client create grafana --type confidential --display-name Grafana \
  --redirect-uri https://grafana.example.com/login/generic_oauth \
  | kubectl apply --dry-run=client -o yaml -f - > grafana-client.yaml
```

The cluster checks the same rules when the object is applied, so a hand-edited object with a
plain `http` or fragment redirect URI or a malformed `secretHash` fails at `kubectl apply`, not at
sign-in. The cluster parses URLs with Kubernetes' own `isURL()`, which is looser than a browser,
so run hand-written redirect URIs through `genkanctl client create` to catch the rest.

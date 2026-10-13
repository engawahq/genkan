# Registering clients

Before an application can sign people in through Genkan, you register it as a client. Each
client is an `OAuthClient` object in Genkan's namespace, and its name is the application's
`client_id`. `kubectl` is a client too; [Get started](get-started.md) registered it.

`genkanctl client create` builds the object for you: it checks your input, prints the object,
and generates a secret when the client needs one. Pipe its output into `kubectl apply`. The
commands below assume the cluster from [Get started](get-started.md) (namespace
`genkan-system`) and run with the cluster admin's kubeconfig.

First decide which kind of client the application is:

| Type | For | Authenticates with |
|---|---|---|
| `public` | `kubectl`, desktop and browser-only apps: anything that runs on the user's device | its `client_id` and PKCE |
| `confidential` | web apps with a server side (Grafana, Argo CD, Headlamp, …) | a secret, plus PKCE |

## Public clients

```sh
genkanctl client create kubectl --type public \
  --redirect-uri http://127.0.0.1:8000/ --audience kubernetes | kubectl apply -f -
```

The options:

- **`--redirect-uri`** is where the browser goes back to after sign-in. Repeat it for several.
- **`--audience kubernetes`** lets the client get tokens that kube-apiserver accepts. Add it
  only when the application calls the Kubernetes API as the signed-in person.
- **`--allow-elevation`** lets the client ask for admin rights (the user's elevated groups, after
  a fresh passkey sign-in). Leave it off unless the client is for administering the cluster,
  like `kubectl`. See [Admin rights](managing-users.md#admin-rights).

### Redirect URIs

A redirect URI is one of:

- `https://` with a host name, such as `https://app.example.com/callback`;
- `http://127.0.0.1/…` or `http://[::1]/…`, for apps that receive the result on the user's own
  machine. Any port matches, so `kubectl` still works when it has to listen on another port.

Genkan compares redirect URIs exactly, character by character. To prevent near-misses,
`genkanctl` accepts a URI only in the form a browser sends it:

- lowercase scheme and host, and no default port (`:443`);
- at least a `/` path: `https://app.example.com/`, not `https://app.example.com`;
- non-ASCII written as `xn--` host names and percent-encoded paths.

It rejects fragments (`#…`), user names in the URI, plain `http` to any other host, and
addresses a browser would refuse, such as `999.1.1.1` or port `99999`.

## Confidential clients

```sh
genkanctl client create grafana --type confidential --display-name Grafana \
  --redirect-uri https://grafana.example.com/login/generic_oauth | kubectl apply -f -
```

The command prints the client secret in your terminal (on stderr), separately from the object.
The secret never ends up in the object, in `kubectl`'s input or in Git. **It is shown only
once**: the cluster keeps just its SHA-256 hash.

Give the secret to the application right away, for example as a Secret in the application's
namespace. Paste it in as below rather than passing it as a command argument, which other users
on the machine can see in the process list:

```sh
read -rs CLIENT_SECRET     # paste the secret, then Enter
printf %s "$CLIENT_SECRET" | kubectl -n monitoring create secret generic grafana-oidc \
  --from-file=client-secret=/dev/stdin
unset CLIENT_SECRET
```

Then configure the application with three values: the issuer URL, the `client_id` (here
`grafana`) and the secret. It finds everything else through
`<issuer>/.well-known/openid-configuration`. Genkan accepts the secret either way applications
send it: HTTP Basic (`client_secret_basic`) or a form field (`client_secret_post`).

### Never choose a secret yourself

Always let `genkanctl client create` generate the secret. The hash is visible to anyone who can
read `OAuthClient` objects or your Git repository, and it has no salt. That is safe for a long
random secret, but a password someone chose can be guessed back from its hash offline, and
Genkan would never notice.

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

If you edit the object by hand, the cluster checks it when you apply it: a plain `http` or
fragment redirect URI, or a malformed `secretHash`, fails at `kubectl apply` rather than at
sign-in. The cluster's URL check is looser than `genkanctl`'s, though, so run new redirect URIs
through `genkanctl client create` to catch the rest.

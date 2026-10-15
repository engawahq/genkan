# Backup, recovery and emergency access

Genkan sits in front of your cluster, so you have to plan for the day it stops working. This
guide explains how to keep a way into the cluster that doesn't depend on Genkan, what to back
up, how to restore it, and how to upgrade without losing anything.

Read it at three moments:

- **before you point kube-apiserver at Genkan**, so you have a way back in;
- **when something breaks**: Genkan is down, the sign-in page is unreachable, or kube-apiserver
  won't start;
- **before an upgrade**.

The examples use the namespace `genkan-system` from [Get started](get-started.md). If you
installed Genkan somewhere else, use your namespace and paths throughout. Paste each command
block into one terminal; later blocks reuse the variables earlier ones set. If a command fails,
stop there and fix it before running the rest.

> [!IMPORTANT]
> Passkeys replace the admin kubeconfig **for everyday work**. They don't replace it as your
> emergency key. Keep that kubeconfig, store a copy offline, and never delete your only way into
> the cluster before you have practised getting back in.

## Contents

- [Keep a way in that doesn't need Genkan](#keep-a-way-in-that-doesnt-need-genkan)
- [Genkan or the sign-in page is down](#genkan-or-the-sign-in-page-is-down)
- [What to back up](#what-to-back-up)
- [Take a backup](#take-a-backup)
- [Restore, keeping everyone's identity](#restore-keeping-everyones-identity)
- [Restore by recreating resources](#restore-by-recreating-resources)
- [Lost signing keys or internal certificate](#lost-signing-keys-or-internal-certificate)
- [Back up and restore a single-server k3s](#back-up-and-restore-a-single-server-k3s)
- [kube-apiserver won't start](#kube-apiserver-wont-start)
- [Upgrade and roll back](#upgrade-and-roll-back)
- [Practise before you need it](#practise-before-you-need-it)

## Keep a way in that doesn't need Genkan

You need two things that keep working when Genkan doesn't:

1. **An admin kubeconfig that uses a client certificate**, not a Genkan sign-in. Every
   distribution creates one:

   | Distribution | Admin kubeconfig |
   |---|---|
   | k3s | `/etc/rancher/k3s/k3s.yaml` |
   | k0s | the output of `k0s kubeconfig admin`, saved to a file |
   | kubeadm | `/etc/kubernetes/admin.conf` |

2. **SSH or console access to every control-plane machine.** The admin kubeconfig only helps
   while kube-apiserver is running. If a bad configuration stops it from starting, the fix
   happens on the machine itself.

Check that the admin kubeconfig really works on its own before you change kube-apiserver's
authentication. For k3s:

```sh
sudo k3s kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml auth whoami
sudo k3s kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get --raw=/readyz
```

Then look after it:

- **Keep it off everyday computers.** It is a cluster-admin credential.
- **Keep an encrypted copy offline**, away from the cluster, and store the key that decrypts it
  somewhere else again. A copy that only lives on the server disappears with the server.
- **Watch the certificate's expiry date.** A kubeconfig that worked on install day can expire.
  Follow your distribution's renewal steps.

### Write down how kube-apiserver is configured today

Before you change anything, record how each control-plane machine starts kube-apiserver: the
distribution and Kubernetes version, which configuration files it reads, and any existing
`--oidc-*`, `--authentication-config` or `--anonymous-auth` settings (including "not set"). You
will need this to undo the change. The service unit shows where the settings come from:

```sh
sudo systemctl cat k3s              # k3s
sudo systemctl cat k0scontroller    # k0s
```

Then save a copy of the current configuration on each machine, in a root-only directory that
kube-apiserver and the kubelet don't watch:

```sh
RECOVERY=/var/backups/genkan-control-plane/$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$RECOVERY"
# Run the line for your distribution.
sudo cp -a /etc/rancher/k3s "$RECOVERY/k3s"           # k3s
sudo cp -a /etc/k0s/k0s.yaml "$RECOVERY/k0s.yaml"      # k0s
sudo cp -a /etc/kubernetes "$RECOVERY/kubernetes"     # kubeadm
```

On kubeadm, also save the cluster configuration while the API still answers:

```sh
umask 077
kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system \
  get configmap kubeadm-config -o yaml > kubeadm-config.before-genkan.yaml
```

These copies can contain private keys, so treat them like the admin kubeconfig: keep an
encrypted copy off the machine too.

If your cluster already has an authentication configuration file with other issuers, **don't**
overwrite it with the one Genkan generates. Add Genkan's `jwt` entry to it instead.

### Authentication and anonymous access go together

Two kube-apiserver rules trip people up when they undo a change:

- `--authentication-config` can't be combined with `--oidc-*` flags.
- If the authentication file has an `anonymous` section, kube-apiserver must not also get an
  `--anonymous-auth` flag.

So when you go back, restore the previous authentication **and** anonymous settings together.
Each distribution handles anonymous access a little differently in Genkan's output:

- **k3s:** the file sets `anonymous.enabled: false`, because k3s drops its own
  `--anonymous-auth=false` once an authentication file is in use.
- **k0s:** the file has no `anonymous` section and k0s keeps its flag. Don't add one; some k0s
  releases reject the combination.
- **kubeadm:** the file allows anonymous access only to `/livez`, `/readyz` and `/healthz`, so
  the kubelet's health checks keep working. If you remove all anonymous access without changing
  those checks, the kubelet keeps restarting a healthy kube-apiserver.
- **generic:** anonymous access is left to you.

A running kube-apiserver reloads a valid authentication file by itself. A missing or broken
file is not a way to switch Genkan off; it can leave kube-apiserver in an unknown state.

## Genkan or the sign-in page is down

Start with the admin kubeconfig, talking to kube-apiserver directly. Don't rely on a cached
Genkan token or an open browser session: tokens already issued keep working until they expire
(minutes), but nobody can sign in or refresh while Genkan is down.

For k3s, on the server:

```sh
sudo k3s kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get --raw=/readyz
sudo k3s kubectl -n genkan-system get deploy,pods,svc,endpointslices
sudo k3s kubectl -n genkan-system logs deploy/genkan --tail=100
```

If `/readyz` fails, kube-apiserver itself is the problem: go to
[kube-apiserver won't start](#kube-apiserver-wont-start).

Otherwise, work out which part is down:

- **Genkan was scaled to zero.** Scale it back to its usual replica count (one in a standard
  install):

  ```sh
  sudo k3s kubectl -n genkan-system scale deploy/genkan --replicas=1
  sudo k3s kubectl -n genkan-system rollout status deploy/genkan --timeout=5m
  ```

- **Genkan is running but failing.** Read the logs and fix the cause: the image,
  configuration or resources. Restarting it again and again rarely helps.
- **Genkan is fine but its public URL isn't.** Check the ingress controller, routes, DNS and
  the public certificate. Kubernetes still fetches Genkan's keys over the internal address, but
  browsers and `kubectl` sign-ins go through the public one.

Things that make it worse:

- **Changing the issuer's host name to get around the outage.** Tokens and passkeys are tied to
  that host name; a new one breaks both.
- **Running `genkanctl setup-link --reset`.** It deletes a user's passkeys and sessions. It
  doesn't fix a pod, an ingress or kube-apiserver.
- **Pasting tokens, links, headers or Secret contents into a chat or ticket.**

### Check that it's really fixed

A ready pod isn't enough. Sign in again from scratch with a passkey, so you know new sign-ins
work and not just cached tokens. On your computer, with the kubeconfig from
[Get started](get-started.md#7-set-up-kubectl-on-your-computer):

```sh
export KUBECONFIG=~/.kube/genkan-k3s.yaml
rm -rf ~/.kube/cache/oidc-login ~/.kube/cache/oidc-login-elevated   # forget cached tokens
kubectl auth whoami
kubectl auth can-i list pods --all-namespaces
kubectl auth can-i '*' '*' --all-namespaces
kubectl --context=genkan-k3s-admin auth can-i '*' '*' --all-namespaces
```

You should see your username as `genkan:<username>`, then `yes`, `no` and, for an admin, `yes`.

Right after kube-apiserver restarts, sign-ins can fail for a short while with
`oidc: authenticator not initialized`: kube-apiserver hasn't fetched Genkan's keys yet. Give it
a few minutes. If it keeps failing, check kube-apiserver's logs, the `genkan` Service endpoints
and the internal certificate. Never turn off certificate checks to make it work.

## What to back up

### Two ways to restore, two different results

Genkan identifies each person by their `User` object's UID. The UID goes into the `sub` claim
of every token, and every passkey is bound to it. Kubernetes assigns UIDs when it creates an
object, so how you restore decides whether people keep their identity:

| | Restore the cluster's datastore | Recreate resources from an export |
|---|---|---|
| User UIDs | Kept | New |
| Existing passkeys | Keep working | Everyone enrols again |
| Apps that track users by `sub` | See the same people | See new people |
| Sessions | Delete them; everyone signs in again | Don't restore them |

So the main backup is **your distribution's datastore backup** (etcd or SQLite snapshot). A
`kubectl get -o json` export is a useful fallback, not a replacement.

Why the export can't keep identities:

- `kubectl` usernames stay the same (`genkan:alice`), but the `sub` claim changes. Apps that
  key accounts on `sub` treat Alice as a new person. Plan that migration with each app.
- A passkey stores the old UID. Genkan rejects it when it doesn't match the new one, and editing
  the `Credential` object can't change what's on the authenticator.
- Credentials, grants and invitations point to their user through an `ownerReference` with the
  UID. A stale reference can make Kubernetes garbage-collect the object.

Never run two copies of the same issuer, with the same signing keys, at the same time. Keep a
restored copy away from production DNS, upstream sign-in callbacks and users until you switch
over.

### The list

Keep these together, with a note of the date, the Genkan image and `genkanctl` version, the
cluster version, the namespace, the issuer URL and the install options you used:

| What | Why it matters |
|---|---|
| The cluster's datastore backup, plus what the distribution needs to open it (server token, encryption keys, cluster certificates) | The only way to keep UIDs and passkeys. A snapshot you can't decrypt isn't a backup. |
| `users`, `credentials`, `oauthclients` (`*.genkan.engawahq.dev`) | People and their groups, passkey records and linked GitHub or Google accounts, registered clients. |
| Secret `genkan-signing-keys` | All of Genkan's private signing keys, including upcoming and retired ones. Can't be rebuilt from anything else. |
| Secret `genkan-internal-tls` | The certificate kube-apiserver uses to reach Genkan internally. Belongs with the authentication file on each control-plane machine. |
| Deployment, Service, ServiceAccount, Role and RoleBinding `genkan`; ClusterRoleBindings `genkan-admins` and `genkan-elevated-admins` | How Genkan runs and who gets admin rights. Back up your own RoleBindings for other apps too. |
| Secrets mounted into Genkan, such as `genkan-config` | GitHub and Google client secrets. Keep the upstream app registrations with them. |
| Public TLS and routing | In Get started: Secret `genkan-tls`, Ingress `genkan`; for rate limiting, Ingress `genkan-rate-limited`, Middleware `genkan-rate-limit` and the `traefik` HelmChartConfig in `kube-system`. |
| kube-apiserver's configuration on each control-plane machine | For k3s: `/etc/rancher/k3s/genkan/authn.yaml` and the config that loads it. |
| Client secrets of confidential apps, in those apps' own secret stores | Genkan keeps only a hash. See below. |
| Your GitOps or user-provisioning configuration | Otherwise it may overwrite what you restore the moment it resumes. |

Leave these out of every restore: `Grant` objects (sessions), `Invitation` objects and the
`genkan-setup` Secret. An old backup can bring back a session you revoked or an invite link
someone shouldn't still have. Export them if you want a record, but delete them after
restoring.

Sign-ins in progress don't need a backup. Genkan keeps them in memory, so people just start
again.

Restoring old data can also bring back things you removed since: a disabled user, a deleted
passkey, an old client secret, admin rights you took away. A restore always ends with a review
of who has access.

### Confidential client secrets

An `OAuthClient` stores only a hash of its secret. `genkanctl client create` shows the secret
once; Genkan can't give it back. After a restore, the client works only if the app still has the
matching secret. If you rotated the secret after the backup, the restored hash is the old one.
Either give the app the matching secret, or [generate a new one](clients.md#replace-a-secret) and
update both sides. The command doesn't keep options you leave out, so pass them all again.

## Take a backup

This export goes alongside your datastore backup. You need `kubectl`, `jq`, `tar` and
[`age`](https://github.com/FiloSottile/age), Bash, and the admin kubeconfig.

Genkan has to be stopped while you export, so the users, credentials and keys all come from the
same moment. That means a short planned outage. Before you start:

- tell people;
- pause GitOps, user provisioning and anything else that writes these objects;
- work in a private directory on an encrypted disk. Don't turn on `set -x`, print Secrets, or
  commit the files. Base64 isn't encryption.

```sh
umask 077
NS=genkan-system
BACKUP=$(mktemp -d "$HOME/genkan-backup.XXXXXXXX")

# Remember how many replicas Genkan had, then stop it.
kubectl -n "$NS" get deploy genkan -o json > "$BACKUP/deployment.json"
jq -r '.spec.replicas // 1' "$BACKUP/deployment.json" > "$BACKUP/replicas.txt"
kubectl -n "$NS" scale deploy/genkan --replicas=0
kubectl -n "$NS" wait --for=delete pod \
  -l app.kubernetes.io/name=genkan --timeout=180s

for resource in users credentials oauthclients grants invitations; do
  kubectl -n "$NS" get "$resource.genkan.engawahq.dev" -o json \
    > "$BACKUP/$resource.json"
done
kubectl -n "$NS" get secret genkan-signing-keys genkan-internal-tls -o json \
  > "$BACKUP/identity-secrets.json"
kubectl -n "$NS" get svc genkan -o json > "$BACKUP/service.json"
kubectl -n "$NS" get serviceaccount/genkan role/genkan rolebinding/genkan -o json \
  > "$BACKUP/namespaced-rbac.json"
kubectl get clusterrolebinding genkan-admins genkan-elevated-admins -o json \
  > "$BACKUP/admin-bindings.json"
kubectl get crd users.genkan.engawahq.dev credentials.genkan.engawahq.dev \
  oauthclients.genkan.engawahq.dev grants.genkan.engawahq.dev \
  invitations.genkan.engawahq.dev -o json > "$BACKUP/crds.json"

# Save every Secret mounted into Genkan, whatever it's called.
jq -r '.spec.template.spec.volumes[]? | .secret.secretName // empty' \
  "$BACKUP/deployment.json" | while IFS= read -r secret; do
    kubectl -n "$NS" get secret "$secret" -o json \
      > "$BACKUP/mounted-secret-$secret.json"
  done
```

If a command fails, start Genkan again before you look into it, so the backup doesn't turn into
an outage:

```sh
kubectl -n "$NS" scale deploy/genkan --replicas="$(cat "$BACKUP/replicas.txt")"
```

Then fix the cause and start over: a half-finished directory isn't a backup.

Add your ingress resources. For the setup in Get started:

```sh
kubectl -n "$NS" get secret genkan-tls -o json > "$BACKUP/public-tls.json"
kubectl -n "$NS" get ingress genkan -o json > "$BACKUP/ingress.json"
```

If you enabled the guide's sign-in rate limit, save its configuration too:

```sh
kubectl -n "$NS" get ingress genkan-rate-limited -o json > "$BACKUP/rate-limited-ingress.json"
kubectl -n "$NS" get middleware.traefik.io genkan-rate-limit -o json > "$BACKUP/rate-limit.json"
kubectl -n kube-system get helmchartconfig traefik -o json > "$BACKUP/traefik-config.json"
```

If you also want a datastore snapshot from the same moment, take it now while Genkan is
stopped. Then start Genkan again and encrypt the export:

```sh
kubectl -n "$NS" scale deploy/genkan \
  --replicas="$(cat "$BACKUP/replicas.txt")"

# age asks for a passphrase. Store it somewhere you can reach when the cluster is gone.
cd ~
ARCHIVE="$(basename "$BACKUP").tar.gz.age"
tar -C "$BACKUP" -czf "$BACKUP.tar.gz" .
age -p -o "$ARCHIVE" "$BACKUP.tar.gz"
rm "$BACKUP.tar.gz"
shasum -a 256 "$ARCHIVE" > "$ARCHIVE.sha256"
```

`tar` runs on its own so you see it if it can't read a file; if it complains, don't keep that
archive. The checksum file names the archive without its directory, so it still works after
you move both files. Copy the archive and its `.sha256` file off the cluster, to storage only a few
people can read, and keep an offline copy. Keep the passphrase separate from the archive. Once
the copy is safe, delete the unencrypted directory. Resume GitOps and provisioning.

### Open a backup

Before either restore, check the archive and decrypt it into a new private directory on an
encrypted disk. Start in the directory that holds the archive and its `.sha256` file:

```sh
umask 077
ARCHIVE=genkan-backup.XXXXXXXX.tar.gz.age   # your archive's file name
shasum -a 256 -c "$ARCHIVE.sha256"
RESTORE=$(mktemp -d "$HOME/genkan-restore.XXXXXXXX")
age -d "$ARCHIVE" | tar -xz -C "$RESTORE"
cd "$RESTORE"
```

This directory now holds Genkan's private signing keys. Delete it when you're done.

## Restore, keeping everyone's identity

Use this when you have a datastore backup. People keep their identity and passkeys.

1. **Isolate, before anything starts.** A snapshot brings Genkan back the way it was when you
   took it. If it was running then, it starts again with the old sessions as soon as the cluster
   does. So before you start the restored cluster, make sure nobody can reach the issuer's
   public address: keep it on a separate network, or block the address at the firewall or load
   balancer. Keep upstream sign-in callbacks away from it too. Work with the admin kubeconfig,
   not a Genkan sign-in.
2. **Restore the datastore** with your distribution's procedure, including the token or keys it
   needs to decrypt it. Use the same Genkan version as when you took the backup.
3. **Stop Genkan** as soon as the API answers, and keep it stopped:

   ```sh
   kubectl -n genkan-system scale deploy/genkan --replicas=0
   ```

   Snapshots taken as in [Take a backup](#take-a-backup) already have it at zero. Compare the
   restored users' UIDs with `users.json` from your export. If they differ, the restore
   recreated the objects: switch to
   [Restore by recreating resources](#restore-by-recreating-resources).
4. **Review who has access.** Since the backup, someone may have been disabled, lost admin
   rights, or had a passkey or client secret revoked. Apply those changes again before anyone
   signs in. If you can't tell whether someone should still have access, leave them disabled
   until the person responsible decides. A passkey that still works doesn't mean its owner
   still should.
5. **Throw away sessions and one-time links**, still with Genkan stopped:

   ```sh
   NS=genkan-system
   kubectl -n "$NS" delete grants.genkan.engawahq.dev --all
   kubectl -n "$NS" delete invitations.genkan.engawahq.dev --all
   kubectl -n "$NS" delete secret genkan-setup --ignore-not-found
   ```

   Everyone is signed out. Tokens already issued still work until they expire, because they are
   self-contained: by default 10 minutes, or 5 for admin tokens, unless you changed the limits.
6. **Restore the rest:** configuration Secrets, app client secrets, public TLS, routes and
   kube-apiserver's authentication file. Check the internal certificate still matches the
   `genkan` Service's address and hasn't expired. If it doesn't, see
   [Lost signing keys or internal certificate](#lost-signing-keys-or-internal-certificate).
7. **Start Genkan** with the same image and issuer, at its usual replica count, then resume
   GitOps. Have an admin sign in fresh, check normal and admin access, and test one passkey
   from before the backup and one confidential client. Only then let everyone back in.

## Restore by recreating resources

Use this only when you have no datastore backup. Expect:

- new UIDs, so new `sub` values in every app;
- everyone enrols a new passkey;
- everyone signs in again.

Restore into an empty namespace or cluster. Don't delete a working production namespace to make
room.

1. **Install Genkan's CRDs, namespace, RBAC and Service** using the same Genkan version as the
   backup. Keep the Deployment at zero and keep the issuer away from users. Don't apply
   `crds.json`, `deployment.json` or `service.json` as they are: they carry fields the old
   cluster set, such as the Service's IP, that a new cluster may reject. **Don't start Genkan
   yet:** it would create new signing keys.
2. **Review `users.json` and `oauthclients.json`** and remove anyone or anything that shouldn't
   come back. Edit a working copy; keep the original archive as it is. Then create them. This
   strips the old cluster's metadata and creates every user **disabled**, so nobody gets in by
   accident:

   ```sh
   NS=genkan-system   # the namespace you are restoring into
   for resource in users oauthclients; do
     jq --arg ns "$NS" '
       {apiVersion:"v1", kind:"List", items:[.items[] |
         {apiVersion, kind,
          metadata: ({name:.metadata.name, namespace:$ns,
                      labels:(.metadata.labels // {}),
                      annotations:((.metadata.annotations // {}) |
                        del(."kubectl.kubernetes.io/last-applied-configuration"))}),
          spec:(if .kind == "User" then .spec + {disabled:true} else .spec end)}]}
     ' "$resource.json" > "$resource.restore.json"
     kubectl create -f "$resource.restore.json"
   done
   ```

   If `create` fails, stop and find out why. Don't switch to a forced apply or delete what's in
   the way.
3. **Restore the signing keys**, the internal and public TLS, and the configuration Secrets,
   **before** starting Genkan:

   ```sh
   for file in identity-secrets.json mounted-secret-*.json public-tls.json; do
     [ -e "$file" ] || continue
     jq --arg ns "$NS" '
       {apiVersion:"v1", kind:"List", items:[(if .kind == "List" then .items[] else . end) |
         {apiVersion, kind, type, data,
          metadata:{name:.metadata.name, namespace:$ns,
            labels:(.metadata.labels // {}),
            annotations:((.metadata.annotations // {}) |
              del(."kubectl.kubernetes.io/last-applied-configuration"))}}]}
     ' "$file" > "${file%.json}.restore.json"
     kubectl apply --server-side -f "${file%.json}.restore.json"
   done
   ```

   `identity-secrets.json` holds a list; the other files hold one Secret each, and the filter
   handles both. This uses `apply`, not `create`, because the installer already made an empty
   signing-key Secret. If apply reports a conflict, find out who owns the field before adding
   `--force-conflicts`.
4. **Leave the old credentials, sessions and links behind.** Don't create anything from
   `credentials.json`, `grants.json` or `invitations.json`. Old passkeys can't work with new
   UIDs. Old sessions point at users by name, so an old refresh token could get a token for
   whoever now has that name. People reconnect GitHub or Google themselves when they enrol.
5. **Bring back one admin.** Make the internal certificate and kube-apiserver's configuration
   match (see the next section), restore the routes, and start Genkan with users still kept
   out. Pick an existing admin from the restored users, check who they are, enable them and
   give them a setup link:

   ```sh
   GENKAN_ISSUER=https://genkan.example.test   # the original issuer
   RECOVERY_USER=alice                         # the admin you are bringing back
   kubectl -n "$NS" get users.genkan.engawahq.dev "$RECOVERY_USER" -o yaml
   kubectl -n "$NS" patch users.genkan.engawahq.dev "$RECOVERY_USER" \
     --type=merge -p '{"spec":{"disabled":false}}'
   genkanctl setup-link --namespace "$NS" --issuer "$GENKAN_ISSUER" \
     --username "$RECOVERY_USER" --reset
   ```

   Check that the `get` shows the account you expect before going on. If the name doesn't
   exist, `setup-link` creates a **new admin**. A setup link lets whoever holds it take over the
   account, so hand it over only in person or through a channel you trust.
6. **Let the others back in.** Enable each approved user and send them an invitation
   (`genkanctl invite --username alice`). Don't re-enable someone just because they're in the
   backup. Ask each app that uses Genkan to move accounts to the new `sub` values, and sign
   everyone out of those apps. Then resume GitOps and provisioning.

## Lost signing keys or internal certificate

### Signing keys

The private signing keys can't be rebuilt from anything else: not the public JWKS, not the
client hashes, not the passkeys. If you lose them and have no backup, Genkan has to start with
new keys. That's a reset, not a restore:

- tokens signed with the old keys stop working, though some apps may accept them until they
  refresh their key cache or the tokens expire;
- delete all grants and invitations and have everyone sign in again;
- users and passkeys are unaffected.

If the `genkan-signing-keys` Secret is empty, Genkan creates new keys when it starts. If the
Secret is gone, Genkan can't create it: recreate the empty Secret with the installer as cluster
admin, and only after you've checked every backup.

If the keys may have been **stolen**, restoring them isn't a fix. Treat it as a key compromise
and start with new keys.

### Internal certificate

`genkan-internal-tls` is the certificate kube-apiserver checks when it fetches Genkan's keys over
the internal address. `genkanctl kube-config` throws away the CA's private key after signing, so a
new certificate always comes with a new CA, and kube-apiserver needs the matching configuration.
Restoring only the Secret, or only the file on the control-plane machine, leaves them out of
step.

To replace it, once the `genkan` Service exists, run `genkanctl kube-config` for your
distribution with the original issuer. It doesn't need Genkan to be running. It reuses the
certificate if it is still good, and `--renew-certificate` forces a new one. Install the
configuration it prints on **every** control-plane machine, as in
[Get started](get-started.md#once-a-year-renew-the-internal-certificate). If the install fails
halfway, run the command again **without** `--renew-certificate`: it prints the configuration
for the certificate it just made. Forcing renewal again only makes things worse.

Don't work around a lost certificate by trusting plain HTTP or skipping certificate checks. If
you lose the **public** certificate, get a new one for the same host name.

## Back up and restore a single-server k3s

This covers one k3s server using its default SQLite datastore, restored on the same machine.
For embedded etcd, an external database, a different Kubernetes version or a new machine, follow
the [k3s backup and restore guide](https://docs.k3s.io/datastore/backup-restore) or
[etcd snapshots](https://docs.k3s.io/cli/etcd-snapshot) instead.

Stop k3s while you copy, so the database files are consistent. Pause other writers and stop
Genkan first, as in [Take a backup](#take-a-backup).

```sh
SNAPSHOT=/var/backups/genkan-k3s/$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$SNAPSHOT"
sudo systemctl stop k3s
sudo tar -C /var/lib/rancher/k3s/server -czf "$SNAPSHOT/db-and-token.tar.gz" db token
sudo chmod 0600 "$SNAPSHOT/db-and-token.tar.gz"
sudo systemctl start k3s
```

The `token` file is needed to decrypt the database; a database without its token may be
useless. Also save `/etc/rancher/k3s`. Then encrypt the archive and copy it off the machine: a
backup on the machine you are trying to recover isn't much of a backup.

Restoring rewinds **the whole cluster**, not just Genkan, so coordinate with everyone who runs
workloads on it. Keep the broken state for later investigation instead of deleting it:

```sh
RECOVERY_ARCHIVE=/path/to/db-and-token.tar.gz   # the decrypted archive
FAILED_STATE=/var/backups/genkan-k3s/failed-$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$FAILED_STATE"
sudo systemctl stop k3s
sudo mv /var/lib/rancher/k3s/server/db "$FAILED_STATE/db"
sudo cp -a /var/lib/rancher/k3s/server/token "$FAILED_STATE/token"
sudo tar -C /var/lib/rancher/k3s/server -xzf "$RECOVERY_ARCHIVE"
sudo systemctl start k3s
sudo k3s kubectl get --raw=/readyz
```

Don't mix a database from one backup with a token from another. If you changed the
authentication file since the backup, put back the matching version before starting k3s.

If you took the snapshot with Genkan stopped, as above, it comes back stopped. If not, it
starts with k3s: block the issuer's public address before starting k3s, and scale Genkan to zero
as soon as `/readyz` answers. Before scaling it up again, do steps 3 to 5 of
[Restore, keeping everyone's identity](#restore-keeping-everyones-identity). A datastore restore
also brings back sessions you had revoked; deleting the grants is what stops them.

## kube-apiserver won't start

First make sure this is really the problem. If Genkan is down but kube-apiserver answers, fix
Genkan with the admin kubeconfig; you don't need to remove anything. Undo the authentication
change on the machine only when kube-apiserver can't start, or when you mean to stop trusting
Genkan.

**Several control-plane machines?** Fix one at a time and check it before moving on. Leave
healthy machines alone. If all of them are down and they run embedded etcd, the first one can't
become ready until enough of them are back, so fix the configuration on each in turn without
waiting. Don't use `cluster-reset` to get around an authentication error.

Check each machine directly, at its own address, with the admin kubeconfig. A request through a
load balancer may land on a machine you haven't touched. Don't use
`--insecure-skip-tls-verify`.

### k3s

Genkan's setup adds:

- the authentication file `/etc/rancher/k3s/genkan/authn.yaml`;
- the drop-in `/etc/rancher/k3s/config.yaml.d/50-genkan.yaml`, which points kube-apiserver at it.

k3s reads drop-ins in alphabetical order, and a later file **replaces** an earlier list unless
the key ends in `+`. So `50-genkan.yaml` may have hidden `kube-apiserver-arg` values from
earlier files. Before removing it, check what will come back.

If `50-genkan.yaml` exists only for Genkan, and nothing else sets `--authentication-config`, move
it out of the way:

```sh
RECOVERY=/var/backups/genkan-emergency/$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$RECOVERY"
if sudo test -f /etc/rancher/k3s/genkan/authn.yaml; then
  sudo cp -a /etc/rancher/k3s/genkan/authn.yaml "$RECOVERY/authn.failed.yaml"
fi
sudo mv /etc/rancher/k3s/config.yaml.d/50-genkan.yaml "$RECOVERY/50-genkan.failed.yaml"
sudo systemctl restart k3s
sudo journalctl -u k3s --since '5 minutes ago' --no-pager
sudo k3s kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get --raw=/readyz
```

If the drop-in already existed before Genkan, restore its earlier contents instead. If you put
the flag in `config.yaml`, another drop-in or the systemd unit, undo it there and keep the rest
of the arguments.

Leave `authn.yaml` where it is. Without the flag, k3s ignores it, and you may want to compare it
with the broken version.

Next time, merge Genkan's arguments into your existing list rather than replacing it.

### k0s

Genkan's setup adds:

- the authentication file `/etc/k0s/genkan/authn.yaml`;
- the key `spec.api.extraArgs.authentication-config` in the controller configuration, usually
  `/etc/k0s/k0s.yaml`. Check the `k0scontroller` service for the file it actually uses.

Save a copy, then edit the active file:

```sh
K0S_CONFIG=/etc/k0s/k0s.yaml   # the file the service actually uses
RECOVERY=/var/backups/genkan-emergency/$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$RECOVERY"
sudo cp -a "$K0S_CONFIG" "$RECOVERY/k0s.failed.yaml"
sudoedit "$K0S_CONFIG"
```

Remove `spec.api.extraArgs.authentication-config` if Genkan added it; otherwise put back its
previous value. Restore any `oidc-*` entries you removed when installing. Also check
`spec.api.rawArgs`, which can carry authentication flags too. Leave everything else as it was.

```sh
sudo systemctl restart k0scontroller
sudo journalctl -u k0scontroller --since '5 minutes ago' --no-pager
sudo k0s kubectl --kubeconfig=/var/lib/k0s/pki/admin.conf get --raw=/readyz
```

`k0s kubectl` is the `kubectl` built into k0s, so it works even where `kubectl` isn't
installed. `/var/lib/k0s/pki/admin.conf` is the controller's own admin kubeconfig; adjust the
path if you use a different data directory. Controller-only machines don't show up in
`kubectl get nodes`, so use `/readyz` to check them.

`spec.api` isn't part of k0s's dynamic configuration, so `k0s config edit` won't help here. If
you manage the cluster with k0sctl or another tool, update its configuration too, or the next run
puts the broken setting back.

### kubeadm and kind

Genkan's setup adds:

- the directory `/etc/kubernetes/genkan`, with `authn.yaml` inside, mounted into kube-apiserver;
- an `--authentication-config` argument and a `genkan` volume in
  `/etc/kubernetes/manifests/kube-apiserver.yaml`;
- matching entries in the `kubeadm-config` ConfigMap.

The kubelet watches the manifest file and restarts kube-apiserver when it changes, even with the
API down. So fix the file on the machine first.

> [!WARNING]
> The kubelet runs **every** file in `/etc/kubernetes/manifests`, whatever its name. Never leave
> a `.bak`, an editor swap file or any other copy there. Keep copies elsewhere, and only use a
> manifest from the same machine.

If you have the manifest from before Genkan, and the Kubernetes version hasn't changed since,
put it back. Set `NODE_API` to this machine's own API address, not the load balancer's, so the
last check talks to the kube-apiserver you just fixed:

```sh
BEFORE=/var/backups/genkan-control-plane/20260101T000000Z   # saved before installing Genkan
NODE_API=https://10.0.0.11:6443                              # this machine's own address
RECOVERY=/var/backups/genkan-emergency/$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$RECOVERY"
sudo cp -a /etc/kubernetes/manifests/kube-apiserver.yaml "$RECOVERY/kube-apiserver.failed.yaml"
sudo cp -a "$BEFORE/kubernetes/manifests/kube-apiserver.yaml" \
  "$RECOVERY/kube-apiserver.recovered.yaml"
sudo mv "$RECOVERY/kube-apiserver.recovered.yaml" /etc/kubernetes/manifests/kube-apiserver.yaml
sudo journalctl -u kubelet --since '5 minutes ago' --no-pager
sudo crictl ps -a --name kube-apiserver
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf --server="$NODE_API" get --raw=/readyz
```

The `mv` replaces the file in one step only if both paths are on the same filesystem; if
your backup directory isn't, copy the file next to `/etc/kubernetes` first. While the API is
down, read kube-apiserver's logs with `sudo crictl logs <container-id>`. On kind, run all of this
inside the control-plane container.

If the old manifest is out of date, copy the current one somewhere outside `manifests`, and in
the copy:

1. remove the `--authentication-config` argument, or restore its previous value;
2. remove the `genkan` volume and volume mount, if nothing else uses them;
3. put back any OIDC or anonymous flags you removed, and leave everything else alone;

then move it into place as above.

Once kube-apiserver is healthy, update `kubeadm-config` so a later `kubeadm upgrade` doesn't
bring the change back:

```sh
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system edit configmap kubeadm-config
```

Under `data.ClusterConfiguration.apiServer`, remove the `authentication-config` entry from
`extraArgs` and the `genkan` entry from `extraVolumes`, and restore any earlier OIDC or anonymous
settings. Edit only those entries; don't replace the whole ConfigMap with an old copy. This
doesn't change the other machines: fix each one's manifest the same way.

### Other distributions

`--distro generic` only writes an authentication file. Before you use it, write down how your
cluster starts kube-apiserver and how to undo the change without the API. On managed Kubernetes,
use your provider's supported way to configure authentication, if there is one.

KubeSolo isn't supported: it doesn't let you pass an authentication configuration to
kube-apiserver. Don't work around this with another `--distro` value.

### Check the result

On **each** machine you fixed, use the admin kubeconfig to check `/readyz`, the nodes and the
authentication settings. If you meant to stop trusting Genkan, confirm that a Genkan token no
longer works. Use a kubeconfig that has only the token: the admin kubeconfig's certificate signs
you in on its own, which hides the result. Check that anonymous access and health checks behave
as before.

Leave Genkan's namespace, objects and Secrets in place. Deleting them doesn't undo the
authentication change; it just loses data.

## Upgrade and roll back

### What Genkan does and doesn't promise yet

Genkan's resources are still `v1alpha1`, with no conversion between versions. Until a release
says otherwise, assume nothing about moving between versions in either direction. Record the
exact commit and image you run, not a reusable tag such as `genkan:dev`.

`kubectl rollout undo` only rolls back the pod template. It doesn't roll back CRDs, users,
signing keys, Secrets, RBAC, Services, ingress or kube-apiserver's files. If a newer Genkan
already wrote data, an older one may not be able to read it.

Genkan runs one replica and is replaced, not rolled. Plan for a short outage: anyone signing in
at that moment has to start again. Don't add replicas to hide it.

### Before you upgrade

1. **Check your emergency access works** and take a full backup, as described above. Write down
   when you took it: that's how much you could lose.
2. **Write down what's running now:** the source commit, the `genkanctl` version, and every
   option you installed with (issuer, namespace, image, every `--serve-arg` and
   `--config-secret`, and any overlays). Keep the old image available on every node.
3. **Get the new image.** Use a digest, or a tag you never reuse that points to a known commit.
   Load it on every node that can run Genkan.
4. **Generate the new manifests into files** with the new `genkanctl` and the same options.
   Compare them with what's running. Don't pipe new defaults straight into the cluster.
5. **Read what changed** between the two versions: CRD schemas, stored formats, options, token
   claims. Try the exact upgrade on a restored copy first, including a sign-in with an existing
   passkey.
6. **Decide how you would go back.** If you don't know whether the old version can read the new
   data, your way back is restoring the backup from step 1, with its data loss. If the data
   needs a migration and none exists, don't upgrade.

It helps to save what's running now (keep these private):

```sh
umask 077
NS=genkan-system
mkdir -m 0700 upgrade-record
kubectl -n "$NS" get deployment genkan -o yaml > upgrade-record/deployment.before.yaml
kubectl -n "$NS" get pods -l app.kubernetes.io/name=genkan \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.name}{"\t"}{.image}{"\t"}{.imageID}{"\n"}{end}{end}' \
  > upgrade-record/image-identities.before.txt
kubectl -n "$NS" rollout history deployment/genkan > upgrade-record/rollout-history.before.txt
```

This is a record, not a backup.

### Upgrade

Fill in the first four lines with your own values. The `manifests` command matches Get started,
which turns on invitations; add every option you installed with and leave out
`--serve-arg=--invitations` if you didn't use it.

```sh
NS=genkan-system
NEXT_GENKANCTL=/path/to/new/genkanctl
NEXT_IMAGE=registry.example.test/genkan@sha256:...   # the new image, by digest
GENKAN_ISSUER=https://genkan.example.test
"$NEXT_GENKANCTL" crds > upgrade-record/crds.next.json
"$NEXT_GENKANCTL" manifests --issuer "$GENKAN_ISSUER" --namespace "$NS" --image "$NEXT_IMAGE" \
  --serve-arg=--invitations > upgrade-record/manifests.next.json
# Leave out the empty signing-key Secret: it's only for new installs.
jq '.items |= map(select(.kind != "Secret"))' upgrade-record/manifests.next.json \
  > upgrade-record/manifests.upgrade.json
```

Read both files before applying them. If apply reports a conflict, find out why instead of adding
`--force-conflicts`. Never delete and recreate a CRD to get past an error: that deletes every
object of that kind.

```sh
kubectl apply --server-side -f upgrade-record/crds.next.json
kubectl apply --server-side -f upgrade-record/manifests.upgrade.json
kubectl -n "$NS" rollout status deployment/genkan --timeout=5m
kubectl -n "$NS" logs deployment/genkan --tail=200
```

Keep the `genkan` Service, `genkan-internal-tls` and `genkan-signing-keys` as they are. A new
Service may get a new IP, and every kube-apiserver has the old one pinned in its authentication
file. Don't renew the certificate, change the issuer or delete sessions as part of an upgrade. If
the new version really needs a different kube-apiserver configuration, treat that as its own
change, one machine at a time. Note that `genkanctl kube-config` may replace the internal
certificate as it runs.

Afterwards, check the running image, readiness and logs. Then sign in fresh with an existing
passkey, try something you're allowed to do and something you aren't, and try admin access. A
ready pod doesn't prove that sign-ins work.

### Roll back

If you aren't sure what the new version wrote, stop it first so it can't write more:

```sh
kubectl -n genkan-system scale deployment/genkan --replicas=0
```

Then choose one:

- **Go back to the old image**, if you know the old version can read the current data. For an
  image-only change:
  `kubectl -n genkan-system set image deployment/genkan genkan="$PREVIOUS_IMAGE"`. For other
  pod-template changes, look at `kubectl rollout history deployment/genkan --revision=N` before
  `kubectl rollout undo deployment/genkan --to-revision=N`. Put back anything else you changed
  yourself, then restore the replica count.
- **Restore the pre-upgrade backup** with the old image, manifests, CRDs and Secrets, using one of
  the restore procedures above. Keep Genkan stopped while you do. You lose everything since the
  backup: new passkeys, group changes, client updates and key rotations. Revoked sessions and
  used invitations can come back, so delete them before reopening.

Never install an empty signing-key Secret, delete credentials, or hand out new setup links just to
get an old version to start.

Afterwards, check the image, readiness and logs, sign in fresh, and check normal and admin access
and your emergency access. Write down what you restored and what was lost.

## Practise before you need it

A recovery plan you've never tried is a guess. Practise on a disposable cluster, such as a VM you
can reset to a snapshot between runs, with test users only. Start each scenario from a clean
install with a freshly enrolled passkey, and finish each one by signing in fresh and checking
normal and admin access.

These are worth trying, along with what you should see:

| Scenario | What to do | What you should see |
|---|---|---|
| Genkan is down | Scale Genkan to zero, use the admin kubeconfig, then scale it back | The admin kubeconfig works throughout. Passkey sign-in works again afterwards. |
| The ingress is down | Stop the ingress controller, use the admin kubeconfig, then start it again | Genkan's public URL fails during the outage; the admin kubeconfig doesn't. Everything works afterwards. |
| kube-apiserver won't start | Install a broken authentication file, then undo it on the machine | The admin kubeconfig works once you've undone it, and Genkan tokens are refused while Genkan is removed. |
| Datastore restore | Back up, delete a user, then restore | Same UID, the old passkey still works. Sessions revoked after the backup come back until you delete the grants. Tokens already issued keep working until they expire. |
| Recreate from an export | Delete a user and recreate it from the export | New UID. The old passkey fails, even with a corrected `Credential`. The user can enrol again. |
| Lost signing keys | Delete the signing-key Secret and recreate it empty | Old tokens and sessions are refused. Users and passkeys still work. |
| Lost internal certificate | Delete `genkan-internal-tls` and run `genkanctl kube-config` | A new certificate and CA. Sign-ins work once kube-apiserver has the new configuration. |
| Failed upgrade | Deploy an image that doesn't exist, then go back | Users, passkeys and sessions are unchanged. |

Things a disposable cluster can't tell you, so try them on your own setup:

- your real authenticators and browsers;
- your public certificate and ingress;
- where you keep the encrypted backups and their passphrase, and whether you can reach them
  when the cluster is gone;
- the apps that sign in through Genkan;
- multi-machine control planes and their datastores;
- the exact upgrade you're about to do.

## Further reading

How Genkan does it:
[passkeys bound to the user UID](../crates/genkan-signin/src/lib.rs),
[users](../crates/genkan-k8s/src/users.rs),
[sessions](../crates/genkan-k8s/src/grants.rs),
[signing keys](../crates/genkan-k8s/src/keys.rs),
[the internal certificate](../crates/genkan-k8s/src/internal_tls.rs) and
[kube-apiserver configuration per distribution](../crates/genkan-k8s/src/kube_config.rs).

Platform documentation:

- k3s: [configuration](https://docs.k3s.io/installation/configuration),
  [cluster access](https://docs.k3s.io/cluster-access) and
  [backup and restore](https://docs.k3s.io/datastore/backup-restore).
- k0s: [configuration](https://docs.k0sproject.io/stable/configuration/) and
  [dynamic configuration](https://docs.k0sproject.io/stable/dynamic-configuration/).
- Kubernetes: [authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/),
  [reconfiguring kubeadm](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-reconfigure/),
  [static pods](https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/) and
  [rolling back a Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#rolling-back-a-deployment).

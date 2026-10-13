<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/cover-dark.avif">
  <img alt="Genkan: cross out admin.conf, log in to Kubernetes with a passkey" src="docs/images/cover-light.avif">
</picture>

# Genkan

**Delete `admin.conf`. Log in to your cluster with a passkey.**

Most self-managed clusters are run with one admin kubeconfig that never expires, gets copied to
every laptop, and cannot be revoked. Genkan (玄関, the entrance of a Japanese house) replaces it
with a passkey: `kubectl` opens your browser, you touch your fingerprint reader, and you get a
token that lasts minutes, not years.

> **Status: alpha.** Not released yet; expect breaking changes.

https://github.com/user-attachments/assets/4c6e29f2-341c-4622-8cc5-4337e13e53b5

*Signing in to [Aptakube](https://aptakube.com) with a passkey: the cluster opens for browsing,
and restarting a deployment is refused with 403 until you ask for admin rights.*

## Why Genkan

- **Passkeys, not passwords.** Touch ID, Windows Hello or a security key. Teammates can also
  link a GitHub or Google account for everyday access.
- **Admin rights only when you ask, for five minutes.** By default your everyday token can look
  but not touch. Changing the cluster needs a fresh passkey tap and a token that expires on its own.
- **No forever key on anyone's laptop.** Tokens last minutes and Kubernetes checks them itself;
  admin tokens cannot be renewed at all. Revoke a person's sessions and their access ends when
  the token in hand expires, within ten minutes.
- **Runs inside the cluster it protects.** One small pod (about 20 MB), no database, no extra
  servers. Works with k3s, k0s and kubeadm, and with any OpenID Connect app such as Argo CD or
  Grafana.

## What it looks like

<table>
  <tr>
    <td width="33%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/sign-in-dark.avif">
      <img alt="Sign-in page with a passkey button and Continue with GitHub" src="docs/images/sign-in-light.avif">
    </picture></td>
    <td width="33%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/sign-in-elevated-dark.avif">
      <img alt="Sign-in page for admin access, with the passkey button only" src="docs/images/sign-in-elevated-light.avif">
    </picture></td>
    <td width="33%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/setup-dark.avif">
      <img alt="Setup page for creating a passkey from a one-time link" src="docs/images/setup-light.avif">
    </picture></td>
  </tr>
  <tr>
    <td align="center"><b>Everyday sign-in</b><br>passkey or GitHub</td>
    <td align="center"><b>Admin access</b><br>passkey only, 5 minutes</td>
    <td align="center"><b>Joining</b><br>a one-time invitation link</td>
  </tr>
</table>

## How it works

1. You run `kubectl get pods`. Your browser opens Genkan's sign-in page.
2. You sign in with your passkey. `kubectl` receives a token valid for ten minutes and renews it
   quietly while you work.
3. Kubernetes checks the token itself. Genkan never sits in the path of your requests.

Need to change something? Use your admin context: one more passkey tap, five minutes of admin
rights, then back to read-only.

## Get started

The [step-by-step guide](docs/get-started.md) builds a k3s cluster in a VM, installs Genkan and
signs `kubectl` in with a passkey from your Mac, in about half an hour.

On a cluster you already run, the shape of it is below. Every `genkanctl` subcommand that needs
an issuer reads `GENKAN_ISSUER`, so these examples do not repeat `--issuer`.

```sh
export GENKAN_ISSUER=https://login.example.com
genkanctl crds | kubectl apply --server-side -f -
genkanctl manifests --image <image> --serve-arg=--invitations | kubectl apply -f -
# Prints kube-apiserver's configuration and how to install it for your distribution:
genkanctl kube-config --distro k3s > authn.yaml
# A one-time link: open it and create your passkey.
genkanctl setup-link --username admin
```

There is no published image yet; the guide shows how to build one.

Then:

- Sign in with [GitHub](docs/github-sign-in.md) or [Google](docs/google-sign-in.md).
- [Register clients](docs/clients.md) such as Grafana or Argo CD, with
  `genkanctl client create`.
- [Manage users](docs/managing-users.md): groups, admin rights, lost passkeys, removing people;
  [provision them from a directory](docs/provisioning-users.md) with a small sync script.
- `genkanctl invite --username alice` to send someone a one-time link. It needs the server
  started with `--invitations`, as above; without it the link cannot be redeemed.

## Learn more

- [Architecture](docs/architecture.md): how the pieces fit, security properties, the crates.
- [Conformance](docs/conformance.md): every specification requirement, mapped to code and tests.
- [Contributing](CONTRIBUTING.md): development setup, the checks CI runs, dependency policy.

## Licence and credits

Apache-2.0. Contributions are accepted under the [Developer Certificate of Origin](DCO).

The sign-in pages copy component class strings from [shadcn/ui](https://ui.shadcn.com) (MIT,
notice in `ui/styles/shadcn.css`) and ship the [Geist](https://github.com/vercel/geist-font) font (SIL Open
Font License 1.1, `crates/genkan-ui/assets/LICENSE-Geist.txt`). The container image includes
Mozilla's CA certificate bundle as packaged by nixpkgs (MPL-2.0).

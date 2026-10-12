# Contributing

## Developer Certificate of Origin

This project uses the [Developer Certificate of Origin 1.1](DCO), not a CLA. Sign off every
commit to certify that you wrote it or otherwise have the right to submit it under the project
licence:

```sh
git commit -s
```

CI rejects pull requests whose commits lack a `Signed-off-by` line matching the author. Commit
messages follow [Conventional Commits](https://www.conventionalcommits.org/).

## Before you open a pull request

Run what CI runs, inside `nix develop`:

```sh
cargo fmt --all --check && nixfmt --check flake.nix && shellcheck scripts/*.sh && actionlint
cargo lint                                   # clippy, all targets and features, -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
cargo nextest run --workspace
cargo deny --locked check
./scripts/unsafe-report.sh
./scripts/build-ui.sh && git diff --exit-code -- crates/genkan-ui/assets && tsc -p ui && ./scripts/ui-budget.sh
```

Design rationale lives next to the code, in rustdoc: state the decision and its reason, and
cite the specification section, paper or prior art it rests on (the crates show the style).
Never cite something you have not read; write "not verified" instead. Code that implements a
MUST or SHOULD of a specification updates [docs/conformance.md](docs/conformance.md).
Documentation is written in English.

## Toolchain

`rust-toolchain.toml` is the only place the compiler version is set; rustup reads it directly
and the Nix flake reads it through fenix `fromToolchainFile`, so both paths build with the same
compiler. The toolchain is a pinned nightly for the parallel front end (`-Zthreads`), current
clippy lints and rustfmt's import ordering. No `#![feature]` is used, so moving to stable is a
configuration change: drop `-Zthreads` from `.cargo/config.toml` and the nightly-only options
from `rustfmt.toml`. A toolchain bump updates the `sha256` in `flake.nix` in the same change;
`scripts/bump-toolchain.sh` does both, moving to the newest nightly of the last week that has every
listed component and target. `.github/workflows/update-toolchain.yml` runs it with
`nix flake update` on the 1st and 15th of each month and opens one pull request.

Release binaries are built with `trim-paths = "all"`, so they carry no build-host paths.

## Lints and formatting

Lints are set once for the workspace in `Cargo.toml`. All are `warn`, so unfinished work still
compiles locally, and `cargo lint` turns every warning into an error in CI.

- `unsafe_code` and `non_ascii_idents` are forbidden.
- clippy `pedantic`, `cargo` and `nursery` are on.
- A selection of `restriction` lints targets what matters in an internet-facing authentication
  server: no panics on input (`unwrap_used`, `expect_used`, `indexing_slicing`, …; tests may
  unwrap), exhaustive matches in security logic (`wildcard_enum_match_arm`), no silently dropped
  errors (`map_err_ignore`, `let_underscore_must_use`, …), and no unexplained suppressions:
  use `#[expect(lint, reason = "…")]`, which also fails once it is no longer needed.
- Only the binaries' `output` modules write to stdout or stderr; everything else logs through
  `tracing`.

`rustfmt.toml` groups and orders imports, wraps comments at 100 columns and fails on code it
cannot format.

## Dependencies

`cargo deny check` enforces the policy in `deny.toml`:

- Licences must be OSI-approved ([SPDX list](https://spdx.org/licenses/),
  [OSI](https://opensource.org/licenses)); crates come from crates.io only; no `*` versions.
- TLS uses rustls with [aws-lc-rs](https://aws.github.io/aws-lc-rs/) as the only cryptographic
  backend. `ring`, OpenSSL, `native-tls`, the FIPS build of aws-lc and `webpki-roots` (whose
  CDLA licence is not OSI-approved; the image ships a CA bundle instead) are banned.
- [RustSec](https://rustsec.org/) advisories and yanked versions fail the check. Every ignored
  advisory carries its reason in `deny.toml`.

Cargo does not pick a release younger than seven days unless it is already in the lock file
(`registry.global-min-publish-age` in `.cargo/config.toml`), which gives the community time to
catch a compromised release. An urgent security update overrides it for one command:
`CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE="0 days" cargo update -p <crate>`.

[Renovate](https://docs.renovatebot.com/) (`renovate.json`) opens the weekly crate, action digest
and k3s updates under the same seven-day delay; compatible crate updates share one pull request.
A crate update that brings in new `unsafe` or native code fails `unsafe-report` until the
allowlist entry below is added and reviewed, so those pull requests are never merged unread.

A dependency that reaches the shipped binaries and contains `unsafe` code or builds native code
needs an entry in `supply-chain/unsafe-allowlist.toml` with a reason and the date a maintainer
approved it. `scripts/unsafe-report.sh` scans the shipped dependency graph (normal and build
dependencies of `genkan` and `genkanctl` for the image target), lists every such crate and fails
on one that is not approved; an entry marked `pending` is a proposal awaiting review. The count
is a review signal, not an audit.

## Tests

- **Unit and integration tests** run anywhere: `cargo nextest run --workspace`.
- **Cluster tests** (`#[ignore]`d) need a disposable cluster in `KUBECONFIG` where you are
  cluster admin. Docker on a Linux machine or VM with k3d is enough:

  ```sh
  mkdir -p /tmp/authn && printf 'apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\nanonymous:\n  enabled: false\njwt: []\n' > /tmp/authn/authn.yaml
  k3d cluster create genkan --image rancher/k3s:v1.36.5-k3s1 --no-lb --wait \
    --volume "/tmp/authn:/etc/rancher/k3s/genkan@server:0" \
    --k3s-arg "--kube-apiserver-arg=authentication-config=/etc/rancher/k3s/genkan/authn.yaml@server:0"
  cargo nextest run --run-ignored only -E 'binary(kubernetes)'
  ```

- **End to end**: build the image (`scripts/build-image.sh genkan:e2e`, Linux), load it
  (`k3d image import genkan:e2e -c genkan`) and run
  `GENKAN_E2E_IMAGE=genkan:e2e GENKAN_E2E_AUTHN_DIR=/tmp/authn cargo nextest run --run-ignored only -E 'binary(e2e)'`.
  It installs Genkan from its image, enrols a passkey with a software authenticator, signs in,
  and checks `kubectl auth whoami`, elevation and the pod's memory.

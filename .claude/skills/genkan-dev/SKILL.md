---
name: genkan-dev
description: Day-to-day development loop for the Genkan repository — environment, the checks CI runs, lint conventions, commits. Use before changing any Rust, TypeScript, Nix or CI file in this repo.
---

# Genkan development loop

## Environment
- Everything runs inside the Nix dev shell: prefix commands with `nix develop -c …` (or enter
  `nix develop`). Do not use system-installed toolchains; `rust-toolchain.toml` pins the
  compiler and the flake reads it.
- The workspace is a flat `crates/` directory; dependencies only point downwards (see the crate
  table in `README.md`). Put new code in the lowest crate that can hold it; never add an upward
  dependency. Binaries: `genkan` (in-cluster server) and `genkanctl` (admin CLI).
- Workspace dependency versions live in the root `Cargo.toml` `[workspace.dependencies]`;
  crates use `name.workspace = true`.

## Checks (what CI runs)
```sh
nix develop -c cargo fmt --all --check   # drop --check to apply the formatting
nix develop -c cargo lint          # clippy --workspace --all-targets --all-features --locked -D warnings
RUSTDOCFLAGS="-D warnings" nix develop -c cargo doc --workspace --no-deps --document-private-items --locked
nix develop -c cargo nextest run --workspace --all-features --locked --no-tests=warn
nix develop -c cargo deny --locked check
nix develop -c ./scripts/unsafe-report.sh
nix develop -c bash -c 'shellcheck scripts/*.sh && actionlint && nixfmt --check flake.nix'
```
Iterate per crate with `-p <crate>` to keep builds short. Cluster tests: see the
`genkan-cluster-tests` skill. UI changes: see `genkan-ui`.

## Lint conventions
- `unsafe` is forbidden. No panics on input: no `unwrap`/`expect`/indexing outside tests.
- Suppress a lint only with `#[expect(lint, reason = "…")]`; never `#[allow]`.
- Matches in security logic are exhaustive (no wildcard arms on enums).
- Output to stdout/stderr only through a binary's `output` module; everything else uses
  `tracing`.
- Docs: identifiers in backticks (clippy `doc_markdown`); add proper nouns to `clippy.toml`
  `doc-valid-idents` instead of backticking them.
- `rustfmt` reflows code; when editing with scripts, match on short, stable anchors.

## Documentation
- Rationale goes in rustdoc next to the code: state the decision and why, cite the
  specification section, paper or prior art (see `genkan-spec-work`). Each crate's README is its
  crate-level doc (`#![doc = include_str!("../README.md")]`).
- Implementing a MUST/SHOULD updates `docs/conformance.md`.

## Commits
- Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `chore(scope):`, `!` for breaking
  changes with a `BREAKING CHANGE:` footer).
- Sign off every commit (`git commit -s`, DCO). Do not add tool- or session-specific trailers.
- Regenerate committed outputs in the same commit: `cargo run -q -p genkanctl -- crds >
  deploy/crds.json`, `… -- rbac > deploy/rbac.json` (tests fail when they are stale), and the UI
  assets.

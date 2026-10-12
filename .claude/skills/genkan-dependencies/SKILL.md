---
name: genkan-dependencies
description: Add or upgrade a Rust or frontend dependency in Genkan under its supply-chain policy (OSI licences, aws-lc-rs only, publish-age delay, unsafe/native review). Use whenever Cargo.toml, Cargo.lock, flake.nix or the UI toolchain changes.
---

# Dependencies

- **Prefer what is already in the graph.** `cargo tree -i <crate> -e normal` shows whether a
  crate is already compiled in (for example hyper, rustls, url). A small, reviewed in-tree
  implementation can beat a new dependency with `unsafe` code; weigh it explicitly.
- **Add at the workspace level**: version and features in the root
  `[workspace.dependencies]`, `name.workspace = true` in the crate. Disable default features you
  do not need; check that no second crypto backend arrives (`ring`, OpenSSL and `webpki-roots`
  are banned in `deny.toml`).
- **Publish age.** Cargo refuses versions younger than seven days. For an urgent security fix:
  `CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE="0 days" cargo update -p <crate>`.
- **Run** `cargo deny --locked check` and `./scripts/unsafe-report.sh`. Every shipped crate that
  contains `unsafe` or builds native code needs an entry in `supply-chain/unsafe-allowlist.toml`:
  `kind`, a concrete `reason` (where the unsafe is, whether it runs only at build time), and
  `approved = "pending"` until a maintainer reviews it and sets the date. Only normal and build
  dependencies of `genkan` and `genkanctl` count; dev-dependencies and test crates do not.
- **Advisories** that do not apply need an `ignore` entry in `deny.toml` with the reason.
- **Frontend tooling** comes from nixpkgs through `flake.nix` (Tailwind CSS v4, bun, TypeScript);
  there is no `package.json` and no npm install. Pin by updating `flake.lock`.

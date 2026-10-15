# Releases

Releases are alpha software. `.github/workflows/release.yml` runs on `vMAJOR.MINOR.PATCH`
tag pushes. A manual dispatch is a **non-publishing rehearsal** of CI, both native builds and
candidate execution. It does not create a tag, GitHub release, registry package or signature.

## Supported platforms

| Artifact | OS | Architecture | Build target |
|---|---|---|---|
| `genkanctl-v<VERSION>-linux-amd64.tar.gz` | Linux | amd64 / x86_64 | `x86_64-unknown-linux-musl` |
| `genkanctl-v<VERSION>-linux-arm64.tar.gz` | Linux | arm64 / aarch64 | `aarch64-unknown-linux-musl` |
| `ghcr.io/engawahq/genkan:v<VERSION>` | Linux | amd64 and arm64 | Native musl builds, multi-platform index |

The CLI and server are statically linked. Release builds reject dynamic interpreters and shared
library dependencies. macOS, Windows and other architectures have **no downloadable release
artifacts**; build the CLI from source there. The container is Linux-only, runs non-root and
contains no shell. It includes the pinned Mozilla CA bundle for outbound TLS. Internal workspace
crates are not published to crates.io.

## Maintainer procedure

1. Merge the desired release commit to `main`, including the workspace version in `Cargo.toml`
   and corresponding `Cargo.lock` changes. For the first release, change `0.0.0` to `0.0.1`.
   The tag must exactly match that version. Only stable three-part tags are accepted; releases
   are marked prerelease while Genkan is alpha.
2. Optionally dispatch **Release** on that commit with its matching version (for example
   `v0.0.1`). This runs the full CI suite and both native candidate smoke jobs without publishing.
3. Configure the GHCR package `engawahq/genkan` as **public** in GitHub package settings and
   allow this repository's Actions token to write it. If the package does not exist yet, the
   first publishing run creates it; set its visibility before its consumer rehearsal, or
   follow the failed-draft recovery procedure below. New GHCR packages may default to private:
   anonymous verification must fail until visibility is public. No PAT or long-lived key is used.
4. Protect release tags with a repository ruleset restricting creation, update and deletion to
   release maintainers. Protect `main` and review workflow changes. The workflow independently
   rejects tagged commits outside `main` and reruns every CI check on the tagged commit; it does
   not trust a green check from another commit or a mutable branch build.
5. Create and push the matching tag, for example `git tag v0.0.1 <commit>` followed by
   `git push origin v0.0.1`. This is the publication operation; a dispatch cannot publish.
6. Inspect the complete Release run. It publishes a draft first; only successful native
   download/verification/startup rehearsals on **both** platforms make the release public.

The build and smoke jobs have read-only repository permissions. Only the publication job has
`packages: write`, `contents: write` and `id-token: write`; the finalization job has only
`contents: write`. Checkout never persists credentials. Sigstore uses GitHub OIDC, Fulcio and
Rekor, not a stored private key. Registry verification deliberately uses an empty Docker
credential configuration, so private packages cannot accidentally pass as public releases.

The pipeline stages are:

- Full reusable CI, including UI, supply-chain checks and Kubernetes end-to-end tests.
- Native amd64/arm64 builds using `rust-toolchain.toml`, `flake.lock`, `Cargo.lock` and
  `cargo auditable build --release --locked`. Source commit time is `SOURCE_DATE_EPOCH`;
  archive member order, ownership, modes and timestamps are normalized and gzip omits time.
  Pinned inputs make builds repeatable; this is **not a claim of independently verified
  bit-for-bit reproducibility** of Rust executables, Docker metadata or SBOM documents.
- Smoke the exact archived CLI and image candidate. No release binary is rebuilt after smoke.
- Copy saved images to GHCR, record platform and index digests, sign the digests, and attach
  CycloneDX SBOM attestations. Build the index from those platform digests, not from tags.
- Sign `SHA256SUMS` with a Sigstore bundle. It covers both CLI archives, all downloadable SBOMs,
  image digests and `provenance.json` (source commit, repository and workflow run). This is
  signed build metadata, **not a SLSA level claim**. Stage all assets in a draft release.
- Fresh native runners download those draft assets, verify signatures and all checksums,
  anonymously pull the signed index by digest and execute the downloaded CLI and image.
  The smoke creates a disposable k3s cluster, installs the CLI-generated resources, starts the
  exact image and checks its discovery/JWKS endpoints. Only then publish the GitHub prerelease.

Versioned image tags become available during draft staging; a failed rehearsal leaves the
GitHub release in draft, not a successful release. Do not consume a staged tag until the full
release run succeeds. Always prefer the immutable digest recorded in the release.

On failure, inspect the draft, candidate tags and Actions logs before recovery. Publication
refuses to overwrite an existing draft or release. Repair package visibility or infrastructure
as needed; remove only that failed draft before deliberately rerunning publication. A rerun
can leave obsolete `candidate-<run>-<attempt>-<arch>` tags; they are not supported release tags.
Do not move a published version tag to different source or bytes.

## Verify a download

Use `cosign` 3.x, GNU `sha256sum`, `jq`, Docker and the tools in this repository's pinned
`nix develop` shell. Substitute the desired published version and your architecture:

```sh
version=v0.0.1
arch=arm64 # or amd64
identity="https://github.com/engawahq/genkan/.github/workflows/release.yml@refs/tags/$version"
gh release download "$version" --repo engawahq/genkan --dir downloaded
cd downloaded
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --check --strict SHA256SUMS
# Extract only after both verification commands succeed.
tar -xzf "genkanctl-$version-linux-$arch.tar.gz"
./genkanctl --help
```

Keep the exact certificate identity check. A signature from some other repository or workflow
is not sufficient. The signed checksum manifest authenticates the CLI archives, their CycloneDX
SBOMs and provenance metadata; downloading a checksum alone does not authenticate anything.

## Verify the image

Read the `index` reference from the verified `image-digests.txt` (also recorded in release notes):

```sh
image=$(awk '$1 == "index" {print $2}' image-digests.txt)
cosign verify --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image"
cosign verify-attestation --type cyclonedx --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image"
docker pull --platform "linux/$arch" "$image"
```

Both platform manifests and the index are signed. Platform-specific server SBOMs are attached
to their manifests and to the index; CLI SBOMs are downloadable `.cdx.json` files. SBOMs inventory
the actual auditable binaries (and the image's CA bundle), not the workspace's test dependencies.
They are inventories, not assurances that dependencies are vulnerability-free.

## Full consumer rehearsal

On a disposable native Linux host with Docker, check out the release source and enter
`nix develop`. Download **all** release assets to `downloaded`, then run:

```sh
bash scripts/release-verify.sh "$version" "$arch" downloaded "$image" "$identity"
```

This verifies the signed manifest, checksums, image signature and SBOM attestation, anonymously
pulls the immutable image and runs the archived CLI plus container startup smoke. It needs
network access to GHCR, Sigstore, the pinned k3s image and the Nix caches. It creates and deletes
its own uniquely named k3d cluster; do not point it at a production cluster.

For a local **unsigned** candidate rehearsal (no GitHub OIDC or public registry needed):

```sh
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
bash scripts/release-build.sh v0.0.0 arm64 dist # use the checked-out Cargo version and native arch
bash scripts/release-smoke.sh dist/genkanctl-v0.0.0-linux-arm64.tar.gz genkan:release-arm64
```

A local candidate smoke does not establish public downloadability, OIDC signing or amd64
execution on an arm64 VM. The tag-triggered native consumer jobs are the publication gate for
those properties; retain their run URL as release rehearsal evidence.

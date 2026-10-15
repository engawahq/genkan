# Releases

Use [GitHub Releases](https://github.com/engawahq/genkan/releases) to download Genkan.
While Genkan is in alpha, releases are marked as prereleases.

## Choose your platform

| Platform | CLI archive | Container image |
|---|---|---|
| Linux amd64 / x86_64 | `genkanctl-v<VERSION>-linux-amd64.tar.gz` | `ghcr.io/engawahq/genkan:v<VERSION>` |
| Linux arm64 / aarch64 | `genkanctl-v<VERSION>-linux-arm64.tar.gz` | Same image tag; Docker selects your architecture |

The CLI and server are statically linked. For macOS, Windows or other architectures, build
the CLI from source.

Each release includes checksums, signatures and SBOMs. An SBOM is a list of the dependencies
included in an artifact; the downloadable SBOM files end in `.cdx.json`.

## Download and verify

You need GitHub CLI (`gh`), `cosign` 3.x and GNU `sha256sum`. Pulling the image also needs Docker.
These command-line tools, apart from Docker, are available in the repository's `nix develop` shell.

Choose a release version and your architecture, then download its files:

```sh
version=v0.0.1
arch=arm64 # use amd64 for x86_64
identity="https://github.com/engawahq/genkan/.github/workflows/release.yml@refs/tags/$version"
gh release download "$version" --repo engawahq/genkan --dir downloaded
```

Verify the signature on `SHA256SUMS`, then use it to check the downloaded files. The identity
ties the signature to Genkan's release workflow and the version you chose.

```sh
(
  set -e
  cd downloaded
  cosign verify-blob --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
  sha256sum --check --strict SHA256SUMS
)
```

After both checks pass, extract and try the CLI:

```sh
tar -xzf "downloaded/genkanctl-$version-linux-$arch.tar.gz"
./genkanctl --help
```

To verify and pull the container, read its digest from the checked `image-digests.txt`.
A digest identifies the exact image bytes.

```sh
image=$(awk '$1 == "index" {print $2}' downloaded/image-digests.txt)
cosign verify --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image"
cosign verify-attestation --type cyclonedx --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image"
docker pull --platform "linux/$arch" "$image"
```

The image and its platform variants are signed, with server SBOMs attached. The signed
checksums also cover the CLI archives, downloadable SBOMs, image digests and `provenance.json`,
which records the source commit and build run.

## Publish a release

1. Update the workspace version in `Cargo.toml` and update `Cargo.lock`. For the first release,
   use `0.0.1`. Merge the release commit to `main`.
2. In GitHub Actions, select **Release → Run workflow**, choose that commit's branch and enter
   the matching version, such as `v0.0.1`. This runs CI and tries both platform builds without
   publishing.
3. Make sure the GHCR package `engawahq/genkan` is public and this repository's Actions token
   can write to it. If the package is new, the first publishing run creates it; change its
   visibility before the download checks run. Set repository rulesets to protect `main` and
   restrict release-tag changes to maintainers.
4. Tag the release commit and push the tag. Replace `YOUR_RELEASE_COMMIT` with its commit hash:

   ```sh
   git tag v0.0.1 YOUR_RELEASE_COMMIT
   git push origin v0.0.1
   ```

5. Watch the **Release** run in GitHub Actions. Once it succeeds, the GitHub prerelease is public.

The tag must match the Cargo version, and the commit must be on `main`. The workflow reruns
CI, builds both platforms using the pinned Rust/Nix toolchain and locked dependencies, and
tests the CLI archives and images it will publish. It then signs and uploads the artifacts,
downloads them on fresh runners, and verifies and runs them before publishing the draft release.
Signing uses GitHub's short-lived identity token through Sigstore. Write permissions are
limited to the publication and finalization jobs.

Image tags appear while the GitHub release is still a draft. Use a release after its workflow
succeeds, and use the digest in its release notes when pinning a deployment.

If a run fails, check its Actions logs and draft release. Fix the cause, such as a private
GHCR package, then delete that failed draft before rerunning publication. Keep published
version tags unchanged.

## Try the artifacts on a test machine

On a disposable Linux machine matching the chosen architecture, install Docker, check out
the release source and enter `nix develop`. With the variables and `downloaded` directory
from the examples above, run:

```sh
bash scripts/release-verify.sh "$version" "$arch" downloaded "$image" "$identity"
```

The script verifies the downloads, pulls the image and creates a temporary k3s cluster.
It uses the downloaded CLI to install Genkan, checks the running server and removes the
cluster when finished. It needs access to GHCR, Sigstore, the k3s image and Nix caches.

To try a build from your working tree, run these commands inside `nix develop`. Use the
version in `Cargo.toml` and your machine's architecture:

```sh
version=v0.0.0
arch=arm64 # or amd64
SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH
bash scripts/release-build.sh "$version" "$arch" dist
bash scripts/release-smoke.sh "dist/genkanctl-$version-linux-$arch.tar.gz" "genkan:release-$arch"
```

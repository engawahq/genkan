#!/usr/bin/env bash
# CI-only publication of the already smoke-tested candidates. No compilation here.
set -euo pipefail
version="${1:?usage: release-publish.sh <version> <candidate-directory>}"
candidates="$(realpath "${2:?candidate directory required}")"
: "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GH_TOKEN:?}"
image="ghcr.io/${GITHUB_REPOSITORY,,}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export DOCKER_CONFIG="$work/docker"
mkdir -p "$DOCKER_CONFIG" "$work/assets"
printf '%s' "$GH_TOKEN" | docker login ghcr.io --username "${GITHUB_ACTOR:?}" --password-stdin
# Refuse overwriting a release (including a previous failed draft). Recovery is manual.
if gh release view "$version" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  echo "Release $version already exists; inspect it before retrying" >&2
  exit 1
fi
refs=()
for arch in amd64 arm64; do
  dir="$candidates/release-$arch"
  candidate="$image:candidate-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$arch"
  # The input is our unsigned, gated local build; signatures are added below.
  # Do not depend on a host-wide containers/policy.json in a Nix-equipped runner.
  skopeo --insecure-policy copy --authfile "$DOCKER_CONFIG/config.json" "docker-archive:$dir/image.tar" "docker://$candidate"
  digest="$(skopeo inspect --authfile "$DOCKER_CONFIG/config.json" --format '{{.Digest}}' "docker://$candidate")"
  ref="$image@$digest"
  refs+=("$ref")
  cosign sign --yes "$ref"
  cosign attest --yes --type cyclonedx --predicate "$dir/genkan-$version-linux-$arch.cdx.json" "$ref"
  cp "$dir/genkanctl-$version-linux-$arch.tar.gz" "$dir/"*.cdx.json "$work/assets/"
  printf '%s  %s\n' "$arch" "$ref" >> "$work/assets/image-digests.txt"
done
# The manifest contains only previously built candidates, selected by digest (never rebuilt).
docker manifest create "$image:$version" "${refs[@]}"
docker manifest push "$image:$version"
digest="$(skopeo inspect --raw --authfile "$DOCKER_CONFIG/config.json" "docker://$image:$version" | sha256sum | cut -d ' ' -f 1)"
ref="$image@sha256:$digest"
printf 'index  %s\n' "$ref" >> "$work/assets/image-digests.txt"
cosign sign --yes "$ref"
# Attach both platform SBOMs to the index, as well as to each platform manifest.
for arch in amd64 arm64; do
  cosign attest --yes --type cyclonedx --predicate "$work/assets/genkan-$version-linux-$arch.cdx.json" "$ref"
done
jq -n --arg commit "$GITHUB_SHA" --arg repository "https://github.com/$GITHUB_REPOSITORY" \
  --arg version "$version" --arg run "https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT" \
  '{source: $repository, commit: $commit, version: $version, workflowRun: $run,
    build: "Pinned flake.lock and rust-toolchain.toml; cargo auditable build --release --locked; native Linux musl"}' \
  > "$work/assets/provenance.json"
(
  cd "$work/assets"
  sha256sum genkanctl-*.tar.gz genkan*.cdx.json image-digests.txt provenance.json > SHA256SUMS
  cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS
)
{
  printf '# Genkan %s (alpha)\n\n' "$version"
  printf 'Source commit: %s\n\n' "$GITHUB_SHA"
  printf 'Linux amd64 and arm64 static CLI archives and container image.\n\n'
  printf '## Image digests\n\n```text\n'
  cat "$work/assets/image-digests.txt"
  printf '```\n\nVerify signatures, checksums and SBOMs using [the release instructions](https://github.com/%s/blob/%s/docs/releases.md).\n' "$GITHUB_REPOSITORY" "$GITHUB_SHA"
} > "$work/notes.md"
gh release create "$version" "$work/assets/"* --repo "$GITHUB_REPOSITORY" --verify-tag \
  --target "$GITHUB_SHA" --draft --prerelease --title "Genkan $version" --notes-file "$work/notes.md"
printf 'image=%s\n' "$ref" >> "${GITHUB_OUTPUT:?}"

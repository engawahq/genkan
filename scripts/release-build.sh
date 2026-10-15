#!/usr/bin/env bash
# Run inside the pinned `nix develop` shell on native Linux; Docker is external.
# Builds candidates only. The workflow runs release-smoke.sh separately before publishing.
set -euo pipefail

if [[ $# != 3 ]]; then
  echo "usage: release-build.sh <vVERSION> <amd64|arm64> <output-dir>" >&2
  exit 2
fi
version="$1"
arch="$2"
root="$(cd "$(dirname "$0")/.." && pwd)"
: "${IN_NIX_SHELL:?run inside nix develop}"
: "${GENKAN_CA_BUNDLE:?run inside nix develop}"
: "${SOURCE_DATE_EPOCH:?set to the release commit timestamp}"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ || ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "expected a v-prefixed release version and integer SOURCE_DATE_EPOCH" >&2
  exit 2
fi
if [[ "$(uname -s)" != Linux ]]; then
  echo "release builds require native Linux" >&2
  exit 2
fi
case "$arch:$(uname -m)" in
  amd64:x86_64) target=x86_64-unknown-linux-musl ;;
  arm64:aarch64 | arm64:arm64) target=aarch64-unknown-linux-musl ;;
  *) echo "unsupported architecture or non-native runner: $arch" >&2; exit 2 ;;
esac
mkdir -p "$3"
output="$(cd "$3" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/cli" "$work/image"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
mkdir -p "$target_dir"
target_dir="$(cd "$target_dir" && pwd)"

# Embedded cargo-auditable metadata lets Syft inventory dependencies in shipped binaries,
# instead of reporting every package in the workspace or Cargo.lock.
cargo auditable build --release --locked --target "$target" --target-dir "$target_dir" \
  --manifest-path "$root/Cargo.toml" -p genkanctl -p genkan
for binary in genkanctl genkan; do
  elf="$(readelf --program-headers --dynamic "$target_dir/$target/release/$binary")"
  if [[ "$elf" == *INTERP* || "$elf" == *'(NEEDED)'* ]]; then
    echo "$binary is not a fully static executable" >&2
    exit 1
  fi
done
install -m 0755 "$target_dir/$target/release/genkanctl" "$work/cli/genkanctl"
tar --format=ustar --sort=name --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 --group=0 --numeric-owner --mode=0755 \
  -C "$work/cli" -cf - genkanctl | gzip -n -9 > "$output/genkanctl-$version-linux-$arch.tar.gz"

# Scan the exact file packaged above, not Cargo manifests or a fresh build.
export SYFT_CHECK_FOR_APP_UPDATE=false
syft scan "file:$work/cli/genkanctl" \
  --output "cyclonedx-json=$output/genkanctl-$version-linux-$arch.cdx.json"
jq -e '.bomFormat == "CycloneDX" and any(.components[]?; (.purl // "") | startswith("pkg:cargo/"))' \
  "$output/genkanctl-$version-linux-$arch.cdx.json" > /dev/null

# Keep the Containerfile's existing traversable CA-directory staging pattern.
install -m 0555 "$target_dir/$target/release/genkan" "$work/image/genkan"
install -d -m 0755 "$work/image/etc" "$work/image/etc/ssl" "$work/image/etc/ssl/certs"
install -m 0444 "$GENKAN_CA_BUNDLE" "$work/image/etc/ssl/certs/ca-certificates.crt"
touch -d "@$SOURCE_DATE_EPOCH" "$work/image/genkan" "$work/image/etc" \
  "$work/image/etc/ssl" "$work/image/etc/ssl/certs" "$work/image/etc/ssl/certs/ca-certificates.crt"
image="genkan:release-$arch"
docker build --platform "linux/$arch" --network none --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --file "$root/Containerfile" --tag "$image" "$work/image"
docker image save --output "$output/image.tar" "$image"

# A scratch image has no distro package database to own the CA bundle. Capture all
# file digests in Syft, then preserve that observed bundle as a CycloneDX file component.
# See https://oss.anchore.com/docs/reference/syft/configuration/ (file.metadata).
SYFT_FILE_METADATA_SELECTION=all SYFT_FILE_METADATA_DIGESTS=sha256 \
  syft scan "docker-archive:$output/image.tar" \
    --output "syft-json=$work/image.syft.json" \
    --output "cyclonedx-json=$work/image.cdx.json"
ca_sha="$(jq -er '[.files[] | select(.location.path == "/etc/ssl/certs/ca-certificates.crt")
  | .digests[] | select(.algorithm == "sha256") | .value] | unique
  | if length == 1 then .[0] else error("missing or ambiguous CA bundle digest") end' "$work/image.syft.json")"
jq --arg sha "$ca_sha" --arg source "$GENKAN_CA_BUNDLE" '
  .components += [{
    type: "file", "bom-ref": "file:/etc/ssl/certs/ca-certificates.crt",
    name: "/etc/ssl/certs/ca-certificates.crt",
    hashes: [{alg: "SHA-256", content: $sha}],
    properties: [{name: "genkan:nix-source", value: $source}]
  }]
' "$work/image.cdx.json" > "$output/genkan-$version-linux-$arch.cdx.json"
jq -e '.bomFormat == "CycloneDX" and any(.components[]?; (.purl // "") | startswith("pkg:cargo/"))' \
  "$output/genkan-$version-linux-$arch.cdx.json" > /dev/null
printf 'Built %s and %s (not published).\n' "$output/genkanctl-$version-linux-$arch.tar.gz" "$image"

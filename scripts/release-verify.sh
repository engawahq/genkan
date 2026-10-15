#!/usr/bin/env bash
# Rehearse consumption of downloaded release assets, without rebuilding or registry credentials.
# Run inside the pinned `nix develop` shell on native Linux amd64 or arm64; Docker is external.
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo 'usage: release-verify.sh <version> <arch> <directory> <image-digest-ref> <certificate-identity>' >&2
  exit 1
fi
version="$1"
arch="$2"
directory="$3"
image="$4"
identity="$5"
root="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo 'release version must be a v-prefixed semantic version' >&2
  exit 1
fi
case "$(uname -s):$(uname -m):$arch" in
  Linux:x86_64:amd64 | Linux:aarch64:arm64) ;;
  *) echo 'release verification supports native Linux amd64 and arm64 only' >&2; exit 1 ;;
esac
if [[ ! "$image" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
  echo 'image reference must be immutable: <registry>/<repository>@sha256:<64 lowercase hex digits>' >&2
  exit 1
fi
if [[ -z "$identity" ]]; then
  echo 'an exact signing certificate identity is required' >&2
  exit 1
fi

directory="$(cd "$directory" && pwd)"
archive="genkanctl-${version}-linux-${arch}.tar.gz"
issuer='https://token.actions.githubusercontent.com'
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Do not inherit the publisher's Docker login. This rehearsal must work for a public consumer.
export DOCKER_CONFIG="$work/docker"
mkdir -p "$DOCKER_CONFIG"
certificate=(--certificate-identity "$identity" --certificate-oidc-issuer "$issuer")

cosign verify-blob "${certificate[@]}" \
  --bundle "$directory/SHA256SUMS.sigstore.json" "$directory/SHA256SUMS"
(
  cd "$directory"
  # A signed manifest must actually cover every artifact consumed below, not just an unrelated file.
  for asset in "$archive" "genkanctl-${version}-linux-${arch}.cdx.json" "genkan-${version}-linux-${arch}.cdx.json" image-digests.txt provenance.json; do
    found=false
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" =~ ^[0-9a-f]{64}\ \  ]] && [[ "${line:66}" == "$asset" ]]; then
        found=true
        break
      fi
    done < SHA256SUMS
    if [[ "$found" != true ]]; then
      echo "signed SHA256SUMS does not cover $asset" >&2
      exit 1
    fi
  done
  sha256sum --check --strict SHA256SUMS
)
# Bind the image consumed below to the same authenticated release as the archives.
recorded_image=
while read -r platform reference; do
  if [[ "$platform" == index ]]; then
    if [[ -n "$recorded_image" ]]; then
      echo 'duplicate image index in signed release metadata' >&2
      exit 1
    fi
    recorded_image="$reference"
  fi
done < "$directory/image-digests.txt"
if [[ "$recorded_image" != "$image" ]]; then
  echo 'requested image differs from the signed release index' >&2
  exit 1
fi

cosign verify "${certificate[@]}" "$image" > "$work/image-signature.json"
# --type checks the in-toto predicate type, and default claim checking binds its subject to image.
cosign verify-attestation "${certificate[@]}" --type cyclonedx "$image" > "$work/attestations.json"
# Require an actual CycloneDX document inside the verified envelope, not merely its type label.
jq --slurp --exit-status --slurpfile expected "$directory/genkan-${version}-linux-${arch}.cdx.json" '
  length > 0 and any(.[]; (.payload | @base64d | fromjson).predicate == $expected[0]) and all(.[];
    (.payload | @base64d | fromjson) as $statement |
    $statement.predicateType == "https://cyclonedx.org/bom" and
    $statement.predicate.bomFormat == "CycloneDX" and
    ($statement.predicate.specVersion | type == "string" and test("^[0-9]+[.][0-9]+$")) and
    ($statement.predicate.version | type == "number" and . >= 1 and floor == .) and
    ($statement.predicate.components | type == "array")
  )
' "$work/attestations.json" > /dev/null

docker pull --platform "linux/$arch" "$image"
"$root/scripts/release-smoke.sh" "$directory/$archive" "$image"

#!/bin/sh
# Mirror the PHP manifests and contract fixtures into upstream/ (docs/port/spec.md §2).
# Usage: scripts/sync-upstream.sh [<git-ref>]   (default: the ref in upstream/REF)
# Source repo: $POLARIS_CORE or ../polaris-core.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
src=${POLARIS_CORE:-"$root/../polaris-core"}
ref=${1:-$(sed -n 1p "$root/upstream/REF" 2>/dev/null | cut -d' ' -f1)}
[ -n "$ref" ] || { echo "no ref given and upstream/REF missing" >&2; exit 1; }
git -C "$src" rev-parse --verify --quiet "$ref^{commit}" >/dev/null || { echo "unknown ref $ref in $src" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git -C "$src" archive "$ref" packages | tar -x -C "$tmp"

rm -rf "$root/upstream/api" "$root/upstream/fixtures"
mkdir -p "$root/upstream/api" "$root/upstream/fixtures"
for pkg in "$tmp"/packages/*/; do
	name=$(basename "$pkg")
	[ -d "$pkg/api" ] && cp -R "$pkg/api" "$root/upstream/api/$name"
	[ -d "$pkg/tests/Contract/fixtures" ] && cp -R "$pkg/tests/Contract/fixtures" "$root/upstream/fixtures/$name"
done

sha=$(git -C "$src" rev-parse --short "$ref^{commit}")
tag=$(git -C "$src" describe --tags --exact-match "$sha" 2>/dev/null || echo untagged)
echo "$sha $tag" > "$root/upstream/REF"
echo "synced upstream $sha ($tag)"

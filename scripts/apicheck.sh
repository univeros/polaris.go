#!/bin/sh
# Fails when the Go API of the module changes incompatibly since <base>. The API is every exported
# name of every package outside internal/ (API.md): what can be imported is what is promised.
#
#   - <base> is before v1.0.0 (its latest tag is v0.x, or it has none): a break passes only when
#     docs/decisions.md gains a line containing "Breaking" in the same change.
#   - <base> is at or after v1.0.0: a break is refused. The only way to break is a new major
#     version, which moves the module path (…/v2); then there is nothing to compare.
#
# Usage: make apicheck [BASE=<ref>]     (default: the latest tag; CI: the pull request's base)
# APICHECK_TAG=<vX.Y.Z> stands in for <base>'s latest tag, to try the v1 rule before v1 exists.
set -eu

apidiff=${APIDIFF:?set APIDIFF (make apicheck sets it)}
root=$(cd "$(dirname "$0")/.." && pwd)
base=${1:?usage: scripts/apicheck.sh <base-ref>}
module=$(cd "$root" && go list -m)

tmp=$(mktemp -d)
trap 'git -C "$root" worktree remove --force "$tmp/base" >/dev/null 2>&1; rm -rf "$tmp"' EXIT
git -C "$root" worktree add --quiet --detach "$tmp/base" "$base"

basemodule=$(cd "$tmp/base" && go list -m)
if [ "$basemodule" != "$module" ]; then
	echo "apicheck: the module path moved from $basemodule to $module: a new major version, not compared with $base"
	exit 0
fi

(cd "$tmp/base" && go run "$apidiff" -m -w "$tmp/base.export" "$module") 2>/dev/null
(cd "$root" && go run "$apidiff" -m -incompatible "$tmp/base.export" "$module") 2>/dev/null >"$tmp/report"

# A report line is "- ./pkg.Ident…: change", "- Ident…: change" for package polaris, or
# "- ./pkg: package removed". apidiff leaves internal/ out; the programs (examples/, cmd/) are
# not importable either.
grep '^- ' "$tmp/report" | grep -v -e '^- \./examples/' -e '^- \./cmd/' >"$tmp/breaks" || true

if [ ! -s "$tmp/breaks" ]; then
	echo "apicheck: the Go API is compatible with $base"
	exit 0
fi
echo "apicheck: incompatible changes to the Go API since $base:"
cat "$tmp/breaks"

tag=${APICHECK_TAG:-$(git -C "$root" describe --tags --abbrev=0 --match 'v[0-9]*' "$base" 2>/dev/null || true)}
major=${tag#v}
major=${major%%.*}
case $major in '' | *[!0-9]*) major=0 ;; esac
if [ "$major" -ge 1 ]; then
	echo "apicheck: refused: $base is $tag, and a v$major module does not break its API (API.md). Keep the old name working and mark it Deprecated; a removal waits for the next major version, whose module path ends in /v$((major + 1))." >&2
	exit 1
fi
if git -C "$root" diff "$(git -C "$root" merge-base "$base" HEAD)" -- docs/decisions.md | grep -q '^+.*Breaking'; then
	echo "apicheck: allowed before v1.0.0: docs/decisions.md records the break"
	exit 0
fi
echo "apicheck: record the break in docs/decisions.md (a \"Breaking\" line) and CHANGELOG.md, or keep the API compatible" >&2
exit 1

#!/bin/sh
# Fails when the stable Go API (scripts/api-stable.txt, API.md §1–§2) changes incompatibly since
# <base>, unless docs/port/decisions.md gains an entry with a "Breaking" line in the same change
# (API.md: every change to a stable name needs a decision entry).
# Usage: make apicheck BASE=<ref>     (CI: the pull request's base branch)
set -eu

apidiff=${APIDIFF:?set APIDIFF (make apicheck sets it)}
root=$(cd "$(dirname "$0")/.." && pwd)
base=${1:?usage: scripts/apicheck.sh <base-ref>}
module=$(cd "$root" && go list -m)

tmp=$(mktemp -d)
trap 'git -C "$root" worktree remove --force "$tmp/base" >/dev/null 2>&1; rm -rf "$tmp"' EXIT
git -C "$root" worktree add --quiet --detach "$tmp/base" "$base"
(cd "$tmp/base" && go run "$apidiff" -m -w "$tmp/base.export" "$module") 2>/dev/null
(cd "$root" && go run "$apidiff" -m -incompatible "$tmp/base.export" "$module") 2>/dev/null >"$tmp/report"

# A report line is "- ./pkg.Ident…: change" ("- Ident…: change" for package polaris); keep those
# whose package, or package.Name, is listed.
awk -v list="$root/scripts/api-stable.txt" '
BEGIN { while ((getline l < list) > 0) { sub(/#.*/, "", l); gsub(/[ \t]/, "", l); if (l != "") stable[l] = 1 } }
/^- / {
	id = substr($0, 3); id = substr(id, 1, index(id, ": ") - 1); pkg = "."
	if (substr(id, 1, 2) == "./") { id = substr(id, 3); pkg = substr(id, 1, index(id, ".") - 1); id = substr(id, length(pkg) + 2) }
	gsub(/^\(\*?|\)/, "", id); name = id; if (index(name, ".")) name = substr(name, 1, index(name, ".") - 1)
	glob = pkg; sub(/\/[^\/]+$/, "/*", glob)
	if (stable[pkg] || (glob != pkg && stable[glob]) || stable[pkg "." name]) print
}' "$tmp/report" >"$tmp/stable"

if [ ! -s "$tmp/stable" ]; then
	echo "apicheck: the stable API is compatible with $base"
	exit 0
fi
echo "apicheck: incompatible changes to the stable API since $base:"
cat "$tmp/stable"
if git -C "$root" diff "$(git -C "$root" merge-base "$base" HEAD)" -- docs/port/decisions.md | grep -q '^+.*Breaking'; then
	echo "apicheck: allowed: docs/port/decisions.md records the break"
	exit 0
fi
echo "apicheck: record the break in docs/port/decisions.md (a \"Breaking\" line) and API.md, or keep the API compatible" >&2
exit 1

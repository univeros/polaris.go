#!/bin/sh
# Prints the CHANGELOG.md section of one version: the body of its GitHub Release
# (.github/workflows/release.yml). Fails when CHANGELOG.md has no "## [<version>]" section, so a
# tag pushed without its changelog entry gets no empty release.
#
#   scripts/release-notes.sh v0.3.1
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tag=${1:?usage: scripts/release-notes.sh <tag>}
version=${tag#v}

notes=$(awk -v head="## [$version]" '
	/^## / { if (found) exit; found = (index($0, head) == 1); next }
	/^\[[^]]*\]: / { if (found) exit }
	found
' "$root/CHANGELOG.md")

if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
	echo "release-notes: CHANGELOG.md has no section \"## [$version]\"" >&2
	exit 1
fi
printf '%s\n' "$notes"

#!/usr/bin/env bash
# Fuzzes every fuzz target (each `func Fuzz*` in a *_test.go file) for FUZZTIME, one target per
# `go test` run (Go fuzzes one target at a time). `make qa` only runs the seed corpora; this
# searches for new inputs. A failing input is written by Go to the package's
# testdata/fuzz/<Target>/; the script goes on with the other targets, lists the failures and
# exits non-zero. Commit a failing input with its fix: it stays a regression test.
#
#   scripts/fuzz.sh                    # every target, FUZZTIME (default 10s) each
#   FUZZTIME=60s scripts/fuzz.sh       # every target, one after the other
#   scripts/fuzz.sh 'FuzzCBOR|FuzzPatch'  # only the targets whose name matches this regexp
#   scripts/fuzz.sh --list [regexp]    # the matching targets as a JSON array of
#                                      # {"target","package","id"}: the CI matrix
#                                      # (.github/workflows/fuzz.yml fuzzes each in its own job)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
fuzztime=${FUZZTIME:-10s}
list=false
if [ "${1:-}" = "--list" ]; then
  list=true
  shift
fi
filter=${1:-.}
cd "$root"

targets=$(grep -rEo --include='*_test.go' --exclude-dir=.git --exclude-dir=.claude '^func Fuzz[A-Za-z0-9_]*' . | sort)
[ -n "$targets" ] || { echo "fuzz: no fuzz targets found" >&2; exit 1; }

ran=0
failed=""
matrix=""
while IFS= read -r line; do
  name=${line##*func }
  [[ $name =~ $filter ]] || continue
  pkg=$(dirname "${line%%:*}")
  ran=$((ran + 1))
  if $list; then
    id=${pkg#./}
    matrix="$matrix${matrix:+,}{\"target\":\"$name\",\"package\":\"$pkg\",\"id\":\"${id//\//-}-$name\"}"
    continue
  fi
  echo "== $name ($pkg, $fuzztime)"
  go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" "$pkg" || failed="$failed $name($pkg)"
done <<<"$targets"

[ $ran -gt 0 ] || { echo "fuzz: no target matches \"$filter\"" >&2; exit 1; }
if $list; then
  echo "[$matrix]"
  exit 0
fi
if [ -n "$failed" ]; then
  echo "fuzz: FAILED:$failed (failing inputs under <package>/testdata/fuzz/)" >&2
  exit 1
fi
echo "fuzz: $ran target(s), no failures"

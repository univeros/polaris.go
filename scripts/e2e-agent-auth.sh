#!/usr/bin/env bash
# Runs the unmodified Agent Auth Protocol client (@auth/agent from npm, the version and hashes pinned
# in internal/e2e/agentauthserver/package-lock.json) against a Polaris server in its discovery mode.
# Needs Go and Node 22 or newer; not part of `make qa`.
#
# Exit status (internal/e2e/agentauthserver/client.mjs): 0 the whole flow passed; 1 anything else.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
src=$root/internal/e2e/agentauthserver
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp "$src/package.json" "$src/package-lock.json" "$src/client.mjs" "$work/"
(cd "$root" && go build -o "$work/agentauthserver" ./internal/e2e/agentauthserver) # go run hides the exit status
cd "$work"
npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
./agentauthserver node client.mjs

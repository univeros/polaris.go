#!/usr/bin/env bash
# Runs upstream's TypeScript agent SDK walkthrough (@polaris-auth/agent,
# packages/agent-ts/e2e/walkthrough.e2e.ts) against the Go server.
#
#   scripts/e2e-agent-ts.sh            # POLARIS_CORE defaults to ../polaris-core
#
# Needs Go, Node >= 20 and agent-ts's node_modules installed in polaris-core (npm ci there).
# It builds internal/e2e/agentserver (the Slim demo's setup on the Go server), copies agent-ts to
# a temp dir laid out as polaris-core is (packages/agent-ts next to examples/slim/var, where the
# walkthrough reads the mail log), symlinks its node_modules, starts the server, runs
# `npm run e2e` there with POLARIS_URL pointing at it, then kills the server and removes the temp
# dir. Nothing under polaris-core is written.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
core=${POLARIS_CORE:-$root/../polaris-core}
sdk=$core/packages/agent-ts
[ -d "$sdk/node_modules" ] || { echo "no $sdk/node_modules: run npm ci in $sdk" >&2; exit 1; }

work=$(mktemp -d)
pid=
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT

(cd "$root" && go build -o "$work/agentserver" ./internal/e2e/agentserver)

mkdir -p "$work/packages" "$work/examples/slim/var"
rsync -a --exclude node_modules "$sdk/" "$work/packages/agent-ts/"
ln -s "$sdk/node_modules" "$work/packages/agent-ts/node_modules"

"$work/agentserver" -mail "$work/examples/slim/var/mail.log" >"$work/server.out" 2>"$work/server.err" &
pid=$!
for _ in $(seq 100); do
  grep -q '^POLARIS_URL=' "$work/server.out" 2>/dev/null && break
  kill -0 "$pid" 2>/dev/null || { cat "$work/server.err" >&2; exit 1; }
  sleep 0.1
done
url=$(sed -n 's/^POLARIS_URL=//p' "$work/server.out")
[ -n "$url" ] || { echo "agentserver did not start" >&2; cat "$work/server.err" >&2; exit 1; }
echo "Go Polaris at $url"

status=0
(cd "$work/packages/agent-ts" && POLARIS_URL=$url npm run --silent e2e) || status=$?
[ "$status" -eq 0 ] || { echo "--- server log ---" >&2; tail -n 50 "$work/server.err" >&2; }
exit "$status"

#!/usr/bin/env bash
# Runs govulncheck and fails on any vulnerability the code reaches (symbol level), except the
# reviewed false positives listed below. govulncheck has no suppression flag, hence this wrapper.
#
#   scripts/govulncheck.sh            # ./...
#   GOVULNCHECK=golang.org/x/vuln/cmd/govulncheck@vX scripts/govulncheck.sh
#
# Needs jq.
set -euo pipefail

govulncheck=${GOVULNCHECK:-golang.org/x/vuln/cmd/govulncheck@v1.10.0}

# Reviewed: ID, then why it does not apply. Re-review on every upgrade of the module named.
ignored=(
  # crewjam/saml: the record covers every version ("introduced 0", no fix) but describes v0.5.1.
  # In the version in go.mod Assertion.Issuer is a value (no nil dereference) and Subject.NameID is
  # namespace qualified; plugins/sso TestSAMLGO20266909 proves both.
  GO-2026-6909
)

out=$(go run "$govulncheck" -format json ./...)
called=$(jq -r 'select(.finding) | .finding | select(.trace[0].function != null) | .osv' <<<"$out" | sort -u)
status=0
for id in $called; do
  if printf '%s\n' "${ignored[@]}" | grep -qx "$id"; then
    echo "ignored (reviewed): $id"
    continue
  fi
  echo "VULNERABLE: $id https://pkg.go.dev/vuln/$id"
  status=1
done
if [ $status -ne 0 ]; then
  echo "details: go run $govulncheck ./..." >&2
else
  echo "govulncheck: no reachable vulnerabilities"
fi
exit $status

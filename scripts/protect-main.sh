#!/bin/sh
# Protects main on GitHub: pull requests only, the four CI checks green and up to date, linear
# history, no force pushes or deletion. Run once the repository is public (GitHub offers branch
# protection on private repositories only on paid plans). Needs gh with admin rights.
set -eu
repo=${REPO:-univeros/polaris.go}
gh api -X PUT "repos/$repo/branches/main/protection" --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "make qa (fmt, vet, lint, test -race, coverage)",
      "govulncheck",
      "database matrix (PostgreSQL 17, MySQL 8.4)",
      "API compatibility"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": true},
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
echo "main is protected on $repo"

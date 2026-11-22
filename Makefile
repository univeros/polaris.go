.PHONY: qa fmt vet lint vuln apicheck test bench fuzz

# Tool versions, fetched with `go run` (never in go.mod).
GOLANGCI_LINT ?= github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
GOVULNCHECK   ?= golang.org/x/vuln/cmd/govulncheck@v1.10.0
APIDIFF       ?= golang.org/x/exp/cmd/apidiff@v0.0.0-20261120182113-8801fbdfac81

qa: fmt vet lint test

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

lint:
	go run $(GOLANGCI_LINT) run ./...

# vuln fails on reachable vulnerabilities except the reviewed ones listed in the script.
vuln:
	GOVULNCHECK=$(GOVULNCHECK) scripts/govulncheck.sh

# apicheck fails on an incompatible change to the Go API (every exported name outside internal/,
# API.md) since BASE, the latest tag by default. Before v1.0.0 a break passes when
# docs/decisions.md records it; from v1.0.0 on it is refused (scripts/apicheck.sh).
BASE ?= $(shell git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || echo origin/main)
apicheck:
	APIDIFF=$(APIDIFF) scripts/apicheck.sh $(BASE)

# test writes coverage.out (gitignored; CI uploads it).
test:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

bench:
	go test -run '^$$' -bench . -benchmem ./...

# fuzz fuzzes every fuzz target for FUZZTIME each (FUZZ: a regexp of target names). CI runs it
# weekly with 60s (.github/workflows/fuzz.yml); `make qa` only runs the seed corpora.
FUZZTIME ?= 10s
FUZZ     ?= .
fuzz:
	FUZZTIME=$(FUZZTIME) scripts/fuzz.sh '$(FUZZ)'

.PHONY: qa fmt vet lint vuln test bench sync

# Tool versions, fetched with `go run` (never in go.mod).
GOLANGCI_LINT ?= github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
GOVULNCHECK   ?= golang.org/x/vuln/cmd/govulncheck@v1.10.0

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

# test writes coverage.out (gitignored; CI uploads it).
test:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

bench:
	go test -run '^$$' -bench . -benchmem ./...

sync:
	scripts/sync-upstream.sh $(REF)

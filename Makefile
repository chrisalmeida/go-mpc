.PHONY: test test-race test-verbose bench cover fmt vet staticcheck lint fuzz vuln examples ci

# Run all tests
test:
	go test ./...

# Run tests with race detector
test-race:
	go test -race -timeout 600s ./...

# Run tests with verbose output
test-verbose:
	go test -v ./dkls23
	go test -v ./frost

# Run benchmarks
bench:
	go test -bench=. -benchmem ./dkls23
	go test -bench=. -benchmem ./frost

# Show test coverage
cover:
	go test -coverprofile=coverage.out ./dkls23 ./frost ./session
	go tool cover -func=coverage.out | tail -1
	@rm -f coverage.out

# Check formatting
fmt:
	@out=$$(gofmt -l ./dkls23 ./frost ./example); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

# Run go vet
vet:
	go vet ./...

# Run staticcheck
staticcheck:
	go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
	go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...

# Run all linters
lint: fmt vet staticcheck

# Run every fuzz target briefly (see scripts/fuzz-smoke.sh for the retry rule)
fuzz:
	@for pkg in ./dkls23 ./frost; do \
		for target in $$(go test -list 'Fuzz.*' $$pkg | grep '^Fuzz'); do \
			./scripts/fuzz-smoke.sh $$pkg $$target 5s || exit 1; \
		done; \
	done

# Scan dependencies and call graph for known vulnerabilities
vuln:
	go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

# Build and run the example modules
examples:
	cd example && go vet ./...
	cd example/dkls23 && go run .
	cd example/frost && go run .

# Run the full CI pipeline locally
ci: lint test-race cover examples fuzz vuln

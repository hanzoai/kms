.PHONY: all build test test-coverage lint fmt bench clean install-tools verify

# Variables
GO := go
GOFLAGS := -v
GOTEST := $(GO) test
GOBUILD := $(GO) build
GOFMT := gofmt
GOLINT := golangci-lint
COVERAGE_OUT := coverage.out

# Default target
all: fmt lint test build

# Build the package
build:
	$(GOBUILD) $(GOFLAGS) ./...

# Run tests
test:
	$(GOTEST) $(GOFLAGS) ./...

# Run tests with coverage
test-coverage:
	$(GOTEST) $(GOFLAGS) -coverprofile=$(COVERAGE_OUT) -covermode=atomic ./...
	$(GO) tool cover -html=$(COVERAGE_OUT) -o coverage.html || true
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
bench:
	$(GOTEST) -bench=. -benchmem ./...

# Format code
fmt:
	$(GOFMT) -s -w .
	$(GO) mod tidy

# Lint code
lint:
	@if ! which $(GOLINT) > /dev/null 2>&1; then \
		echo "golangci-lint not installed, skipping lint"; \
	else \
		$(GOLINT) run ./...; \
	fi

# Install development tools
install-tools:
	@echo "Installing development tools..."
	@if ! which $(GOLINT) > /dev/null 2>&1; then \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
	fi

# Clean build artifacts
clean:
	rm -f $(COVERAGE_OUT) coverage.html
	$(GO) clean -cache

# Verify module
verify:
	$(GO) mod verify
	$(GO) mod tidy
	@if [ -n "$$(git status --porcelain go.mod go.sum)" ]; then \
		echo "go.mod or go.sum is dirty after go mod tidy"; \
		exit 1; \
	fi

# Run all checks (used in CI)
ci: fmt lint test-coverage bench verify

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Format, lint, test, and build"
	@echo "  build         - Build the package"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  bench         - Run benchmarks"
	@echo "  fmt           - Format code"
	@echo "  lint          - Lint code"
	@echo "  install-tools - Install development tools"
	@echo "  clean         - Clean build artifacts"
	@echo "  verify        - Verify module dependencies"
	@echo "  ci            - Run all CI checks"
	@echo "  help          - Show this help message"
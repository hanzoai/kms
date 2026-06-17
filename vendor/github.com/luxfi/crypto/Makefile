# Lux Post-Quantum Cryptography Makefile

.PHONY: all test bench clean fmt lint install-deps verify build

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOFMT=gofmt
GOMOD=$(GOCMD) mod

# Packages
PACKAGES=./mlkem/... ./mldsa/... ./slhdsa/... ./lamport/... ./precompile/...
ALL_PACKAGES=./...

# Build variables
CGO_ENABLED ?= 1
GOFLAGS ?=

all: fmt lint test

# Install dependencies
install-deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✅ Dependencies installed"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	$(GOFMT) -s -w .
	@echo "✅ Code formatted"

# Lint code
lint:
	@echo "🔍 Linting code..."
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6; \
	fi
	golangci-lint run --timeout=5m || true
	@echo "✅ Linting complete"

# Run tests (exclude cgo/ when native C libs not installed, timeout per package)
test:
	@echo "Running tests..."
	@if pkg-config --exists lux-crypto lux-gpu 2>/dev/null; then \
		CGO_ENABLED=$(CGO_ENABLED) $(GOTEST) -v -race -count=1 -timeout 600s $(ALL_PACKAGES); \
	else \
		CGO_ENABLED=$(CGO_ENABLED) $(GOTEST) -v -race -count=1 -timeout 600s $$($(GOCMD) list ./... | grep -v /cgo); \
	fi
	@echo "Tests complete"

# Run tests with coverage
test-coverage:
	@echo "📊 Running tests with coverage..."
	CGO_ENABLED=$(CGO_ENABLED) $(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic $(ALL_PACKAGES)
	@echo "Coverage report generated: coverage.out"
	@go tool cover -func=coverage.out
	@echo "✅ Coverage analysis complete"

# Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	CGO_ENABLED=1 $(GOTEST) -bench=. -benchmem -run=^$ $(ALL_PACKAGES)
	@echo "✅ Benchmarks complete"

# Build all packages
build:
	@echo "🔨 Building packages..."
	CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -v $(ALL_PACKAGES)
	@echo "✅ Build complete"

# Verify module
verify:
	@echo "✔️ Verifying module..."
	$(GOMOD) verify
	@echo "✅ Module verified"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	$(GOCMD) clean
	rm -f coverage.out
	@echo "✅ Clean complete"

# Install CI tools
install-tools:
	@echo "🛠️ Installing CI tools..."
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
	@echo "✅ Tools installed"

# Help
help:
	@echo "Lux Post-Quantum Cryptography Makefile"
	@echo "Usage: make [target]"

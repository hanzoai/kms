# Lux Accel - Go bindings for luxcpp/lux-accel
#
# Prerequisites:
#   - Go 1.21+
#   - lux_accel library installed (via fetch-deps or manual build)

SHELL := /bin/bash
.PHONY: all test bench clean fetch-deps install-deps check-deps

# Version of luxcpp to fetch
LUXCPP_VERSION ?= v0.1.0
LUXCPP_REPO := github.com/luxfi/luxcpp

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
	PLATFORM := darwin
	ifeq ($(UNAME_M),arm64)
		ARCH := arm64
	else
		ARCH := amd64
	endif
	LIB_EXT := dylib
	INSTALL_PREFIX ?= /usr/local
else ifeq ($(UNAME_S),Linux)
	PLATFORM := linux
	ARCH := $(UNAME_M)
	LIB_EXT := so
	INSTALL_PREFIX ?= /usr/local
else
	PLATFORM := windows
	ARCH := amd64
	LIB_EXT := dll
	INSTALL_PREFIX ?= C:/Program Files/Lux
endif

# Release asset name
RELEASE_ASSET := lux-accel-$(LUXCPP_VERSION)-$(PLATFORM)-$(ARCH).tar.gz
RELEASE_URL := https://$(LUXCPP_REPO)/releases/download/$(LUXCPP_VERSION)/$(RELEASE_ASSET)

# luxcpp source location (for build-deps)
LUXCPP_DIR ?= $(realpath ../../../luxcpp)
SUDO ?=

all: check-deps test

# Check if lux_accel is available
check-deps:
	@echo "Checking dependencies..."
	@if [ -f "$(INSTALL_PREFIX)/lib/liblux_accel.$(LIB_EXT)" ]; then \
		echo "  lux_accel: found at $(INSTALL_PREFIX)/lib"; \
	elif [ -f "$(LUXCPP_DIR)/install/lib/liblux_accel.$(LIB_EXT)" ]; then \
		echo "  lux_accel: found at $(LUXCPP_DIR)/install/lib"; \
	else \
		echo "  lux_accel: NOT FOUND"; \
		echo "  Run 'make fetch-deps' or 'make build-deps' to install"; \
		exit 1; \
	fi
	@if [ -f "$(INSTALL_PREFIX)/include/lux/accel/c_api.h" ]; then \
		echo "  headers: found at $(INSTALL_PREFIX)/include"; \
	elif [ -f "$(LUXCPP_DIR)/install/include/lux/accel/c_api.h" ]; then \
		echo "  headers: found at $(LUXCPP_DIR)/install/include"; \
	else \
		echo "  headers: NOT FOUND"; \
		exit 1; \
	fi

# Fetch pre-built binaries from GitHub releases
fetch-deps:
	@echo "Fetching lux-accel $(LUXCPP_VERSION) for $(PLATFORM)-$(ARCH)..."
	@mkdir -p .deps
	@if command -v curl >/dev/null 2>&1; then \
		curl -fsSL -o .deps/$(RELEASE_ASSET) $(RELEASE_URL) || \
		(echo "Release not found. Try building from source with 'make build-deps'"; exit 1); \
	elif command -v wget >/dev/null 2>&1; then \
		wget -q -O .deps/$(RELEASE_ASSET) $(RELEASE_URL) || \
		(echo "Release not found. Try building from source with 'make build-deps'"; exit 1); \
	else \
		echo "Error: curl or wget required"; exit 1; \
	fi
	@echo "Extracting..."
	@tar -xzf .deps/$(RELEASE_ASSET) -C .deps/
	@echo "Done. Run 'make install-deps' to install to $(INSTALL_PREFIX)"

# Install fetched deps to system path
install-deps:
	@echo "Installing to $(INSTALL_PREFIX)..."
	@if [ -d .deps/include ]; then \
		$(SUDO) mkdir -p $(INSTALL_PREFIX)/include/lux/accel; \
		$(SUDO) cp -r .deps/include/lux/accel/* $(INSTALL_PREFIX)/include/lux/accel/; \
	fi
	@if [ -d .deps/lib ]; then \
		$(SUDO) mkdir -p $(INSTALL_PREFIX)/lib; \
		$(SUDO) cp -r .deps/lib/* $(INSTALL_PREFIX)/lib/; \
	fi
	@echo "Installed to $(INSTALL_PREFIX)"

# Build lux-accel from source (requires luxcpp checkout)
build-deps:
	@echo "Building lux-accel from source..."
	@if [ ! -d "$(LUXCPP_DIR)/lux-accel" ]; then \
		echo "Error: luxcpp not found at $(LUXCPP_DIR)"; \
		echo "Set LUXCPP_DIR to your luxcpp checkout"; \
		exit 1; \
	fi
	@cd "$(LUXCPP_DIR)/lux-accel" && \
	mkdir -p build && cd build && \
	cmake .. -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_INSTALL_PREFIX=$(LUXCPP_DIR)/install && \
	cmake --build . -j$$(nproc 2>/dev/null || sysctl -n hw.ncpu) && \
	cmake --install .
	@echo "Built and installed to $(LUXCPP_DIR)/install"

# Install from luxcpp install dir to system
install-system:
	@echo "Installing from $(LUXCPP_DIR)/install to $(INSTALL_PREFIX)..."
	@$(SUDO) mkdir -p $(INSTALL_PREFIX)/include/lux/accel
	@$(SUDO) mkdir -p $(INSTALL_PREFIX)/lib
	@$(SUDO) cp -r $(LUXCPP_DIR)/install/include/lux/accel/* $(INSTALL_PREFIX)/include/lux/accel/
	@$(SUDO) cp $(LUXCPP_DIR)/install/lib/liblux_accel* $(INSTALL_PREFIX)/lib/
	@echo "Installed to $(INSTALL_PREFIX)"

# Run tests
test: check-deps
	@echo "Running tests..."
	CGO_ENABLED=1 go test -v -race -count=1 ./...

# Run benchmarks
bench: check-deps
	@echo "Running benchmarks..."
	CGO_ENABLED=1 go test -v -bench=. -benchmem -run=^$$ ./...

# Test without CGO (stub fallback)
test-nocgo:
	@echo "Running tests without CGO..."
	CGO_ENABLED=0 go test -v -count=1 ./...

# Clean build artifacts
clean:
	rm -rf .deps
	go clean -testcache

# Show environment info
info:
	@echo "Platform: $(PLATFORM)-$(ARCH)"
	@echo "Install prefix: $(INSTALL_PREFIX)"
	@echo "LUXCPP_DIR: $(LUXCPP_DIR)"
	@echo "Go version: $(shell go version)"
	@echo "CGO enabled: $(shell go env CGO_ENABLED)"
	@echo ""
	@echo "Library search:"
	@ls -la $(INSTALL_PREFIX)/lib/liblux_accel* 2>/dev/null || echo "  not found in $(INSTALL_PREFIX)/lib"
	@ls -la $(LUXCPP_DIR)/install/lib/liblux_accel* 2>/dev/null || echo "  not found in $(LUXCPP_DIR)/install/lib"

help:
	@echo "Lux Accel - Go bindings for luxcpp/lux-accel"
	@echo ""
	@echo "Targets:"
	@echo "  check-deps     - Verify lux_accel library is available"
	@echo "  fetch-deps     - Download pre-built binaries from GitHub releases"
	@echo "  install-deps   - Install fetched deps to $(INSTALL_PREFIX)"
	@echo "  build-deps     - Build lux-accel from luxcpp source"
	@echo "  install-system - Install from luxcpp/install to system"
	@echo "  test           - Run tests with CGO"
	@echo "  test-nocgo     - Run tests without CGO"
	@echo "  bench          - Run benchmarks"
	@echo "  info           - Show environment information"
	@echo "  clean          - Remove build artifacts"
	@echo ""
	@echo "Environment variables:"
	@echo "  LUXCPP_VERSION  - Version to fetch (default: $(LUXCPP_VERSION))"
	@echo "  INSTALL_PREFIX  - Install location (default: $(INSTALL_PREFIX))"
	@echo "  LUXCPP_DIR      - Path to luxcpp source (default: $(LUXCPP_DIR))"

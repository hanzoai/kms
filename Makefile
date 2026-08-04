# Hanzo KMS

help: ## Show this help.
	@awk 'BEGIN{FS=":.*##";printf "\nUsage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*##/{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# What the image ships. The Dockerfile builds exactly these two binaries and no
# others — cmd/kms-fetch and cmd/smoke-zap are helpers, not release artifacts.
# It names the two recipes below rather than repeating them, so each binary has
# one build. Those recipes stay a plain `go build`: the image adds CGO_ENABLED=0,
# GOEXPERIMENT=jsonv2 and -ldflags="-s -w" on top, which is a release concern and
# not what you want in the edit loop.
build: kmsd kms ## Build both binaries the image ships: ./kmsd and ./kms.

kmsd: ## Build the KMS server.
	go build -o kmsd ./cmd/kmsd/

kms: ## Build the KMS CLI.
	go build -o kms ./cmd/kms/

test: ## Run the tests.
	go test ./...

vet: ## Vet.
	go vet ./...

lint: vet ## Lint — go vet, the one static check this repo runs.

clean: ## Remove the built binaries.
	rm -f kmsd kms

.PHONY: help build kmsd kms test vet lint clean

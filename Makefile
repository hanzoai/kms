# Hanzo KMS

kmsd:
	go build -o kmsd ./cmd/kmsd/

kms-cli:
	go build -o kms-cli ./cmd/kms-cli/

test:
	go test ./internal/...

vet:
	go vet ./...

clean:
	rm -f kmsd kms-cli

.PHONY: kmsd kms-cli test vet clean

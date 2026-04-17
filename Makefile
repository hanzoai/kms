# Hanzo KMS

kmsd:
	go build -o kmsd ./cmd/kmsd/

kms:
	go build -o kms ./cmd/kms/

test:
	go test ./internal/...

vet:
	go vet ./...

clean:
	rm -f kmsd kms

.PHONY: kmsd kms test vet clean

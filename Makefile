# Hanzo KMS

# --- Go binaries ---

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

# --- Legacy (Node.js) ---

build:
	docker compose -f docker-compose.prod.yml build

push:
	docker compose -f docker-compose.prod.yml push

up-dev:
	docker compose -f docker-compose.dev.yml up --build

up-dev-ldap:
	docker compose -f docker-compose.dev.yml --profile ldap up --build

up-dev-metrics:
	docker compose -f docker-compose.dev.yml --profile metrics up --build

up-prod:
	docker compose -f docker-compose.prod.yml up --build

down:
	docker compose -f docker-compose.dev.yml down

reviewable-ui:
	cd frontend && \
	npm run lint:fix && \
	npm run type:check

reviewable-api:
	cd backend && \
	npm run lint:fix && \
	npm run type:check

reviewable: reviewable-ui reviewable-api

up-dev-sso:
	docker compose -f docker-compose.dev.yml --profile sso up --build

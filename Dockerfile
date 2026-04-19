# Hanzo KMS — thin wrapper over luxfi/kms.
#
# Build is now pure Go (no SQLCipher, no Base, no TS frontend toolchain
# required). The TS dashboard ships as a static asset built in a separate
# stage and copied verbatim.

FROM node:22-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN corepack enable pnpm && pnpm install --frozen-lockfile
COPY frontend/ .
RUN pnpm vite build

FROM golang:1.26-bookworm AS build

ARG GITHUB_TOKEN
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    GOPRIVATE="github.com/luxfi/*,github.com/hanzoai/*" \
    GONOSUMCHECK="github.com/luxfi/*,github.com/hanzoai/*" \
    git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/" && \
    go mod download

COPY . .

# Pure Go build — no CGO required (luxfi/kms uses ZapDB, not SQLCipher).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /kmsd ./cmd/kmsd/ && \
    go build -ldflags="-s -w" -o /kms ./cmd/kms/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /kmsd /usr/local/bin/kmsd
COPY --from=build /kms  /usr/local/bin/kms
COPY --from=frontend /src/frontend/dist /app/frontend

# Hanzo defaults — the binary already defaults to these, env vars only
# document them for operators inspecting the image.
ENV KMS_LISTEN=:8443 \
    KMS_ZAP_PORT=9653 \
    KMS_DATA_DIR=/data/hanzo-kms \
    KMS_NODE_ID=hanzo-kms-0 \
    KMS_FRONTEND_DIR=/app/frontend \
    BRAND_NAME=Hanzo

RUN mkdir -p /data/hanzo-kms

EXPOSE 8443 9653
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/healthz || exit 1

ENTRYPOINT ["kmsd"]

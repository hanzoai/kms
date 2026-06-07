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
RUN pnpm build

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

# Per SCALE_STANDARD.md §2 — GOEXPERIMENT=jsonv2 is mandatory in every
# production Dockerfile that builds Go code emitting JSON to clients.
# Verified -12% time / -23% allocs on the edge POST roundtrip.
ARG GO_EXPERIMENT=jsonv2
ENV GOEXPERIMENT=${GO_EXPERIMENT}

# Pure Go build — no CGO required (luxfi/kms uses ZapDB, not SQLCipher).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /kmsd ./cmd/kmsd/ && \
    go build -ldflags="-s -w" -o /kms ./cmd/kms/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 1000 hanzo && \
    useradd  --system --uid 1000 --gid hanzo --home-dir /data/hanzo-kms --shell /sbin/nologin hanzo

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

RUN mkdir -p /data/hanzo-kms && chown -R hanzo:hanzo /data/hanzo-kms /app/frontend

USER 1000
WORKDIR /data/hanzo-kms

EXPOSE 8443 9653
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/healthz || exit 1

ENTRYPOINT ["kmsd"]

# Hanzo KMS — thin wrapper over luxfi/kms.
#
# Build is now pure Go (no SQLCipher, no Base, no TS frontend toolchain
# required). The TS dashboard ships as a static asset built in a separate
# stage and copied verbatim.

FROM ghcr.io/hanzoai/nodejs:v24.18.0 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN corepack enable pnpm && pnpm install --frozen-lockfile
COPY frontend/ .
RUN pnpm build

FROM golang:1.26-bookworm AS build

ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
# kmsclient is an in-repo module built via a local replace (see go.mod).
# Stage its go.mod/go.sum so `go mod download` can read the replaced module's
# graph before the full source tree is copied.
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
# Every module in this graph is public. They resolve through the module proxy
# and verify against the checksum database under the h1: hashes already in
# go.sum, so this build carries no credential and sets no GOPRIVATE — the
# checksum database stays authoritative for every dependency.
RUN --mount=type=cache,target=/go/pkg/mod \
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

# What the scratch stage copies in place of useradd and mkdir, which it does not have.
RUN printf 'hanzo:x:1000:1000::/data/hanzo-kms:/sbin/nologin\n' > /etc/passwd.kms && \
    printf 'hanzo:x:1000:\n' > /etc/group.kms && \
    mkdir -p /emptydir

# THE IMAGE IS THE TWO BINARIES.
#
# Both are CGO_ENABLED=0 and statically linked, so they take nothing from a host.
# Debian was supplying ca-certificates (data the binary reads), an account
# (/etc/passwd, which the kernel reads to name a uid it already enforces), and
# curl — which existed for one line, the HEALTHCHECK.
#
# That matters more here than in most images. This is the service that holds the
# estate's secrets, and a base image is the largest thing in it that nobody here
# wrote: apt, dpkg, a shell, coreutils, glibc, each on its own upstream and its
# own CVE feed, none of it ever executed by kmsd. A credential store should be
# the smallest reviewable surface in the fleet, not the largest.
#
# The HEALTHCHECK is deleted rather than given a static curl: every deployment
# runs under Kubernetes, whose readinessProbe and livenessProbe ask
# /healthz from outside the container. Shipping an HTTP client inside a secret
# store so it can ask itself a question the orchestrator already asks is a poor
# trade.
FROM scratch

# Data, read by the binaries, executed by nothing.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# The account. scratch has no useradd, so the two files it would have written are
# written in the builder and copied. The uid is what the kernel enforces; these
# only let something later put a name to it.
COPY --from=build /etc/passwd.kms /etc/passwd
COPY --from=build /etc/group.kms /etc/group

# The data directory, owned by the account, created in the builder because there
# is no mkdir here. A mounted volume replaces it; this is what the image holds
# when nothing is mounted.
COPY --from=build --chown=1000:1000 /emptydir /data/hanzo-kms

COPY --from=build /kmsd /usr/local/bin/kmsd
COPY --from=build /kms  /usr/local/bin/kms
COPY --from=frontend --chown=1000:1000 /src/frontend/dist /app/frontend

# Hanzo defaults — the binary already defaults to these, env vars only
# document them for operators inspecting the image.
ENV KMS_LISTEN=:8443 \
    KMS_ZAP_PORT=9653 \
    KMS_DATA_DIR=/data/hanzo-kms \
    KMS_NODE_ID=hanzo-kms-0 \
    KMS_FRONTEND_DIR=/app/frontend \
    BRAND_NAME=Hanzo

USER 1000:1000
WORKDIR /data/hanzo-kms
EXPOSE 8443 9653
ENTRYPOINT ["/usr/local/bin/kmsd"]

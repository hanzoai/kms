# Hanzo KMS — ZAP Schema
#
# Server: kms (Go) at kms.hanzo.svc.cluster.local or via the unified
# cloud binary at api.hanzo.ai/v1/kms.
#
# This schema is the minimum ZAP-typed public surface needed for the
# HIP-0106 Mount() contract. The full HTTP surface is documented in
# pkg/kms/CLAUDE.md and remains the source of truth for /v1/kms/*
# routes. Wider ZAP-typed handlers (PutSecret, Sign, RotateKeys, …)
# will land as separate schema PRs.
#
# Code generation:
#   zapc generate schema/kms.zap --lang go   --out ./gen/zap/
#   zapc generate schema/kms.zap --lang ts   --out ./gen/zap/

# ── Health ────────────────────────────────────────────────────────────────

struct HealthRequest
  # No fields. Probe is a side-effect-free GET.

struct HealthResponse
  status   Text
  service  Text
  version  Text

# ── Service interface ────────────────────────────────────────────────────

interface KMSService
  # Liveness probe. Always answers ok unless the process is unreachable.
  # Mounted at GET /v1/kms/health by Mount(app, deps).
  health (request HealthRequest) -> (response HealthResponse)

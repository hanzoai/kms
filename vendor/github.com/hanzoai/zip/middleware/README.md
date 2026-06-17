# zip middleware

Generic middleware for the zip framework. Auth-specific middleware
(JWT validation, identity-header stripping) lives in
[`github.com/hanzoai/gateway/middleware`](https://github.com/hanzoai/gateway/tree/main/middleware)
— see "Why auth lives in gateway" below.

## Available middleware

| Name | Purpose |
|---|---|
| `Recover()` | panic → JSON 500 |
| `Logger(luxlog.Logger)` | request log via luxfi/log |
| `RequestID()` | X-Request-Id propagation |
| `Timeout(d)` | per-request ctx deadline |
| `MaxBody(n)` | request size limit |
| `CORS(opts)` | standard CORS |
| `RateLimit(opts)` | per-key token bucket |
| `Telemetry(o11yClient)` | OTel span + request metrics |

## Why auth lives in gateway

JWT validation + identity-header minting are the responsibility of the
`gateway` subsystem (per HIP-0106). Other subsystems mounted inside the
unified `cloud` binary trust the gateway-minted `X-Org-Id` header and do
NOT re-validate JWTs themselves — re-running JWT validation per-subsystem
is wasteful and risks divergent validation rules.

Subsystems that need to ASSERT the request was gateway-minted import
`github.com/hanzoai/gateway` and call `gateway.AssertGatewayMinted(c)`.

## Pipeline order

Recommended order for a service that mounts zip behind hanzoai/gateway:

```go
app.Use(
    middleware.Recover(),                // 1. always first
    middleware.RequestID(),              // 2. mint request id
    middleware.Logger(app.Logger()),     // 3. log with request id
    middleware.Telemetry(o11y),          // 4. metrics
    middleware.RateLimit(rlCfg),         // 5. limit
    middleware.CORS(corsCfg),            // 6. last — close to response
)
```

JWT validation + identity-header stripping/minting is owned by the
gateway subsystem; see
[`github.com/hanzoai/gateway/middleware`](https://github.com/hanzoai/gateway/tree/main/middleware).

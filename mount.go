// HIP-0106 Mount() entry point. Lets cmd/cloud import this package and
// register the in-process KMS server with the shared zip.App alongside
// every other Hanzo subsystem (iam, base, vfs, amqp, …).
//
// Wire shape:
//
//	import _ "github.com/hanzoai/kms"  // init() registers
//
// The init() function below calls cloud.Register("kms", 10, …). At
// startup the cloud binary iterates the registry and calls Mount() for
// each enabled subsystem. Standalone kmsd remains unchanged — both
// shapes co-exist.
//
// The mount strategy is "wrap, don't rewrite": kms.Embed already
// returns an http.Handler containing every KMS route, JWT verifier,
// audit ledger, and ZAP transport. We expose that handler under
// /v1/kms/* via zip's net/http adaptor. The /v1/kms/health route is a
// native zip handler so liveness/readiness do not require booting the
// full Embedded server. (cloud.MountAll runs before any subsystem opens
// a database — Mount() must therefore be cheap.)
package kms

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hanzoai/cloud/pkg/cloud"
	"github.com/hanzoai/zip"
)

// Mount registers KMS routes with the shared cloud zip.App per HIP-0106.
//
// Mount boots the in-process Embedded server with SkipListen=true and
// attaches its http.Handler to the parent App. The parent App owns the
// listener; KMS only contributes routes. The Embedded handle is
// retained on a process-global so cmd/cloud can call Stop during
// graceful shutdown.
//
// /v1/kms/health is a native zip handler that always answers — even
// when KMS_ENV is misconfigured and Embed refuses to boot — so the
// cloud binary's readiness probe doesn't go dark on a KMS misconfig.
func Mount(app *zip.App, deps cloud.Deps) error {
	logger := deps.Logger.New("subsystem", "kms")

	// Native /v1/kms/health — always served, no auth required.
	app.Get("/v1/kms/health", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "ok",
			"service": "kms",
			"version": Version,
		})
	})
	app.Get("/v1/kms/readyz", func(c *zip.Ctx) error {
		if mountedHandle == nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]any{
				"status":  "not_ready",
				"service": "kms",
				"reason":  "embed not initialised",
			})
		}
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "ready",
			"service": "kms",
			"version": Version,
		})
	})

	// Embed the in-process server. SkipListen=true: zip owns the
	// listener. The Embedded handle owns DB, ZAP node, replicator,
	// audit ledger — Stop() drains them on shutdown.
	cfg := EmbedConfig{
		SkipListen: true,
		DataDir:    fmt.Sprintf("%s/kms", strings.TrimRight(deps.DataDir, "/")),
	}
	em, err := Embed(context.Background(), cfg)
	if err != nil {
		// Refuse mounted-but-broken state. cloud.MountAll bubbles
		// the error so the binary exits non-zero on misconfig.
		return fmt.Errorf("kms: embed: %w", err)
	}
	mountedHandle = em
	logger.Info("kms mounted",
		"data_dir", cfg.DataDir,
		"version", Version,
		"zap_port", em.ZAPPort())

	// Mount every other /v1/kms/* and /healthz route under the parent
	// router. zip.AdaptNetHTTP costs ~5% perf vs native fiber dispatch
	// — acceptable migration cost. Subsequent passes can rewrite hot
	// paths in native zip; for now the entire surface is preserved.
	//
	// Two prefixes are mounted so the existing client libraries (which
	// hit /v1/kms/*) and the standalone /healthz probe both work
	// unchanged.
	app.Mount("/v1/kms", em.HTTPHandler())
	app.Mount("/healthz", em.HTTPHandler())

	return nil
}

// mountedHandle is the Embedded server retained for shutdown.
// nil before Mount(), non-nil after. cmd/cloud can reach in via
// Shutdown() to drain. Package-global because cloud.MountAll has no
// per-subsystem teardown handle today — registering one is a separate
// PR. nil-safe.
var mountedHandle *Embedded

// Shutdown drains the in-process KMS server. Idempotent. Safe to call
// when Mount was never invoked.
func Shutdown(ctx context.Context) error {
	if mountedHandle == nil {
		return nil
	}
	err := mountedHandle.Stop(ctx)
	mountedHandle = nil
	return err
}

// init registers KMS with the cloud subsystem registry. Order 10 keeps
// KMS ahead of vfs/amqp/mq (which may need secrets at mount time) and
// behind iam (order 50 — auth first).
func init() {
	cloud.Register("kms", 10, func(app any, deps cloud.Deps) error {
		a, ok := app.(*zip.App)
		if !ok {
			return fmt.Errorf("kms.Mount: app is %T, want *zip.App", app)
		}
		return Mount(a, deps)
	})
}

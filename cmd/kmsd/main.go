// Hanzo KMS daemon — HIP-0106 thin shim.
//
// All assembly logic, route handlers, JWT verification, audit log,
// version CAS, and ZAP transport live in pkg/kms. This binary just:
//
//   - Loads config via cloud.LoadConfig() (env + flags).
//   - Builds shared deps via cloud.BuildDeps(cfg).
//   - Spins up a zip.App, calls kms.Mount(app, deps) — the same Mount
//     the unified cloud binary calls — and listens on cfg.ListenAddr.
//
// The fused cloud binary mounts pkg/kms via blank import + init()
// registration. This shim exists for standalone deploys (Dockerfile,
// k8s sidecars) where running the whole cloud surface is overkill.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hanzoai/cloud/pkg/cloud"
	"github.com/hanzoai/zip"
	"github.com/hanzoai/zip/middleware"
	"github.com/luxfi/log"

	kms "github.com/hanzoai/kms"
)

// version is overridden at build time via -ldflags "-X main.version=...".
// We propagate it into the package-level kms.Version so /healthz and
// /v1/kms/health report the same string.
var version = "dev"

func main() {
	kms.Version = version

	cfg := cloud.LoadConfig()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	deps := cloud.BuildDeps(cfg)

	app := zip.New(zip.Config{
		Logger:  deps.Logger,
		AppName: "kms",
	})
	app.Use(middleware.Recover())
	app.Use(middleware.RequestID())
	app.Use(middleware.Logger(deps.Logger))

	if err := kms.Mount(app, deps); err != nil {
		log.Crit("kms: mount", "err", err)
	}

	// Listen in a goroutine so we can intercept SIGINT/SIGTERM and
	// drain the in-process server gracefully via kms.Shutdown.
	listenErr := make(chan error, 1)
	go func() {
		log.Info("kms: listening", "addr", cfg.ListenAddr)
		listenErr <- app.Listen(cfg.ListenAddr)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case s := <-sig:
		log.Info("kms: shutting down", "signal", s)
	case err := <-listenErr:
		log.Crit("kms: listen failed", "err", err)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	_ = kms.Shutdown(stopCtx)
	_ = app.ShutdownWithContext(stopCtx)
}

// Hanzo KMS daemon.
//
// All assembly logic, route handlers, JWT verification, audit log, version CAS
// and ZAP transport live in package kms. This binary composes kms.App under a
// listener of its own and drains it on a signal. The unified cloud binary
// composes the same kms.App the same way; standalone exists for deploys where
// running the whole cloud surface is overkill.
//
// It reads no host's config. It used to call cloud.LoadConfig, which meant the
// daemon bound $CLOUD_LISTEN (default :8080) while its own image documents
// KMS_LISTEN=:8443 and its HEALTHCHECK curls 8443 — the container's stated
// configuration was not the one the process used.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luxfi/log"
	"github.com/zap-proto/zip"
	"github.com/zap-proto/zip/middleware"

	kms "github.com/hanzoai/kms"
)

// version is overridden at build time via -ldflags "-X main.version=...".
// We propagate it into the package-level kms.Version so /healthz and
// /v1/kms/health report the same string.
var version = "dev"

func main() {
	kms.Version = version

	ctx := context.Background()
	shutdown := initTelemetry(ctx, "hanzo-kms")
	defer shutdown(ctx)

	kmsApp, err := kms.App("")
	if err != nil {
		log.Crit("kms: build", "err", err)
	}

	app := zip.New(zip.Config{AppName: "kmsd"})
	app.Use(middleware.Recover())
	app.Use(middleware.RequestID())
	app.Use(kmsApp)

	// Listen in a goroutine so we can intercept SIGINT/SIGTERM and drain the
	// in-process server gracefully. Shutting the outer app down drains the
	// composed one, which drains Embed.
	addr := kms.ListenAddr()
	listenErr := make(chan error, 1)
	go func() {
		log.Info("kms: listening", "addr", addr)
		listenErr <- app.Listen("http://" + addr)
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
	_ = app.ShutdownWithContext(stopCtx)
}

// Hanzo KMS daemon — thin wrapper around pkg/kms.Embed().
//
// All assembly logic, route handlers, JWT verification, audit log,
// version CAS, and ZAP transport live in pkg/kms. This binary just:
//
//   - Loads config from environment.
//   - Calls kms.Embed(ctx, cfg) to bring up the in-process server.
//   - Waits for SIGINT/SIGTERM and shuts down gracefully.
//
// The fused hanzo binary will import pkg/kms and call kms.Embed()
// with the shared root context and per-service config — kmsd is
// just one of many embeds in that scenario.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luxfi/log"

	kms "github.com/hanzoai/kms/pkg/kms"
)

// version is overridden at build time via -ldflags
// "-X main.version=...". We propagate it into the package-level
// kms.Version so /healthz reports the same string.
var version = "dev"

func main() {
	kms.Version = version

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	em, err := kms.Embed(ctx, kms.EmbedConfig{})
	if err != nil {
		log.Crit("kms: embed", "err", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info("kms: shutting down")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	_ = em.Stop(stopCtx)
}

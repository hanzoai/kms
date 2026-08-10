// KMS is an app. It builds its own zip.App and hands it back, so a host
// composes it — app.Use(kmsApp) — and nothing of the host's crosses into this
// module.
//
// It used to be the other way around: Mount(app, deps) took hanzoai/cloud's
// Deps and an app the host had already built, and an init() pushed itself into
// cloud's registry so cloud could call it back. That points the dependency the
// wrong way. It makes the graph circular, since cloud imports kms in order to
// mount it, and it fixes the set of possible hosts at exactly one — there are
// two editions of hanzoai/cloud declaring the same module path, so cloud.Deps
// names a different type in each and a package that takes it can be composed by
// one of them and never the other.
//
// Of the whole Deps struct this package read two fields: a logger, which
// luxfi/log already publishes as a process default and Embed already uses, and
// a data root, which is one string. So the coupling was one string.
//
// The strategy is still "wrap, don't rewrite": kms.Embed already returns an
// http.Handler carrying every KMS route, the JWT verifier, the audit ledger and
// the ZAP transport. That handler hangs off a wildcard route through zip's
// net/http adaptor; health and readiness are native zip handlers.
package kms

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/zap-proto/zip"
)

// App builds the KMS surface and returns it as a zip.App.
//
// root is the one fact a host supplies: the data root KMS keeps its store
// under, as root/kms. Empty means KMS resolves its own — $KMS_DATA_DIR, else
// /data/hanzo-kms — which is what the standalone daemon wants.
//
// Embed runs with SkipListen: whoever composes this app owns the listener, and
// KMS only contributes routes. Teardown travels with the app rather than with
// the process — the Embedded handle owns zapdb, the ZAP node, the replicator
// and the audit ledger, and drains on the app's shutdown hook. zip makes a
// parent drain the children it composed, so there is no global handle to reach
// for and nothing a host has to remember to call.
//
// A failed Embed returns an error and no app. There is no mounted-but-broken
// state to probe for.
func App(root string) (*zip.App, error) {
	cfg := EmbedConfig{SkipListen: true}
	if root != "" {
		cfg.DataDir = strings.TrimRight(root, "/") + "/kms"
	}
	em, err := Embed(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("kms: embed: %w", err)
	}

	app := zip.New(zip.Config{AppName: "kms"})
	app.OnShutdown(em.Stop)

	// Native probes, so liveness and readiness cost no trip through the
	// adaptor. Registered before the wildcard that follows them.
	probe := func(status string) zip.Handler {
		return func(c *zip.Ctx) error {
			return c.JSON(http.StatusOK, map[string]any{
				"status":  status,
				"service": "kms",
				"version": Version,
			})
		}
	}
	app.Get("/v1/kms/health", probe("ok"))
	app.Get("/v1/kms/readyz", probe("ready"))

	// Everything else, over the net/http bridge. AdaptNetHTTP costs ~5% against
	// native dispatch and preserves the surface exactly. Two prefixes so the
	// client libraries (/v1/kms/*) and the container probe (/healthz) both work
	// unchanged; the trailing wildcard is optional, so /healthz itself resolves.
	h := zip.AdaptNetHTTP(em.HTTPHandler())
	app.All("/v1/kms/*", h)
	app.All("/healthz/*", h)

	return app, nil
}

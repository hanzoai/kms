package cloud

import (
	"fmt"

	luxlog "github.com/luxfi/log"

	"github.com/hanzoai/cloud/clients"
)

// BuildDeps constructs the Deps used by every subsystem's Mount(app, deps).
//
// Wiring rules per HIP-0106 inter-subsystem contract:
//
//  1. If the subsystem is enabled in this process, the Client field is
//     left nil here. The subsystem's own Mount() will install a typed
//     in-process Client into Deps via the SetClient helpers exposed by
//     this package. (Subsystem Mounts run after BuildDeps; they have
//     full access to construct their concrete implementation, and the
//     resulting object goes back into Deps for everyone else to call.)
//
//  2. If the subsystem is disabled but cfg has a non-empty ZAP RPC
//     endpoint for it, the Client field gets a ZAP-RPC stub targeting
//     that endpoint. Subsystem code calls deps.X.Foo(...) without
//     knowing the call goes over the wire.
//
//  3. If the subsystem is disabled AND there is no endpoint, the Client
//     field gets a "disabled" stub that fails closed with a clear
//     error. Mount-time consumers detect this with
//     clients.IsDisabled(err) and log a friendly "dep X needed by Y
//     not configured" message.
//
// JSON does not appear in any of these paths. Inter-subsystem calls
// are ZAP-typed Go values either via direct method dispatch (mode 1)
// or via ZAP RPC over the wire (mode 2). JSON happens only at the
// gateway/ingress edge, through the hanzoai/zip jsonenc helper.
//
// Payments and Vault are special: they are NEVER in-process per
// HIP-0106 solo-vault CDE. Their clients always resolve via
// clients.PaymentsRPCAt / clients.VaultRPCAt; the disabled stub fires
// when no endpoint is configured.
func BuildDeps(cfg *Config) Deps {
	logger := luxlog.New("cloud")
	logger.Info("building deps",
		"brand", cfg.Brand,
		"domain", cfg.Domain,
		"data_dir", cfg.DataDir,
		"enabled", cfg.Enable,
	)

	deps := Deps{
		Logger:  logger,
		Brand:   cfg.Brand,
		Domain:  cfg.Domain,
		DataDir: cfg.DataDir,
	}

	// For each subsystem: enabled → leave nil (Mount fills it); not
	// enabled + endpoint → RPC client; not enabled + no endpoint →
	// disabled stub.
	deps.IAM = pickIAMClient(cfg, logger)
	deps.KMS = pickKMSClient(cfg, logger)
	deps.Base = pickBaseClient(cfg, logger)
	deps.Commerce = pickCommerceClient(cfg, logger)
	deps.AI = pickAIClient(cfg, logger)
	deps.O11y = pickO11yClient(cfg, logger)
	deps.VFS = pickVFSClient(cfg, logger)
	deps.MQ = pickMQClient(cfg, logger)

	// Payments and Vault never co-resident. Disabled stub when no
	// endpoint, otherwise RPC.
	deps.Payments = pickPaymentsClient(cfg, logger)
	deps.Vault = pickVaultClient(cfg, logger)

	return deps
}

// pickIAMClient returns the canonical IAMClient for this process.
// nil = enabled here, Mount will fill it. RPC = remote endpoint
// configured. Disabled = not enabled, no endpoint.
func pickIAMClient(cfg *Config, log luxlog.Logger) IAMClient {
	if cfg.Enabled("iam") {
		return nil
	}
	if cfg.IAMZAPAddr != "" {
		log.Info("deps.IAM → ZAP RPC", "addr", cfg.IAMZAPAddr)
		return clients.IAMRPCAt(cfg.IAMZAPAddr)
	}
	return clients.DisabledIAM()
}

func pickKMSClient(cfg *Config, log luxlog.Logger) KMSClient {
	if cfg.Enabled("kms") {
		return nil
	}
	if cfg.KMSZAPAddr != "" {
		log.Info("deps.KMS → ZAP RPC", "addr", cfg.KMSZAPAddr)
		return clients.KMSRPCAt(cfg.KMSZAPAddr)
	}
	return clients.DisabledKMS()
}

func pickBaseClient(cfg *Config, log luxlog.Logger) BaseClient {
	if cfg.Enabled("base") {
		return nil
	}
	if cfg.BaseZAPAddr != "" {
		log.Info("deps.Base → ZAP RPC", "addr", cfg.BaseZAPAddr)
		return clients.BaseRPCAt(cfg.BaseZAPAddr)
	}
	return clients.DisabledBase()
}

func pickCommerceClient(cfg *Config, log luxlog.Logger) CommerceClient {
	if cfg.Enabled("commerce") {
		return nil
	}
	if cfg.CommerceZAPAddr != "" {
		log.Info("deps.Commerce → ZAP RPC", "addr", cfg.CommerceZAPAddr)
		return clients.CommerceRPCAt(cfg.CommerceZAPAddr)
	}
	return clients.DisabledCommerce()
}

func pickAIClient(cfg *Config, log luxlog.Logger) AIClient {
	if cfg.Enabled("ai") {
		return nil
	}
	if cfg.AIZAPAddr != "" {
		log.Info("deps.AI → ZAP RPC", "addr", cfg.AIZAPAddr)
		return clients.AIRPCAt(cfg.AIZAPAddr)
	}
	return clients.DisabledAI()
}

func pickO11yClient(cfg *Config, log luxlog.Logger) O11yClient {
	if cfg.Enabled("o11y") {
		return nil
	}
	if cfg.O11yZAPAddr != "" {
		log.Info("deps.O11y → ZAP RPC", "addr", cfg.O11yZAPAddr)
		return clients.O11yRPCAt(cfg.O11yZAPAddr)
	}
	// O11y disabled-stub is no-op (not fail-closed) — telemetry
	// going nowhere is a normal mode.
	return clients.DisabledO11y()
}

func pickVFSClient(cfg *Config, log luxlog.Logger) VFSClient {
	if cfg.Enabled("vfs") {
		return nil
	}
	if cfg.VFSZAPAddr != "" {
		log.Info("deps.VFS → ZAP RPC", "addr", cfg.VFSZAPAddr)
		return clients.VFSRPCAt(cfg.VFSZAPAddr)
	}
	return clients.DisabledVFS()
}

func pickMQClient(cfg *Config, log luxlog.Logger) MQClient {
	if cfg.Enabled("mq") {
		return nil
	}
	if cfg.MQZAPAddr != "" {
		log.Info("deps.MQ → ZAP RPC", "addr", cfg.MQZAPAddr)
		return clients.MQRPCAt(cfg.MQZAPAddr)
	}
	return clients.DisabledMQ()
}

func pickPaymentsClient(cfg *Config, log luxlog.Logger) PaymentsClient {
	if cfg.PaymentsZAPAddr != "" {
		log.Info("deps.Payments → ZAP RPC", "addr", cfg.PaymentsZAPAddr)
		return clients.PaymentsRPCAt(cfg.PaymentsZAPAddr)
	}
	return clients.DisabledPayments()
}

func pickVaultClient(cfg *Config, log luxlog.Logger) VaultClient {
	if cfg.VaultZAPAddr != "" {
		log.Info("deps.Vault → ZAP RPC", "addr", cfg.VaultZAPAddr)
		return clients.VaultRPCAt(cfg.VaultZAPAddr)
	}
	return clients.DisabledVault()
}

// MountFunc is the canonical signature every subsystem exposes per
// HIP-0106. Each Hanzo Go service ships a top-level `Mount` symbol
// matching this signature; cmd/cloud/main.go imports the package and
// calls it.
type MountFunc func(app any, deps Deps) error // app is *zip.App; using any here to avoid an import cycle in pkg/cloud

// MountSpec describes one subsystem registered for mounting. The Order
// is used when ordering matters for inter-subsystem deps (e.g. iam
// before authz before commerce).
type MountSpec struct {
	Name  string
	Order int
	Mount MountFunc
}

// Registry is the in-process subsystem registry. Subsystems register via
// init() functions in their respective packages OR cmd/cloud/main.go can
// explicitly enumerate them. Either pattern works.
var Registry []MountSpec

// Register adds a subsystem to the in-process registry.
func Register(name string, order int, mount MountFunc) {
	Registry = append(Registry, MountSpec{Name: name, Order: order, Mount: mount})
}

// MountAll iterates the registry in order and calls Mount() on each
// enabled subsystem.
func MountAll(app any, cfg *Config, deps Deps) error {
	// Sort registry by order — bubble sort, registry is tiny.
	for i := 0; i < len(Registry); i++ {
		for j := i + 1; j < len(Registry); j++ {
			if Registry[j].Order < Registry[i].Order {
				Registry[i], Registry[j] = Registry[j], Registry[i]
			}
		}
	}

	logger := deps.Logger
	for _, spec := range Registry {
		if !cfg.Enabled(spec.Name) {
			logger.Debug("subsystem disabled", "name", spec.Name)
			continue
		}
		if err := spec.Mount(app, deps); err != nil {
			return fmt.Errorf("mount %s: %w", spec.Name, err)
		}
		logger.Info("mounted subsystem", "name", spec.Name)
	}
	return nil
}

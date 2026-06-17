package cloud

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config is the cloud binary's startup configuration. Drives which
// subsystems mount, what brand surface to serve, and where data lives.
type Config struct {
	// Enable lists subsystems to mount this run. Empty = all enabled.
	// Example: --enable=iam,base,kms,commerce,ai,gateway,o11y
	Enable []string

	// Brand is the white-label brand identifier.
	Brand string

	// Domain is the deployment's primary public domain.
	Domain string

	// IAMIssuer is the JWKS issuer for JWT validation (usually iam.hanzo.id).
	IAMIssuer string

	// KMSMasterKeyRef points at the KMS master key for per-tenant DEK derivation.
	KMSMasterKeyRef string

	// DataDir is the on-disk data root.
	DataDir string

	// ListenAddr is the public HTTP listener (default :8080).
	ListenAddr string

	// ZAPListenAddr is the ZAP-RPC listener (default :9653).
	ZAPListenAddr string

	// HealthListenAddr is the health/metrics listener (default :9090).
	HealthListenAddr string

	// AdminListenAddr is the admin endpoint (default :8081, gated by IAM admin).
	AdminListenAddr string

	// Endpoints for out-of-process subsystems (payments, vault). Empty
	// means the subsystem is disabled OR the deployment expects a default
	// service-discovery resolution.
	PaymentsZAPAddr string
	VaultZAPAddr    string

	// ZAP RPC endpoints for subsystems that are NOT enabled in this
	// process but are still needed by an enabled subsystem. Empty
	// means "no remote endpoint" — the client falls back to the
	// disabled stub which fails closed with a clear error.
	//
	// Convention: <subsystem>.<env>.<deployment>.svc:9653 — the same
	// inter-subsystem listener port the unified binary exposes. The
	// transport is hanzoai/zap, never JSON.
	IAMZAPAddr      string
	KMSZAPAddr      string
	BaseZAPAddr     string
	CommerceZAPAddr string
	AIZAPAddr       string
	O11yZAPAddr     string
	VFSZAPAddr      string
	MQZAPAddr       string
}

// LoadConfig reads flags + env into a Config. Flags override env.
func LoadConfig() *Config {
	cfg := &Config{
		ListenAddr:       getenv("CLOUD_LISTEN", ":8080"),
		ZAPListenAddr:    getenv("CLOUD_ZAP_LISTEN", ":9653"),
		HealthListenAddr: getenv("CLOUD_HEALTH_LISTEN", ":9090"),
		AdminListenAddr:  getenv("CLOUD_ADMIN_LISTEN", ":8081"),
		Brand:            getenv("CLOUD_BRAND", "hanzo"),
		Domain:           getenv("CLOUD_DOMAIN", "api.hanzo.ai"),
		IAMIssuer:        getenv("CLOUD_IAM_ISSUER", "https://iam.hanzo.id"),
		KMSMasterKeyRef:  getenv("CLOUD_KMS_MASTER_KEY_REF", ""),
		DataDir:          getenv("CLOUD_DATA_DIR", "/var/lib/cloud"),
		PaymentsZAPAddr:  getenv("CLOUD_PAYMENTS_ZAP_ADDR", ""),
		VaultZAPAddr:     getenv("CLOUD_VAULT_ZAP_ADDR", ""),
		IAMZAPAddr:       getenv("CLOUD_IAM_ZAP_ADDR", ""),
		KMSZAPAddr:       getenv("CLOUD_KMS_ZAP_ADDR", ""),
		BaseZAPAddr:      getenv("CLOUD_BASE_ZAP_ADDR", ""),
		CommerceZAPAddr:  getenv("CLOUD_COMMERCE_ZAP_ADDR", ""),
		AIZAPAddr:        getenv("CLOUD_AI_ZAP_ADDR", ""),
		O11yZAPAddr:      getenv("CLOUD_O11Y_ZAP_ADDR", ""),
		VFSZAPAddr:       getenv("CLOUD_VFS_ZAP_ADDR", ""),
		MQZAPAddr:        getenv("CLOUD_MQ_ZAP_ADDR", ""),
	}

	var enableCSV string
	flag.StringVar(&enableCSV, "enable", getenv("CLOUD_ENABLE", ""), "comma-separated subsystem list (empty=all)")
	flag.StringVar(&cfg.Brand, "brand", cfg.Brand, "white-label brand")
	flag.StringVar(&cfg.Domain, "domain", cfg.Domain, "primary domain")
	flag.StringVar(&cfg.IAMIssuer, "iam-issuer", cfg.IAMIssuer, "JWKS issuer")
	flag.StringVar(&cfg.KMSMasterKeyRef, "kms-master-key-ref", cfg.KMSMasterKeyRef, "KMS master key reference")
	flag.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "data root")
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "HTTP listener")
	flag.Parse()

	if enableCSV != "" {
		for _, name := range strings.Split(enableCSV, ",") {
			if s := strings.TrimSpace(name); s != "" {
				cfg.Enable = append(cfg.Enable, s)
			}
		}
	}
	return cfg
}

// Enabled reports whether subsystem `name` is enabled in this config.
// Empty Enable list = all subsystems enabled.
func (c *Config) Enabled(name string) bool {
	if len(c.Enable) == 0 {
		return true
	}
	for _, s := range c.Enable {
		if s == name {
			return true
		}
	}
	return false
}

func getenv(key, dflt string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return dflt
}

// Validate returns an error if the config is missing required values.
func (c *Config) Validate() error {
	if c.Brand == "" {
		return fmt.Errorf("brand is required")
	}
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data-dir is required")
	}
	return nil
}

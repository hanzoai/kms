// Package cloud is the unified Hanzo Cloud binary per HIP-0106.
//
// One Go binary mounts every Hanzo-native subsystem (iam, base, kms,
// commerce, ai, gateway, o11y, vfs, mq, dns, amqp, mcp, ...) via the
// canonical Mount(app *zip.App, deps cloud.Deps) error contract. Brand,
// enabled subsystems, and tenant scope are deployment configuration; the
// binary is the same artifact across every white-label deployment.
//
// Per HIP-0106 — github.com/hanzoai/HIPs/blob/main/HIPs/hip-0106-unified-hanzo-cloud-binary.md.
package cloud

import (
	luxlog "github.com/luxfi/log"

	"github.com/hanzoai/cloud/types"
)

// Deps is the shared dependency surface passed to every subsystem's
// Mount(app, deps) function. Subsystems consume only what they need.
//
// In-process: each Client below resolves to a direct Go method-call
// implementation. Out-of-process (legacy split deploys): the same Client
// resolves to a ZAP-RPC implementation. Subsystem code does not branch
// on which mode; the interface is the contract.
type Deps struct {
	// Logger is the canonical Hanzo logger (luxfi/log). Subsystems derive
	// scoped child loggers from this.
	Logger luxlog.Logger

	// Brand is the white-label brand identifier for this deployment.
	// Values: "hanzo", "lux", "zoo", "osage", "pars", or any customer brand.
	Brand string

	// Domain is the deployment's primary domain (e.g. "api.hanzo.ai",
	// "api.osage.cloud"). Subsystems use this to scope URLs in responses.
	Domain string

	// DataDir is the per-deployment data root. Per-tenant SQLite files
	// land at {DataDir}/orgs/{orgSlug}/{service}.db per HIP-0302.
	DataDir string

	// Subsystem clients — populated by BuildDeps based on enabled subsystems.
	// Each is an interface with both in-process and ZAP-RPC implementations.
	IAM      IAMClient
	KMS      KMSClient
	Base     BaseClient
	Commerce CommerceClient
	AI       AIClient
	O11y     O11yClient
	VFS      VFSClient
	MQ       MQClient

	// Payments + Vault stay out-of-process (PCI scope isolation per
	// HIP-0106). These clients always resolve to ZAP-RPC implementations,
	// never in-process.
	Payments PaymentsClient
	Vault    VaultClient
}

// Per-subsystem client interfaces live in cloud/types so the
// cloud/clients package can implement them without an import cycle.
// We re-export them as aliases at the cloud root so subsystem code
// keeps writing cloud.IAMClient, cloud.KMSClient, etc.

type IAMClient = types.IAMClient
type KMSClient = types.KMSClient
type BaseClient = types.BaseClient
type CommerceClient = types.CommerceClient
type AIClient = types.AIClient
type O11yClient = types.O11yClient
type VFSClient = types.VFSClient
type MQClient = types.MQClient
type PaymentsClient = types.PaymentsClient
type VaultClient = types.VaultClient

// --- placeholder types (replaced by ZAP-generated types per subsystem) ---
//
// These re-export the canonical transport shapes from cloud/types so
// subsystems and the clients package can both use them without
// pulling cloud as a dependency. As zapc generates typed bindings per
// subsystem, each alias here becomes an alias to the generated type
// in <subsystem>/zap/gen/*.go.

type Claims = types.Claims
type User = types.User
type Org = types.Org
type DBHandle = types.DBHandle
type TenantConfig = types.TenantConfig
type ChatRequest = types.ChatRequest
type ChatResponse = types.ChatResponse
type Counter = types.Counter
type Timing = types.Timing
type Span = types.Span
type IntentRequest = types.IntentRequest
type IntentResponse = types.IntentResponse
type IntentStatus = types.IntentStatus
type VaultChargeRequest = types.VaultChargeRequest
type VaultChargeResponse = types.VaultChargeResponse

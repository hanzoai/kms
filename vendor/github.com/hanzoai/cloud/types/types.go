// Package types holds the placeholder transport types AND the
// inter-subsystem client interfaces shared between cloud (the
// orchestrator) and cloud/clients (the in-process and RPC client
// implementations). Both packages reference this leaf package to
// avoid an import cycle.
//
// As subsystems ship their .zap schemas and zapc generates typed
// bindings, the placeholders here are replaced by aliases to the
// generated structs in <subsystem>/zap/gen/*.go. Until then the
// stable shape lives here so subsystem code can pin signatures
// without re-importing through cloud.
package types

import "context"

// Claims is the JWT-validated identity surface gateway hands to
// downstream subsystems per HIP-0026. Sub = JWT `sub`, Org = JWT
// `owner`, Email = JWT `email`, IsAdmin = JWT `isAdmin`.
type Claims struct {
	Sub     string
	Org     string
	Email   string
	IsAdmin bool
}

// User is the IAM-served user object.
type User struct {
	ID    string
	Email string
	Name  string
}

// Org is the IAM-served org object.
type Org struct {
	ID   string
	Slug string
	Name string
}

// DBHandle is the per-tenant database handle Base hands out.
type DBHandle interface{ Close() error }

// TenantConfig is the commerce-served tenant settings struct.
type TenantConfig struct {
	OrgID string
	Brand string
}

// ChatRequest mirrors the AI subsystem's chat-completion request.
type ChatRequest struct {
	Model  string
	Prompt string
}

// ChatResponse mirrors the AI subsystem's chat-completion response.
type ChatResponse struct{ Content string }

// Counter / Timing / Span are the canonical o11y handles.
type Counter interface{ Inc(n int64) }
type Timing interface{ Observe(seconds float64) }
type Span interface{ End() }

// IntentRequest creates a payments intent. Commerce never sees PAN;
// it only ever passes the vault token + amount + currency.
type IntentRequest struct {
	Token       string
	Currency    string
	AmountCents int64
}

// IntentResponse acknowledges intent creation / state.
type IntentResponse struct {
	ID     string
	Status string
}

// IntentStatus is the status-poll response.
type IntentStatus struct{ Status string }

// VaultChargeRequest is the payments→vault charge request. Vault is
// the only system that sees PAN — it dereferences the token and
// makes the processor call.
type VaultChargeRequest struct {
	Token       string
	ProcessorID string
	Currency    string
	AmountCents int64
}

// VaultChargeResponse is the vault→payments charge response.
type VaultChargeResponse struct {
	ProcessorRef string
	Status       string
}

// IAMClient is the inter-subsystem interface to IAM. Co-resident:
// direct Go call. Split: ZAP-RPC.
type IAMClient interface {
	VerifyJWT(ctx context.Context, bearer string) (Claims, error)
	GetUser(ctx context.Context, userID string) (*User, error)
	GetOrg(ctx context.Context, orgID string) (*Org, error)
}

// KMSClient is the inter-subsystem interface to KMS.
type KMSClient interface {
	GetSecret(ctx context.Context, ref string) ([]byte, error)
	PutSecret(ctx context.Context, ref string, value []byte) error
	Sign(ctx context.Context, keyRef string, payload []byte) ([]byte, error)
}

// BaseClient is the inter-subsystem interface to Base.
type BaseClient interface {
	Open(ctx context.Context, orgID, serviceName string) (DBHandle, error)
}

// CommerceClient is the inter-subsystem interface to Commerce.
type CommerceClient interface {
	GetTenantConfig(ctx context.Context, orgID string) (*TenantConfig, error)
}

// AIClient is the inter-subsystem interface to AI.
type AIClient interface {
	ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
}

// O11yClient is the inter-subsystem interface to o11y.
type O11yClient interface {
	Counter(name string, tags ...string) Counter
	Timing(name string, tags ...string) Timing
	Span(ctx context.Context, name string) (context.Context, Span)
}

// VFSClient is the inter-subsystem interface to vfs.
type VFSClient interface {
	Put(ctx context.Context, key string, payload []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// MQClient is the inter-subsystem interface to mq.
type MQClient interface {
	Publish(ctx context.Context, subject string, payload []byte) error
	Subscribe(ctx context.Context, subject string, handler func([]byte) error) error
}

// PaymentsClient is the inter-subsystem interface to payments. Always
// ZAP-RPC; never co-resident (PCI scope isolation).
type PaymentsClient interface {
	CreateIntent(ctx context.Context, req *IntentRequest) (*IntentResponse, error)
	ConfirmIntent(ctx context.Context, intentID string) (*IntentResponse, error)
	GetIntentStatus(ctx context.Context, intentID string) (*IntentStatus, error)
}

// VaultClient is the inter-subsystem interface to vault. The ONLY
// system that touches PAN. Always ZAP-RPC; never co-resident.
type VaultClient interface {
	Charge(ctx context.Context, req *VaultChargeRequest) (*VaultChargeResponse, error)
}

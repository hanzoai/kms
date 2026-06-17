package clients

import (
	"context"
	"fmt"

	"github.com/hanzoai/cloud/types"
)

// disabledErr is the error every "dep not wired" client returns. The
// subsystem name is the field of cloud.Deps that resolved to a
// disabled client; the caller is the subsystem that asked for the dep
// (used for the "X needs Y but Y isn't enabled" log message at mount
// time).
type disabledErr struct{ subsystem string }

func (e *disabledErr) Error() string {
	return fmt.Sprintf("cloud: dep %q is disabled — enable the subsystem or configure its RPC endpoint", e.subsystem)
}

// IsDisabled reports whether err originated from a disabled client.
// Subsystem mount code can use this to log a friendly warning instead
// of cascading a 500.
func IsDisabled(err error) bool {
	_, ok := err.(*disabledErr)
	return ok
}

// --- one type per disabled client ----------------------------------------

type disabledIAM struct{}

func (disabledIAM) VerifyJWT(_ context.Context, _ string) (types.Claims, error) {
	return types.Claims{}, &disabledErr{"iam"}
}
func (disabledIAM) GetUser(_ context.Context, _ string) (*types.User, error) {
	return nil, &disabledErr{"iam"}
}
func (disabledIAM) GetOrg(_ context.Context, _ string) (*types.Org, error) {
	return nil, &disabledErr{"iam"}
}

type disabledKMS struct{}

func (disabledKMS) GetSecret(_ context.Context, _ string) ([]byte, error) {
	return nil, &disabledErr{"kms"}
}
func (disabledKMS) PutSecret(_ context.Context, _ string, _ []byte) error {
	return &disabledErr{"kms"}
}
func (disabledKMS) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, &disabledErr{"kms"}
}

type disabledBase struct{}

func (disabledBase) Open(_ context.Context, _, _ string) (types.DBHandle, error) {
	return nil, &disabledErr{"base"}
}

type disabledCommerce struct{}

func (disabledCommerce) GetTenantConfig(_ context.Context, _ string) (*types.TenantConfig, error) {
	return nil, &disabledErr{"commerce"}
}

type disabledAI struct{}

func (disabledAI) ChatCompletion(_ context.Context, _ *types.ChatRequest) (*types.ChatResponse, error) {
	return nil, &disabledErr{"ai"}
}

type disabledO11y struct{}

func (disabledO11y) Counter(_ string, _ ...string) types.Counter { return noopCounter{} }
func (disabledO11y) Timing(_ string, _ ...string) types.Timing   { return noopTiming{} }
func (disabledO11y) Span(ctx context.Context, _ string) (context.Context, types.Span) {
	return ctx, noopSpan{}
}

type disabledVFS struct{}

func (disabledVFS) Put(_ context.Context, _ string, _ []byte) error {
	return &disabledErr{"vfs"}
}
func (disabledVFS) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, &disabledErr{"vfs"}
}

type disabledMQ struct{}

func (disabledMQ) Publish(_ context.Context, _ string, _ []byte) error {
	return &disabledErr{"mq"}
}
func (disabledMQ) Subscribe(_ context.Context, _ string, _ func([]byte) error) error {
	return &disabledErr{"mq"}
}

type disabledPayments struct{}

func (disabledPayments) CreateIntent(_ context.Context, _ *types.IntentRequest) (*types.IntentResponse, error) {
	return nil, &disabledErr{"payments"}
}
func (disabledPayments) ConfirmIntent(_ context.Context, _ string) (*types.IntentResponse, error) {
	return nil, &disabledErr{"payments"}
}
func (disabledPayments) GetIntentStatus(_ context.Context, _ string) (*types.IntentStatus, error) {
	return nil, &disabledErr{"payments"}
}

type disabledVault struct{}

func (disabledVault) Charge(_ context.Context, _ *types.VaultChargeRequest) (*types.VaultChargeResponse, error) {
	return nil, &disabledErr{"vault"}
}

// --- noop telemetry handles so callers don't have to nil-check ----------

type noopCounter struct{}

func (noopCounter) Inc(_ int64) {}

type noopTiming struct{}

func (noopTiming) Observe(_ float64) {}

type noopSpan struct{}

func (noopSpan) End() {}

// --- constructors --------------------------------------------------------

// DisabledIAM returns a fail-closed IAM client.
func DisabledIAM() types.IAMClient { return disabledIAM{} }

// DisabledKMS returns a fail-closed KMS client.
func DisabledKMS() types.KMSClient { return disabledKMS{} }

// DisabledBase returns a fail-closed Base client.
func DisabledBase() types.BaseClient { return disabledBase{} }

// DisabledCommerce returns a fail-closed Commerce client.
func DisabledCommerce() types.CommerceClient { return disabledCommerce{} }

// DisabledAI returns a fail-closed AI client.
func DisabledAI() types.AIClient { return disabledAI{} }

// DisabledO11y returns an O11y client that emits to /dev/null. Used
// when o11y isn't mounted; subsystems get no-op metrics rather than
// nil deref or error spam.
func DisabledO11y() types.O11yClient { return disabledO11y{} }

// DisabledVFS returns a fail-closed VFS client.
func DisabledVFS() types.VFSClient { return disabledVFS{} }

// DisabledMQ returns a fail-closed MQ client.
func DisabledMQ() types.MQClient { return disabledMQ{} }

// DisabledPayments returns a fail-closed Payments client.
func DisabledPayments() types.PaymentsClient { return disabledPayments{} }

// DisabledVault returns a fail-closed Vault client.
func DisabledVault() types.VaultClient { return disabledVault{} }

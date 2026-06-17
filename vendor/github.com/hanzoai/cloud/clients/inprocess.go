package clients

import (
	"github.com/hanzoai/cloud/types"
)

// InProcess wraps a co-resident subsystem implementation as the
// canonical cloud.<Subsystem>Client. The wrapper is a typed
// pass-through: calls hit the in-process implementation directly via
// Go method dispatch with zero marshalling and zero network hops.
//
// This is the inter-subsystem default when subsystems mount on the
// same zip.App (the common HIP-0106 case). Subsystems that pass their
// own concrete *T to BuildDeps get that *T back through the typed
// interface — no per-subsystem glue per the "one way" rule.
//
// Per-subsystem constructors (one per cloud client interface):
//
//   IAMInProcess(impl types.IAMClient) types.IAMClient
//   KMSInProcess(impl types.KMSClient) types.KMSClient
//   ... etc.
//
// They are intentionally trivial; the value of the wrapper is the
// type-system enforcement that "in-process" and "RPC" satisfy the
// same interface — subsystem code never branches on the mode.

// IAMInProcess wraps a co-resident IAM implementation. Subsystems
// call deps.IAM.VerifyJWT(...) etc. without knowing whether IAM is
// in-process or remote.
func IAMInProcess(impl types.IAMClient) types.IAMClient { return impl }

// KMSInProcess wraps a co-resident KMS implementation.
func KMSInProcess(impl types.KMSClient) types.KMSClient { return impl }

// BaseInProcess wraps a co-resident Base implementation.
func BaseInProcess(impl types.BaseClient) types.BaseClient { return impl }

// CommerceInProcess wraps a co-resident Commerce implementation.
func CommerceInProcess(impl types.CommerceClient) types.CommerceClient { return impl }

// AIInProcess wraps a co-resident AI implementation.
func AIInProcess(impl types.AIClient) types.AIClient { return impl }

// O11yInProcess wraps a co-resident O11y implementation.
func O11yInProcess(impl types.O11yClient) types.O11yClient { return impl }

// VFSInProcess wraps a co-resident VFS implementation.
func VFSInProcess(impl types.VFSClient) types.VFSClient { return impl }

// MQInProcess wraps a co-resident MQ implementation.
func MQInProcess(impl types.MQClient) types.MQClient { return impl }

// Payments is NEVER in-process — see PaymentsRPCAt for the only
// allowed wiring. Vault is the same. The interfaces exist on
// cloud.Deps so subsystems can call them, but the underlying client
// always reaches the split-deployed PCI process via ZAP RPC.

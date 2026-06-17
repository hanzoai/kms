// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// consensus_auth.go — consensus-native authorization for ZAP secret opcodes.
//
// The CSV ACL approach is dead. Authority lives in Lux consensus:
//
//  - Identity: every caller signs its envelope with a mnemonic-derived
//    ML-DSA-65 key whose NodeID is the canonical SHAKE256-384 digest
//    (luxfi/keys.ServiceIdentity + luxfi/ids.NodeIDSchemeMLDSA65).
//
//  - Authority: consensus says which NodeIDs are currently authorized
//    for which path under which cert profile. The Polaris cert
//    (quasar.ComposePolaris) is the threshold attestation that binds a
//    validator set to a round; an authorizer asks "is this NodeID a
//    member of a current Polaris-attested authority?" before releasing
//    a secret.
//
//  - Capability: writes require an admin overlay. The overlay is a
//    pure-function predicate the operator wires at boot — it is NOT a
//    CSV the kmsd maintains. The canonical implementation reads its
//    admin set from the same consensus authority, scoped to the
//    "operator" path prefix.
//
// kmsd boot wires a single ConsensusAuthorizer; tests pass a Fake.
// There is no fallback ACL. If consensus is unreachable the server
// fails closed (Authorize returns false + a structured reason).

package zapserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/ids"
)

// Op is the wire opcode under authorization. Re-exported as a typed
// value so the authorizer surface is independent of the package-level
// opcode constants (handlers still use the raw uint16 — this is the
// boundary type).
type Op uint16

// Authorized opcodes mirror the four exported in server.go. Kept as
// typed aliases so a refactor of the wire constants does not silently
// widen the authorizer's contract.
const (
	OpAuthGet    Op = Op(OpSecretGet)
	OpAuthPut    Op = Op(OpSecretPut)
	OpAuthList   Op = Op(OpSecretList)
	OpAuthDelete Op = Op(OpSecretDelete)
)

// IsWrite reports whether the opcode is a mutation. Used by the
// in-process authorizer to gate writes behind the admin overlay.
func (o Op) IsWrite() bool {
	switch o {
	case OpAuthPut, OpAuthDelete:
		return true
	default:
		return false
	}
}

// String returns "OpSecretGet" / "OpSecretPut" / etc. so audit logs
// stay readable without leaking opcode bytes.
func (o Op) String() string {
	switch o {
	case OpAuthGet:
		return "OpSecretGet"
	case OpAuthPut:
		return "OpSecretPut"
	case OpAuthList:
		return "OpSecretList"
	case OpAuthDelete:
		return "OpSecretDelete"
	}
	return fmt.Sprintf("Op_0x%04X", uint16(o))
}

// Identity is the verified service identity carried by a request. The
// envelope-signature verifier populates this before invoking the
// authorizer — the authorizer does not re-verify the signature; it
// asks "is this verified NodeID authorized for this op on this path?"
type Identity struct {
	// NodeID is the 20-byte canonical NodeID derived from the service
	// mnemonic + path via luxfi/keys.NewServiceIdentity. Map-key safe.
	NodeID ids.NodeID

	// FullDigest is the 48-byte SHAKE256-384 commitment to the
	// identity. Bound into the envelope signature; carried here so an
	// audit log row can record the strong commitment instead of the
	// 20-byte prefix alone.
	FullDigest ids.FullDigest

	// ServicePath is the canonical path string the identity was
	// derived from, as declared by the caller. Verified by the
	// envelope-signature path before this struct is constructed.
	ServicePath string
}

// String returns a stable diagnostic string. Not a wire form.
func (i Identity) String() string {
	if i.ServicePath != "" {
		return fmt.Sprintf("%s@%s", i.ServicePath, i.NodeID.String())
	}
	return i.NodeID.String()
}

// Decision is the structured authorizer outcome. A `false` decision
// always carries a Reason so audit logs and client error responses
// can attribute the deny without leaking authorizer internals.
type Decision struct {
	Allow  bool
	Reason string
}

// Allow returns an Allow decision with the given reason.
func Allow(reason string) Decision { return Decision{Allow: true, Reason: reason} }

// Deny returns a Deny decision with the given reason.
func Deny(reason string) Decision { return Decision{Allow: false, Reason: reason} }

// ConsensusAuthorizer is the contract the kmsd talks to. Production
// impls dial Lux consensus and return whatever it says; tests pass a
// Fake. There is no "fall back to a local ACL" branch.
//
// Authorize MUST be safe for concurrent use. The kmsd calls it on
// every request; a serial impl would bottleneck the secret surface.
type ConsensusAuthorizer interface {
	// Authorize returns Allow if the identity may invoke op on path.
	// Path is the canonical "/"-joined string the caller addresses
	// (e.g. "hanzo/kms-operator") with no leading or trailing slash.
	//
	// On consensus unreachable / transient error the impl returns
	// (Deny, err). The kmsd treats this as fail-closed and surfaces
	// statusForbid on the wire.
	Authorize(ctx context.Context, ident Identity, path string, op Op) (Decision, error)
}

// AuthorityProvider returns the set of NodeIDs the consensus layer
// currently attests as members of the named authority. The kmsd holds
// one AuthorityProvider per authority name (typically "validators" and
// "operator"); the in-process authorizer composes them.
//
// Implementations MUST be cheap to call (the kmsd may invoke them on
// every request). The InProcessAuthorizer caches per-authority results
// for a short TTL; that cache is the only ambient state in the auth
// surface.
type AuthorityProvider interface {
	// Members returns the current authority set. The returned slice
	// MUST NOT be mutated by the caller; the provider may share the
	// underlying array.
	Members(ctx context.Context) ([]ids.NodeID, error)
}

// AuthorityProviderFunc is a function adapter for AuthorityProvider.
type AuthorityProviderFunc func(ctx context.Context) ([]ids.NodeID, error)

// Members runs the wrapped function.
func (f AuthorityProviderFunc) Members(ctx context.Context) ([]ids.NodeID, error) {
	return f(ctx)
}

// InProcessAuthorizerConfig wires the in-process ConsensusAuthorizer
// from two authority providers and an optional cache TTL.
//
// Validators is the broad read authority — every member may Get and
// List under any path. Operator is the write authority — only its
// members may Put and Delete. Both providers are interrogated on
// every request; results are cached per-authority for CacheTTL (0 =
// no cache, every call dials the provider).
type InProcessAuthorizerConfig struct {
	// Validators is the broad read authority. Required.
	Validators AuthorityProvider

	// Operator is the write authority. Required.
	Operator AuthorityProvider

	// CacheTTL is the per-authority result TTL. 0 disables caching
	// (every request dials both providers). 30s is the production
	// default — the kmsd reconfigures the cache via the operator's
	// reconciliation interval, not by mutating this field after boot.
	CacheTTL time.Duration
}

// NewInProcessAuthorizer wires an authorizer over two AuthorityProviders.
// Returns an error if either provider is nil.
func NewInProcessAuthorizer(cfg InProcessAuthorizerConfig) (*InProcessAuthorizer, error) {
	if cfg.Validators == nil {
		return nil, errors.New("zapserver: validator authority provider is required")
	}
	if cfg.Operator == nil {
		return nil, errors.New("zapserver: operator authority provider is required")
	}
	return &InProcessAuthorizer{
		validators: cfg.Validators,
		operator:   cfg.Operator,
		cacheTTL:   cfg.CacheTTL,
	}, nil
}

// InProcessAuthorizer is the canonical ConsensusAuthorizer. The "in
// process" name means the policy composition runs in the kmsd process;
// the AUTHORITY data still comes from consensus (via the providers).
type InProcessAuthorizer struct {
	validators AuthorityProvider
	operator   AuthorityProvider
	cacheTTL   time.Duration

	mu             sync.RWMutex
	validatorsSet  map[ids.NodeID]struct{}
	validatorsRead time.Time
	operatorSet    map[ids.NodeID]struct{}
	operatorRead   time.Time
}

// Authorize is the entry point. Decision order:
//
//  1. Reject ops outside the four secret opcodes.
//  2. Look up the identity's NodeID in the validator authority. Miss
//     → Deny("not-a-validator").
//  3. For writes: additionally look up the NodeID in the operator
//     authority. Miss → Deny("not-an-operator").
//  4. Allow.
//
// On provider error: Deny + error so the caller can log the transient
// failure while the wire still sees a clean forbid.
func (a *InProcessAuthorizer) Authorize(ctx context.Context, ident Identity, path string, op Op) (Decision, error) {
	switch op {
	case OpAuthGet, OpAuthPut, OpAuthList, OpAuthDelete:
	default:
		return Deny(fmt.Sprintf("unknown-opcode-%s", op.String())), nil
	}

	if isEmptyNodeID(ident.NodeID) {
		return Deny("missing-identity"), nil
	}

	validators, err := a.snapshotValidators(ctx)
	if err != nil {
		return Deny("validator-authority-unreachable"), err
	}
	if _, ok := validators[ident.NodeID]; !ok {
		return Deny("not-a-validator"), nil
	}

	if !op.IsWrite() {
		return Allow("validator-read"), nil
	}

	operators, err := a.snapshotOperator(ctx)
	if err != nil {
		return Deny("operator-authority-unreachable"), err
	}
	if _, ok := operators[ident.NodeID]; !ok {
		return Deny("not-an-operator"), nil
	}
	_ = strings.TrimSpace(path) // path bound at envelope verify; reserved
	return Allow("operator-write"), nil
}

// snapshotValidators returns the current validator authority. Cached
// up to a.cacheTTL.
func (a *InProcessAuthorizer) snapshotValidators(ctx context.Context) (map[ids.NodeID]struct{}, error) {
	a.mu.RLock()
	if a.cacheTTL > 0 && a.validatorsSet != nil && time.Since(a.validatorsRead) < a.cacheTTL {
		set := a.validatorsSet
		a.mu.RUnlock()
		return set, nil
	}
	a.mu.RUnlock()

	members, err := a.validators.Members(ctx)
	if err != nil {
		return nil, fmt.Errorf("validators: %w", err)
	}
	set := toNodeIDSet(members)
	a.mu.Lock()
	a.validatorsSet = set
	a.validatorsRead = time.Now()
	a.mu.Unlock()
	return set, nil
}

// snapshotOperator returns the current operator authority. Cached up
// to a.cacheTTL.
func (a *InProcessAuthorizer) snapshotOperator(ctx context.Context) (map[ids.NodeID]struct{}, error) {
	a.mu.RLock()
	if a.cacheTTL > 0 && a.operatorSet != nil && time.Since(a.operatorRead) < a.cacheTTL {
		set := a.operatorSet
		a.mu.RUnlock()
		return set, nil
	}
	a.mu.RUnlock()

	members, err := a.operator.Members(ctx)
	if err != nil {
		return nil, fmt.Errorf("operator: %w", err)
	}
	set := toNodeIDSet(members)
	a.mu.Lock()
	a.operatorSet = set
	a.operatorRead = time.Now()
	a.mu.Unlock()
	return set, nil
}

// toNodeIDSet builds a constant-time-lookup set from a slice. The
// returned map is internal; callers receive a read-only view via
// snapshot*.
func toNodeIDSet(members []ids.NodeID) map[ids.NodeID]struct{} {
	out := make(map[ids.NodeID]struct{}, len(members))
	for _, id := range members {
		out[id] = struct{}{}
	}
	return out
}

// isEmptyNodeID reports whether the NodeID is the all-zero value. The
// envelope verifier sets ident.NodeID from the signer's pubkey; an
// empty value here means the wire path skipped the verification
// (forward-compat bridge) and we MUST deny.
func isEmptyNodeID(n ids.NodeID) bool {
	for _, b := range n {
		if b != 0 {
			return false
		}
	}
	return true
}

// StaticAuthorityProvider returns the supplied NodeID set on every
// call. Used at boot when the operator hands the kmsd a consensus
// snapshot via env / file; the snapshot is refreshed by re-applying
// the operator manifest, not by the kmsd polling.
//
// Note: this is NOT a CSV ACL. The static set is a consensus snapshot;
// the snapshot's authority is "consensus said these NodeIDs were the
// authority members at time T". Refresh = re-apply.
type StaticAuthorityProvider struct {
	members []ids.NodeID
}

// NewStaticAuthorityProvider returns a provider over the given NodeID
// set. Defensive copy: the caller may mutate the slice after this
// returns without affecting the provider.
func NewStaticAuthorityProvider(members []ids.NodeID) *StaticAuthorityProvider {
	c := make([]ids.NodeID, len(members))
	copy(c, members)
	return &StaticAuthorityProvider{members: c}
}

// Members returns the static snapshot.
func (s *StaticAuthorityProvider) Members(_ context.Context) ([]ids.NodeID, error) {
	return s.members, nil
}

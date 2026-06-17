// Package clients holds the canonical ZAP-typed inter-subsystem
// clients used by cloud.Deps.
//
// Per HIP-0106 "Inter-subsystem contract": ZAP (the Hanzo native binary
// protocol). Every subsystem ships its public interface as a .zap
// schema; zapc generates Go bindings; cloud wires the in-process
// ZAP-typed Go interfaces when subsystems are co-resident, falls
// back to ZAP RPC over the wire when split.
//
// This package provides three factories per subsystem:
//
//   - <Subsystem>InProcess(impl): wraps a co-resident implementation
//     as a ZAP-typed client. Direct Go method calls. No marshalling,
//     no network.
//
//   - <Subsystem>RPC(addr): builds a ZAP-RPC client targeting a
//     remote endpoint (used in split deployments).
//
//   - Disabled<Subsystem>(): returns a typed nil that fails closed
//     with a clear error message when called. Lets subsystem mount
//     code defensively detect "the dep isn't wired" without nil
//     dereferences.
//
// cloud.BuildDeps picks the right one for each subsystem based on
// cfg.Enabled(name) and the configured RPC endpoint.
//
// Note (zapc): the ZAP RPC wire format is exercised by hanzoai/zap
// (Rust impl) and hanzoai/zap-go (Go bindings). The current Go
// scaffolding here ships stubs sufficient to enforce the contract;
// the actual RPC dispatch sits behind a transport layer that
// subsystems will swap in as each subsystem ships its .zap schema +
// zapc-generated client. TODO(zapc-gen) markers identify the
// expansion points.
package clients

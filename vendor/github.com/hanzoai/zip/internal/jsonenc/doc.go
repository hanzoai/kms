// Package jsonenc is zip's single JSON entry point.
//
// All JSON marshalling in zip — c.JSON(), c.Bind().Body(), typed.go's
// generic In/Out handlers, module.go's extension envelope — goes
// through Marshal / Unmarshal here. There is no other JSON path.
//
// Implementation: two build-tag-gated files swap the body. When the
// binary is compiled with GOEXPERIMENT=jsonv2, the import resolver
// can reach the stdlib's encoding/json/v2 package and the v2.go file
// is selected; otherwise v1.go is selected and we fall back to
// stdlib encoding/json. Either way callers see Marshal / Unmarshal —
// no v1/v2 branching in zip's own code.
//
// Per HIP-0106 "Wire protocol stack": JSON is the boundary format
// (ingress → gateway → subsystem handler). Inter-subsystem calls use
// ZAP-typed Go values. JSON marshalling happens at most once per
// request, at the subsystem handler boundary, through THIS package.
//
// Brand policy: no third-party JSON library is allowed. Stdlib only.
// goccy/go-json, sonic, jsoniter, and friends are NOT permitted in
// the Hanzo Go stack — see HIP-0106 canonical Hanzo Go stack.
package jsonenc

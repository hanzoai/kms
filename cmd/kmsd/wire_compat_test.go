package main

import (
	"testing"

	"github.com/luxfi/kms/pkg/zapserver"
)

// TestWireCompatibility_OpcodesMatchLuxfi pins the canonical luxfi/kms ZAP
// opcodes so any drift in the upstream surface fails this build. The
// hanzo-kms server registers exactly these opcodes via zapserver.Register —
// see cmd/kmsd/main.go where we call zs.Register(n).
//
// The numeric values here are part of the public wire format. Any change is
// a breaking client/server compatibility break with luxfi clients, and any
// such change must land in luxfi/kms first, not here.
func TestWireCompatibility_OpcodesMatchLuxfi(t *testing.T) {
	cases := []struct {
		name string
		got  uint16
		want uint16
	}{
		{"OpSecretGet", zapserver.OpSecretGet, 0x0040},
		{"OpSecretPut", zapserver.OpSecretPut, 0x0041},
		{"OpSecretList", zapserver.OpSecretList, 0x0042},
		{"OpSecretDelete", zapserver.OpSecretDelete, 0x0043},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s opcode drifted from canonical luxfi/kms: got 0x%04X want 0x%04X",
				c.name, c.got, c.want)
		}
	}
}

//go:build !goexperiment.jsonv2

package jsonenc

import (
	"encoding/json"
)

// Variant reports which JSON implementation backs this build. v2 is
// reachable only under `GOEXPERIMENT=jsonv2`; without that flag the
// stdlib encoding/json/v2 import does not resolve at compile time and
// zip falls back to encoding/json v1. zip.New() logs Variant once at
// startup so operators can spot a missing GOEXPERIMENT in CI.
const Variant = "encoding/json"

// Marshal encodes v as JSON via encoding/json (v1).
func Marshal(v any) ([]byte, error) { return json.Marshal(v) }

// Unmarshal decodes data into v via encoding/json (v1).
func Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

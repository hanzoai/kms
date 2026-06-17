//go:build goexperiment.jsonv2

package jsonenc

import (
	jsonv2 "encoding/json/v2"
)

// Variant reports which JSON implementation backs this build. zip.New()
// logs this once at startup so operators can confirm v2 is active.
const Variant = "encoding/json/v2"

// Marshal encodes v as JSON via encoding/json/v2.
func Marshal(v any) ([]byte, error) { return jsonv2.Marshal(v) }

// Unmarshal decodes data into v via encoding/json/v2.
func Unmarshal(data []byte, v any) error { return jsonv2.Unmarshal(data, v) }

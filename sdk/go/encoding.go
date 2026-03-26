// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kms

import "encoding/base64"

// base64URLEncode encodes data to URL-safe base64 without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes URL-safe base64 without padding.
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

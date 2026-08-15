// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package kmsclient

import "testing"

// The server mounts /v1/kms/secrets and reads the org from the credential. A URL
// carrying an org segment reaches nothing — and would be asking the server to
// take the caller's word for the tenant, which is the one thing it must not do.
func TestSecretURLCarriesNoOrgSegment(t *testing.T) {
	c := &Client{endpoint: "https://api.hanzo.ai", org: "hanzo"}

	got := c.secretPath("", "OPENROUTER_API_KEY")
	if want := "https://api.hanzo.ai/v1/kms/secrets/OPENROUTER_API_KEY"; got != want {
		t.Fatalf("secretPath = %q, want %q", got, want)
	}
	if nested := c.secretPath("ci", "DB"); nested != "https://api.hanzo.ai/v1/kms/secrets/ci/DB" {
		t.Fatalf("a nested path should ride under secrets, got %q", nested)
	}
}

// The org travels in the credential, so naming a different one changes nothing
// about where the request goes. If this ever fails, the client has started
// letting a caller address another tenant by writing its name down.
func TestTheOrgDoesNotSteerTheURL(t *testing.T) {
	mine := (&Client{endpoint: "https://api.hanzo.ai", org: "hanzo"}).secretPath("", "K")
	theirs := (&Client{endpoint: "https://api.hanzo.ai", org: "someone-else"}).secretPath("", "K")
	if mine != theirs {
		t.Fatalf("the org steered the URL: %q vs %q", mine, theirs)
	}
}

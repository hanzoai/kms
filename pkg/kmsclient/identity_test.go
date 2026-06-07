// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kmsclient

import (
	"os"
	"strings"
	"testing"
)

const idTestMnemonic = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

// TestIdentity_DeterministicNodeID — same (mnemonic, path) ↔ same
// NodeID. The scale-out story depends on this; every replica of a
// service derives the same NodeID so consensus registers one entry,
// not N.
func TestIdentity_DeterministicNodeID(t *testing.T) {
	a, err := NewIdentity(idTestMnemonic, "hanzo/auto")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Wipe()
	b, err := NewIdentity(idTestMnemonic, "hanzo/auto")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Wipe()
	if a.NodeID != b.NodeID {
		t.Errorf("NodeID drift: %s vs %s", a.NodeID, b.NodeID)
	}
	if a.Header.NodeID != b.Header.NodeID {
		t.Errorf("Header NodeID drift")
	}
}

// TestIdentity_DistinctPaths — same mnemonic, different path → distinct
// NodeID. Each service in the cluster has its own identity even though
// they all derive from the same operator-bootstrapped mnemonic seed.
func TestIdentity_DistinctPaths(t *testing.T) {
	a, err := NewIdentity(idTestMnemonic, "hanzo/auto")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Wipe()
	b, err := NewIdentity(idTestMnemonic, "hanzo/commerce")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Wipe()
	if a.NodeID == b.NodeID {
		t.Errorf("paths must yield distinct NodeIDs")
	}
}

// TestIdentityFromEnv_LuxMnemonic — LUX_MNEMONIC drives the derivation.
func TestIdentityFromEnv_LuxMnemonic(t *testing.T) {
	t.Setenv("LUX_MNEMONIC", idTestMnemonic)
	_ = os.Unsetenv("MNEMONIC") // ensure LUX wins
	id, err := IdentityFromEnv("hanzo/auto")
	if err != nil {
		t.Fatalf("IdentityFromEnv: %v", err)
	}
	defer id.Wipe()
	expected, err := NewIdentity(idTestMnemonic, "hanzo/auto")
	if err != nil {
		t.Fatal(err)
	}
	defer expected.Wipe()
	if id.NodeID != expected.NodeID {
		t.Errorf("LUX_MNEMONIC NodeID mismatch")
	}
}

// TestIdentityFromEnv_FallsBackToMnemonic — MNEMONIC is the legacy name
// retained for compatibility with luxd's existing pattern.
func TestIdentityFromEnv_FallsBackToMnemonic(t *testing.T) {
	t.Setenv("LUX_MNEMONIC", "")
	t.Setenv("MNEMONIC", idTestMnemonic)
	id, err := IdentityFromEnv("hanzo/auto")
	if err != nil {
		t.Fatalf("IdentityFromEnv (fallback): %v", err)
	}
	defer id.Wipe()
}

// TestIdentityFromEnv_RequiresOneOf — both env vars empty fails.
func TestIdentityFromEnv_RequiresOneOf(t *testing.T) {
	t.Setenv("LUX_MNEMONIC", "")
	t.Setenv("MNEMONIC", "")
	if _, err := IdentityFromEnv("hanzo/auto"); err == nil ||
		!strings.Contains(err.Error(), "LUX_MNEMONIC") {
		t.Fatalf("expected LUX_MNEMONIC error, got %v", err)
	}
}

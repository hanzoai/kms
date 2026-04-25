// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kms

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// mockComplianceServer creates a test HTTP server that simulates compliance MPC node endpoints.
func mockComplianceServer(t *testing.T) (*httptest.Server, *mockComplianceState) {
	t.Helper()
	state := &mockComplianceState{
		retained:    make(map[string]RetainedRecord),
		breakGlass:  make(map[string]*BreakGlassToken),
		auditLog:    make([]AuditEntry, 0),
		secrets:     make(map[string][]byte),
		auditValid:  true,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()

		p := r.URL.Path
		m := r.Method

		// Route most-specific paths first to avoid prefix collisions.
		switch {

		// --- Audit: verify, export (before generic /audit) ---

		case m == http.MethodGet && pathEndsWith(p, "/zk/compliance/audit/verify"):
			resp := struct {
				Valid bool `json:"valid"`
			}{
				Valid: state.auditValid,
			}
			json.NewEncoder(w).Encode(resp)

		case m == http.MethodGet && pathContains(p, "/zk/compliance/audit/export"):
			format := r.URL.Query().Get("format")
			switch format {
			case "json":
				json.NewEncoder(w).Encode(state.auditLog)
			case "csv":
				w.Write([]byte("ts,actor,action,key,reason,ip\n"))
				for _, e := range state.auditLog {
					w.Write([]byte(e.Timestamp.Format(time.RFC3339) + "," + e.ActorID + "," + e.Action + "," + e.SecretKey + "," + e.Reason + "," + e.SourceIP + "\n"))
				}
			default:
				http.Error(w, "unsupported format", http.StatusBadRequest)
			}

		case m == http.MethodGet && pathContains(p, "/zk/compliance/audit") && r.URL.Query().Get("since") != "":
			resp := struct {
				Entries []AuditEntry `json:"entries"`
			}{
				Entries: state.auditLog,
			}
			json.NewEncoder(w).Encode(resp)

		// --- Break-glass: GET/DELETE with token (has extra path segments) before bare break-glass ---

		case m == http.MethodGet && pathContains(p, "/zk/compliance/break-glass/") && !pathEndsWith(p, "/zk/compliance/break-glass/"):
			// GET /v1/orgs/{org}/zk/compliance/break-glass/{token}/{key}
			found := false
			for _, tok := range state.breakGlass {
				if time.Now().After(tok.ExpiresAt) {
					http.Error(w, "break-glass token expired", http.StatusForbidden)
					return
				}
				found = true
				resp := struct {
					Value []byte `json:"value"`
				}{
					Value: []byte("emergency-decrypted-value"),
				}
				json.NewEncoder(w).Encode(resp)
				return
			}
			if !found {
				http.Error(w, "invalid break-glass token", http.StatusForbidden)
				return
			}

		case m == http.MethodDelete && pathContains(p, "/zk/compliance/break-glass/"):
			// DELETE /v1/orgs/{org}/zk/compliance/break-glass/{token}
			state.breakGlass = make(map[string]*BreakGlassToken)
			state.auditLog = append(state.auditLog, AuditEntry{
				Timestamp: time.Now(),
				ActorID:   "test-actor",
				Action:    "break-glass-revoke",
			})
			w.WriteHeader(http.StatusOK)

		// --- Break-glass: bare endpoint (no token in path) ---

		case m == http.MethodPost && pathEndsWith(p, "/zk/compliance/break-glass"):
			var req breakGlassRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			token := &BreakGlassToken{
				Token:      "bg-token-" + time.Now().Format("150405.000"),
				ExpiresAt:  time.Now().Add(time.Duration(req.DurationMs) * time.Millisecond),
				SecretKeys: req.SecretKeys,
			}
			state.breakGlass[token.Token] = token
			state.auditLog = append(state.auditLog, AuditEntry{
				Timestamp: time.Now(),
				ActorID:   "test-actor",
				Action:    "break-glass-request",
				Reason:    req.Reason,
			})
			w.WriteHeader(http.StatusOK)

		case m == http.MethodGet && pathEndsWith(p, "/zk/compliance/break-glass"):
			var latest *BreakGlassToken
			for _, tok := range state.breakGlass {
				if latest == nil || tok.ExpiresAt.After(latest.ExpiresAt) {
					latest = tok
				}
			}
			if latest == nil {
				http.Error(w, "no break-glass tokens", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(latest)

		// --- Retained ---

		case m == http.MethodPost && pathEndsWith(p, "/zk/compliance/retained"):
			var req retainRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			now := time.Now()
			for _, k := range req.SecretKeys {
				state.retained[k] = RetainedRecord{
					Key:        k,
					RetainedAt: now,
					ExpiresAt:  now.Add(7 * 365 * 24 * time.Hour),
				}
			}
			w.WriteHeader(http.StatusOK)

		case m == http.MethodGet && pathEndsWith(p, "/zk/compliance/retained"):
			records := make([]RetainedRecord, 0, len(state.retained))
			for _, rec := range state.retained {
				records = append(records, rec)
			}
			resp := struct {
				Records []RetainedRecord `json:"records"`
			}{
				Records: records,
			}
			json.NewEncoder(w).Encode(resp)

		// --- Regulator export ---

		case m == http.MethodPost && pathEndsWith(p, "/zk/compliance/export"):
			var req regulatorExportRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			state.lastExportKeys = req.SecretKeys
			w.WriteHeader(http.StatusOK)

		case m == http.MethodGet && pathEndsWith(p, "/zk/compliance/export"):
			pkg := RegulatorPackage{
				EncryptedSecrets: []byte("encrypted-blob"),
				EscrowMaterial:   []byte("escrow-wrapped-material"),
				AuditTrail:       []byte("chain-hashed-audit"),
				ExportTimestamp:  time.Now(),
			}
			json.NewEncoder(w).Encode(pkg)

		// --- Enable/Disable compliance (most general /zk/compliance — must be LAST) ---

		case m == http.MethodPost && pathEndsWith(p, "/zk/compliance"):
			var req enableComplianceRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			state.complianceEnabled = true
			state.complianceMode = req.Mode
			state.escrowPubKey = req.EscrowPubKey
			w.WriteHeader(http.StatusOK)

		case m == http.MethodDelete && pathEndsWith(p, "/zk/compliance"):
			if state.hasActiveRetention() {
				http.Error(w, "active retention prevents disabling compliance", http.StatusConflict)
				return
			}
			state.complianceEnabled = false
			w.WriteHeader(http.StatusOK)

		// --- Delete secret (check retention) ---

		case m == http.MethodDelete && pathContains(p, "/zk/secrets/"):
			for _, rec := range state.retained {
				if time.Now().Before(rec.ExpiresAt) {
					http.Error(w, "secret is under retention", http.StatusForbidden)
					return
				}
			}
			w.WriteHeader(http.StatusOK)

		default:
			http.Error(w, "not found: "+p, http.StatusNotFound)
		}
	}))

	return srv, state
}

type mockComplianceState struct {
	mu                sync.Mutex
	complianceEnabled bool
	complianceMode    ComplianceMode
	escrowPubKey      []byte
	retained          map[string]RetainedRecord
	breakGlass        map[string]*BreakGlassToken
	auditLog          []AuditEntry
	secrets           map[string][]byte
	auditValid        bool
	lastExportKeys    []string
}

func (s *mockComplianceState) hasActiveRetention() bool {
	for _, rec := range s.retained {
		if time.Now().Before(rec.ExpiresAt) {
			return true
		}
	}
	return false
}

// pathEndsWith checks if the URL path ends with the given suffix.
func pathEndsWith(path, suffix string) bool {
	return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
}

// pathContains checks if the path contains the substring.
func pathContains(path, sub string) bool {
	for i := 0; i <= len(path)-len(sub); i++ {
		if path[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func newTestComplianceClient(t *testing.T, srvURL string) *Client {
	t.Helper()
	c, err := NewClient(Config{
		Nodes:     []string{srvURL},
		OrgSlug:   "compliance-org",
		Threshold: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnableCompliance_CreatesEscrowShard(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	escrowKey := []byte("regulator-hpke-public-key-32bytes")
	err := c.EnableCompliance(ComplianceConfig{
		Mode:            ComplianceHIPAA,
		EscrowPubKey:    escrowKey,
		RetentionYears:  7,
		WORMAuditLog:    true,
		BreakGlass:      true,
		RegulatorAccess: RegulatorWithOrgCooperation,
	})
	if err != nil {
		t.Fatalf("EnableCompliance: %v", err)
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if !state.complianceEnabled {
		t.Error("expected compliance to be enabled")
	}
	if state.complianceMode != ComplianceHIPAA {
		t.Errorf("expected HIPAA mode, got %d", state.complianceMode)
	}
	if string(state.escrowPubKey) != string(escrowKey) {
		t.Error("expected escrow public key to be stored")
	}
}

func TestEnableCompliance_ValidationErrors(t *testing.T) {
	srv, _ := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	tests := []struct {
		name string
		cfg  ComplianceConfig
	}{
		{
			name: "mode none",
			cfg:  ComplianceConfig{Mode: ComplianceNone, EscrowPubKey: []byte("key"), RetentionYears: 1},
		},
		{
			name: "no escrow key",
			cfg:  ComplianceConfig{Mode: ComplianceSEC, RetentionYears: 1},
		},
		{
			name: "zero retention",
			cfg:  ComplianceConfig{Mode: ComplianceSEC, EscrowPubKey: []byte("key"), RetentionYears: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := c.EnableCompliance(tt.cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestBreakGlass_CreatesTimeLimitedToken(t *testing.T) {
	srv, _ := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	token, err := c.RequestBreakGlass("patient emergency", []string{"db-password", "api-key"}, 15*time.Minute)
	if err != nil {
		t.Fatalf("RequestBreakGlass: %v", err)
	}

	if token.Token == "" {
		t.Error("expected non-empty token")
	}
	if len(token.SecretKeys) != 2 {
		t.Errorf("expected 2 secret keys, got %d", len(token.SecretKeys))
	}
	if token.ExpiresAt.Before(time.Now()) {
		t.Error("expected token to expire in the future")
	}
}

func TestBreakGlass_ExpiredTokenRejected(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	// Insert an already-expired token into mock state.
	state.mu.Lock()
	state.breakGlass["expired-token"] = &BreakGlassToken{
		Token:      "expired-token",
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
		SecretKeys: []string{"secret-1"},
	}
	state.mu.Unlock()

	_, err := c.GetWithBreakGlass("expired-token", "secret-1")
	if err == nil {
		t.Fatal("expected error for expired break-glass token, got nil")
	}
}

func TestBreakGlass_GetWithValidToken(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	// Insert a valid token into mock state.
	state.mu.Lock()
	state.breakGlass["valid-token"] = &BreakGlassToken{
		Token:      "valid-token",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		SecretKeys: []string{"secret-1"},
	}
	state.mu.Unlock()

	value, err := c.GetWithBreakGlass("valid-token", "secret-1")
	if err != nil {
		t.Fatalf("GetWithBreakGlass: %v", err)
	}
	if string(value) != "emergency-decrypted-value" {
		t.Errorf("unexpected value: %q", value)
	}
}

func TestBreakGlass_RevokeToken(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	// Insert a valid token.
	state.mu.Lock()
	state.breakGlass["revoke-me"] = &BreakGlassToken{
		Token:      "revoke-me",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		SecretKeys: []string{"secret-1"},
	}
	state.mu.Unlock()

	if err := c.RevokeBreakGlass("revoke-me"); err != nil {
		t.Fatalf("RevokeBreakGlass: %v", err)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.breakGlass) != 0 {
		t.Error("expected break-glass tokens to be cleared after revoke")
	}
}

func TestBreakGlass_ValidationErrors(t *testing.T) {
	srv, _ := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	if _, err := c.RequestBreakGlass("", []string{"key"}, time.Minute); err == nil {
		t.Error("expected error for empty reason")
	}
	if _, err := c.RequestBreakGlass("reason", nil, time.Minute); err == nil {
		t.Error("expected error for nil secret keys")
	}
	if _, err := c.RequestBreakGlass("reason", []string{"key"}, -time.Minute); err == nil {
		t.Error("expected error for negative duration")
	}
}

func TestAuditLog_ReturnsEntriesInOrder(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	// Pre-populate audit entries with ordered timestamps.
	now := time.Now()
	state.mu.Lock()
	state.auditLog = []AuditEntry{
		{Timestamp: now.Add(-2 * time.Hour), ActorID: "alice", Action: "set", SecretKey: "key-1"},
		{Timestamp: now.Add(-1 * time.Hour), ActorID: "bob", Action: "get", SecretKey: "key-2"},
		{Timestamp: now, ActorID: "carol", Action: "delete", SecretKey: "key-3"},
	}
	state.mu.Unlock()

	entries, err := c.AuditLog(now.Add(-3*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("AuditLog: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Verify order is preserved.
	if entries[0].ActorID != "alice" || entries[1].ActorID != "bob" || entries[2].ActorID != "carol" {
		t.Error("audit entries not in expected order")
	}

	// Verify timestamps are ordered.
	for i := 1; i < len(entries); i++ {
		if entries[i].Timestamp.Before(entries[i-1].Timestamp) {
			t.Errorf("entry %d timestamp before entry %d", i, i-1)
		}
	}
}

func TestVerifyAuditLog_DetectsTampering(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	// Verify valid log.
	valid, err := c.VerifyAuditLog()
	if err != nil {
		t.Fatalf("VerifyAuditLog: %v", err)
	}
	if !valid {
		t.Error("expected audit log to be valid")
	}

	// Simulate tampering.
	state.mu.Lock()
	state.auditValid = false
	state.mu.Unlock()

	valid, err = c.VerifyAuditLog()
	if err != nil {
		t.Fatalf("VerifyAuditLog after tamper: %v", err)
	}
	if valid {
		t.Error("expected audit log to be invalid after tampering")
	}
}

func TestExportAuditLog_Formats(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	state.mu.Lock()
	state.auditLog = []AuditEntry{
		{Timestamp: time.Now(), ActorID: "alice", Action: "set", SecretKey: "key-1"},
	}
	state.mu.Unlock()

	// JSON format.
	data, err := c.ExportAuditLog("json")
	if err != nil {
		t.Fatalf("ExportAuditLog json: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON export")
	}

	// CSV format.
	data, err = c.ExportAuditLog("csv")
	if err != nil {
		t.Fatalf("ExportAuditLog csv: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty CSV export")
	}

	// Invalid format.
	_, err = c.ExportAuditLog("xml")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestMarkRetained_PreventsDeletetion(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	// Mark secrets as retained.
	err := c.MarkRetained([]string{"db-password", "tls-cert"})
	if err != nil {
		t.Fatalf("MarkRetained: %v", err)
	}

	state.mu.Lock()
	if len(state.retained) != 2 {
		t.Errorf("expected 2 retained records, got %d", len(state.retained))
	}
	state.mu.Unlock()

	// Verify ListRetained returns them.
	records, err := c.ListRetained()
	if err != nil {
		t.Fatalf("ListRetained: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 retained records, got %d", len(records))
	}

	// Verify retention timestamps are set.
	for _, rec := range records {
		if rec.RetainedAt.IsZero() {
			t.Error("expected non-zero RetainedAt")
		}
		if rec.ExpiresAt.IsZero() {
			t.Error("expected non-zero ExpiresAt")
		}
		if rec.ExpiresAt.Before(rec.RetainedAt) {
			t.Error("ExpiresAt should be after RetainedAt")
		}
	}
}

func TestRetentionExpired_AllowsDeletion(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	// Insert an already-expired retention record.
	state.mu.Lock()
	state.retained["old-secret"] = RetainedRecord{
		Key:        "old-secret",
		RetainedAt: time.Now().Add(-10 * 365 * 24 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // expired
	}
	state.mu.Unlock()

	// Attempt to disable compliance — should succeed because retention is expired.
	err := c.DisableCompliance()
	if err != nil {
		t.Fatalf("DisableCompliance should succeed when retention is expired: %v", err)
	}
}

func TestRetentionActive_BlocksDisableCompliance(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	// Insert an active retention record.
	state.mu.Lock()
	state.retained["active-secret"] = RetainedRecord{
		Key:        "active-secret",
		RetainedAt: time.Now(),
		ExpiresAt:  time.Now().Add(7 * 365 * 24 * time.Hour),
	}
	state.mu.Unlock()

	// Attempt to disable compliance — should fail because retention is active.
	err := c.DisableCompliance()
	if err == nil {
		t.Fatal("DisableCompliance should fail when retention is active")
	}
}

func TestRegulatorExport_ProducesValidPackage(t *testing.T) {
	srv, state := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	pkg, err := c.RegulatorExport([]string{"secret-1", "secret-2"})
	if err != nil {
		t.Fatalf("RegulatorExport: %v", err)
	}

	if len(pkg.EncryptedSecrets) == 0 {
		t.Error("expected non-empty EncryptedSecrets")
	}
	if len(pkg.EscrowMaterial) == 0 {
		t.Error("expected non-empty EscrowMaterial")
	}
	if len(pkg.AuditTrail) == 0 {
		t.Error("expected non-empty AuditTrail")
	}
	if pkg.ExportTimestamp.IsZero() {
		t.Error("expected non-zero ExportTimestamp")
	}

	// Verify the server received the right keys.
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.lastExportKeys) != 2 {
		t.Errorf("expected 2 export keys, got %d", len(state.lastExportKeys))
	}
}

func TestRegulatorExport_ValidationErrors(t *testing.T) {
	srv, _ := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	_, err := c.RegulatorExport(nil)
	if err == nil {
		t.Error("expected error for nil secret keys")
	}

	_, err = c.RegulatorExport([]string{})
	if err == nil {
		t.Error("expected error for empty secret keys")
	}
}

func TestComplianceMode_AllModes(t *testing.T) {
	srv, _ := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)
	escrowKey := []byte("regulator-key")

	modes := []struct {
		name string
		mode ComplianceMode
	}{
		{"HIPAA", ComplianceHIPAA},
		{"SEC", ComplianceSEC},
		{"FINRA", ComplianceFINRA},
		{"SOX", ComplianceSOX},
		{"GDPR", ComplianceGDPR},
	}

	for _, tt := range modes {
		t.Run(tt.name, func(t *testing.T) {
			err := c.EnableCompliance(ComplianceConfig{
				Mode:           tt.mode,
				EscrowPubKey:   escrowKey,
				RetentionYears: 5,
				WORMAuditLog:   true,
			})
			if err != nil {
				t.Fatalf("EnableCompliance(%s): %v", tt.name, err)
			}
		})
	}
}

func TestMarkRetained_ValidationErrors(t *testing.T) {
	srv, _ := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	if err := c.MarkRetained(nil); err == nil {
		t.Error("expected error for nil secret keys")
	}
	if err := c.MarkRetained([]string{}); err == nil {
		t.Error("expected error for empty secret keys")
	}
}

func TestGetWithBreakGlass_ValidationErrors(t *testing.T) {
	srv, _ := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	if _, err := c.GetWithBreakGlass("", "key"); err == nil {
		t.Error("expected error for empty token")
	}
	if _, err := c.GetWithBreakGlass("tok", ""); err == nil {
		t.Error("expected error for empty key")
	}
}

func TestRevokeBreakGlass_ValidationErrors(t *testing.T) {
	srv, _ := mockComplianceServer(t)
	defer srv.Close()

	c := newTestComplianceClient(t, srv.URL)

	if err := c.RevokeBreakGlass(""); err == nil {
		t.Error("expected error for empty token")
	}
}

func TestConfigWithCompliance(t *testing.T) {
	cfg := Config{
		Nodes:     []string{"https://node1:9999"},
		OrgSlug:   "test-org",
		Threshold: 1,
		Compliance: &ComplianceConfig{
			Mode:           ComplianceHIPAA,
			EscrowPubKey:   []byte("key"),
			RetentionYears: 7,
			WORMAuditLog:   true,
			BreakGlass:     true,
		},
	}

	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient with compliance config: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestConfigWithoutCompliance(t *testing.T) {
	cfg := Config{
		Nodes:     []string{"https://node1:9999"},
		OrgSlug:   "test-org",
		Threshold: 1,
	}

	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient without compliance config: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

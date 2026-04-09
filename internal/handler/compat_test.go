package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
)

func TestAuthToken(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	req.Header.Set("Authorization", "Bearer test-jwt-token")
	w := httptest.NewRecorder()

	h.AuthToken(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] != "test-jwt-token" {
		t.Fatalf("expected token echo, got %v", resp["token"])
	}
}

func TestGetUser(t *testing.T) {
	h := NewCompat()

	t.Run("no claims", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/user", nil)
		w := httptest.NewRecorder()
		h.GetUser(w, req)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("with claims", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/user", nil)
		ctx := auth.WithClaims(req.Context(), &auth.Claims{
			Sub:   "user-123",
			Email: "z@hanzo.ai",
			Owner: "hanzo",
		})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		h.GetUser(w, req)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp map[string]any
		json.NewDecoder(w.Body).Decode(&resp)
		user := resp["user"].(map[string]any)
		if user["id"] != "user-123" {
			t.Fatalf("expected user-123, got %v", user["id"])
		}
		if user["email"] != "z@hanzo.ai" {
			t.Fatalf("expected z@hanzo.ai, got %v", user["email"])
		}
		if user["superAdmin"] != true {
			t.Fatal("expected superAdmin true")
		}
	})
}

func TestListOrgs(t *testing.T) {
	h := NewCompat()

	t.Run("with owner claim", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/organization", nil)
		ctx := auth.WithClaims(req.Context(), &auth.Claims{Owner: "lux"})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		h.ListOrgs(w, req)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp map[string]any
		json.NewDecoder(w.Body).Decode(&resp)
		orgs := resp["organizations"].([]any)
		if len(orgs) != 1 {
			t.Fatalf("expected 1 org, got %d", len(orgs))
		}
		org := orgs[0].(map[string]any)
		if org["slug"] != "lux" {
			t.Fatalf("expected slug lux, got %v", org["slug"])
		}
	})

	t.Run("empty owner defaults", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/organization", nil)
		ctx := auth.WithClaims(req.Context(), &auth.Claims{Owner: ""})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		h.ListOrgs(w, req)
		var resp map[string]any
		json.NewDecoder(w.Body).Decode(&resp)
		orgs := resp["organizations"].([]any)
		org := orgs[0].(map[string]any)
		if org["slug"] != "default" {
			t.Fatalf("expected slug default, got %v", org["slug"])
		}
	})
}

func TestSelectOrg(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/select-organization", nil)
	req.Header.Set("Authorization", "Bearer org-token")
	w := httptest.NewRecorder()
	h.SelectOrg(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] != "org-token" {
		t.Fatalf("expected org-token, got %v", resp["token"])
	}
}

func TestGetOrg(t *testing.T) {
	h := NewCompat()
	r := chi.NewRouter()
	r.Get("/v1/organization/{orgId}", h.GetOrg)

	req := httptest.NewRequest(http.MethodGet, "/v1/organization/hanzo", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	org := resp["organization"].(map[string]any)
	if org["id"] != "hanzo" {
		t.Fatalf("expected hanzo, got %v", org["id"])
	}
}

func TestOrgSubscription(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodGet, "/v1/organization/hanzo/subscription", nil)
	w := httptest.NewRecorder()
	h.OrgSubscription(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	plan := resp["plan"].(map[string]any)
	if plan["slug"] != "enterprise" {
		t.Fatalf("expected enterprise, got %v", plan["slug"])
	}
	if plan["status"] != "active" {
		t.Fatalf("expected active, got %v", plan["status"])
	}
}

func TestOrgPermissions(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodGet, "/v1/organization/hanzo/permissions", nil)
	w := httptest.NewRecorder()
	h.OrgPermissions(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	rules := resp["packRules"].([]any)
	if len(rules) == 0 {
		t.Fatal("expected non-empty packRules")
	}
	// Verify at least secrets/read exists.
	found := false
	for _, r := range rules {
		rule := r.(map[string]any)
		if rule["subject"] == "secrets" && rule["action"] == "read" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected secrets/read permission in packRules")
	}
}

func TestDuplicateAccounts(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodGet, "/v1/user/duplicate-accounts", nil)
	w := httptest.NewRecorder()
	h.DuplicateAccounts(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	accts := resp["accounts"].([]any)
	if len(accts) != 0 {
		t.Fatalf("expected empty accounts, got %d", len(accts))
	}
}

func TestSubOrganizations(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodGet, "/v1/sub-organizations", nil)
	w := httptest.NewRecorder()
	h.SubOrganizations(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	subs := resp["subOrganizations"].([]any)
	if len(subs) != 0 {
		t.Fatalf("expected empty subOrganizations, got %d", len(subs))
	}
}

func TestSRPLoginStubs(t *testing.T) {
	h := NewCompat()

	t.Run("login1", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login1", nil)
		w := httptest.NewRecorder()
		h.SRPLogin1(w, req)
		if w.Code != 501 {
			t.Fatalf("expected 501, got %d", w.Code)
		}
	})

	t.Run("login2", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login2", nil)
		w := httptest.NewRecorder()
		h.SRPLogin2(w, req)
		if w.Code != 501 {
			t.Fatalf("expected 501, got %d", w.Code)
		}
	})
}

func TestStatusEnhanced(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	w := httptest.NewRecorder()
	h.StatusEnhanced(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] != "Ok" {
		t.Fatalf("expected Ok, got %v", resp["message"])
	}
	if _, ok := resp["date"]; !ok {
		t.Fatal("expected date field")
	}
}

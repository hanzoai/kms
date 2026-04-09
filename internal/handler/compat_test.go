package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/hanzoai/kms/internal/auth"
)

func withClaims(req *http.Request, c *auth.Claims) *http.Request {
	return req.WithContext(auth.WithClaims(req.Context(), c))
}

func TestAuthToken(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	req = withClaims(req, &auth.Claims{Sub: "u1", Email: "a@b.com", Owner: "org"})
	w := httptest.NewRecorder()
	h.AuthToken(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] != "session-valid" {
		t.Fatalf("expected session-valid, got %v", resp["token"])
	}
}

func TestAuthToken_NoClaims(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	w := httptest.NewRecorder()
	h.AuthToken(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
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
		req = withClaims(req, &auth.Claims{Sub: "user-123", Email: "z@test.com", Owner: "org"})
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
	})
}

func TestListOrgs(t *testing.T) {
	h := NewCompat()

	t.Run("with owner claim", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/organization", nil)
		req = withClaims(req, &auth.Claims{Owner: "lux"})
		w := httptest.NewRecorder()
		h.ListOrgs(w, req)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("empty owner defaults", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/organization", nil)
		req = withClaims(req, &auth.Claims{Owner: ""})
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
	req = withClaims(req, &auth.Claims{Sub: "u1", Owner: "org"})
	w := httptest.NewRecorder()
	h.SelectOrg(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] != "session-valid" {
		t.Fatalf("expected session-valid, got %v", resp["token"])
	}
}

func TestGetOrg(t *testing.T) {
	h := NewCompat()
	r := chi.NewRouter()
	r.Get("/v1/organization/{orgId}", h.GetOrg)

	t.Run("matching org", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/organization/myorg", nil)
		req = withClaims(req, &auth.Claims{Owner: "myorg"})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("cross-org blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/organization/other", nil)
		req = withClaims(req, &auth.Claims{Owner: "myorg"})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
}

func TestOrgSubscription(t *testing.T) {
	h := NewCompat()
	r := chi.NewRouter()
	r.Get("/v1/organization/{orgId}/subscription", h.OrgSubscription)

	req := httptest.NewRequest(http.MethodGet, "/v1/organization/myorg/subscription", nil)
	req = withClaims(req, &auth.Claims{Owner: "myorg"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestOrgPermissions(t *testing.T) {
	h := NewCompat()
	r := chi.NewRouter()
	r.Get("/v1/organization/{orgId}/permissions", h.OrgPermissions)

	req := httptest.NewRequest(http.MethodGet, "/v1/organization/myorg/permissions", nil)
	req = withClaims(req, &auth.Claims{Owner: "myorg"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	rules := resp["packRules"].([]any)
	if len(rules) == 0 {
		t.Fatal("expected non-empty packRules")
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
}

func TestSubOrganizations(t *testing.T) {
	h := NewCompat()
	req := httptest.NewRequest(http.MethodGet, "/v1/sub-organizations", nil)
	w := httptest.NewRecorder()
	h.SubOrganizations(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestSRPLoginStubs(t *testing.T) {
	h := NewCompat()
	for _, path := range []string{"/v1/auth/login1", "/v1/auth/login2"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		w := httptest.NewRecorder()
		if path == "/v1/auth/login1" {
			h.SRPLogin1(w, req)
		} else {
			h.SRPLogin2(w, req)
		}
		if w.Code != 501 {
			t.Fatalf("%s: expected 501, got %d", path, w.Code)
		}
	}
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
}

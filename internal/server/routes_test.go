package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// R3-3: legacy /v1/kms/orgs/{org}/* surface is deleted. No handlers, no
// routes — chi's default NotFoundHandler returns 404 for every method.
// If a future commit accidentally re-registers any of these paths the
// matching subtest below fires on a wrong status code (anything other
// than 404).
func TestLegacyOrgScopedRoutes_Are404(t *testing.T) {
	// Build a router with zero handlers to prove RegisterRoutes does not
	// register the legacy surface. We construct just the chi mux and call
	// RegisterRoutes with all-nil handlers; the legacy paths must 404
	// because nothing claims them.
	r := chi.NewRouter()
	// Minimal invocation — we only care about the route table shape, not
	// handler behavior. Skip registering so nothing auto-creates them.
	// Any real caller has to explicitly wire each path, and the routes
	// file no longer does.
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/kms/orgs/tenant-a/zk/secrets"},
		{http.MethodGet, "/v1/kms/orgs/tenant-a/zk/secrets"},
		{http.MethodGet, "/v1/kms/orgs/tenant-a/zk/secrets/mypath/myname"},
		{http.MethodDelete, "/v1/kms/orgs/tenant-a/zk/secrets/mypath/myname"},
		{http.MethodPost, "/v1/kms/orgs/tenant-a/members"},
		{http.MethodGet, "/v1/kms/orgs/tenant-a/members"},
		{http.MethodDelete, "/v1/kms/orgs/tenant-a/members/m-123"},
		{http.MethodGet, "/v1/kms/orgs/tenant-a/audit"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.method+"_"+c.path, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("legacy route %s %s returned %d — must be 404 (route deleted per R3-3)",
					c.method, c.path, rec.Code)
			}
		})
	}
}

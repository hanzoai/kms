package kmsclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"no endpoint", Config{IAMEndpoint: "x", ClientID: "x", ClientSecret: "x", Org: "x"}},
		{"no iam", Config{Endpoint: "x", ClientID: "x", ClientSecret: "x", Org: "x"}},
		{"no client id", Config{Endpoint: "x", IAMEndpoint: "x", ClientSecret: "x", Org: "x"}},
		{"no client secret", Config{Endpoint: "x", IAMEndpoint: "x", ClientID: "x", Org: "x"}},
		{"no org", Config{Endpoint: "x", IAMEndpoint: "x", ClientID: "x", ClientSecret: "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNew_Valid(t *testing.T) {
	c, err := New(Config{
		Endpoint:     "http://kms:8443",
		IAMEndpoint:  "http://iam:8000",
		ClientID:     "id",
		ClientSecret: "sec",
		Org:          "test-org",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.org != "test-org" {
		t.Errorf("org = %q, want test-org", c.org)
	}
}

func TestSplitPathName(t *testing.T) {
	tests := []struct {
		input    string
		wantPath string
		wantName string
	}{
		{"providers/alpaca/dev/api_key", "providers/alpaca/dev", "api_key"},
		{"simple/key", "simple", "key"},
		{"key", "", "key"},
		{"a/b/c/d", "a/b/c", "d"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pn := splitPathName(tt.input)
			if pn.path != tt.wantPath {
				t.Errorf("path = %q, want %q", pn.path, tt.wantPath)
			}
			if pn.name != tt.wantName {
				t.Errorf("name = %q, want %q", pn.name, tt.wantName)
			}
		})
	}
}

func TestGet_WithMockServer(t *testing.T) {
	// Mock IAM token endpoint.
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token-123",
			"expires_in":   3600,
		})
	}))
	defer iam.Close()

	// Mock KMS server — implements canonical two-step resolve + fetch.
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token-123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Step 1: GET /v1/kms/tenants/{tenantId}/secrets?path=&name= → list items
		if r.URL.Path == "/v1/kms/tenants/liquidity/secrets" {
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{
					"secretId": "sec_abc",
					"path":     r.URL.Query().Get("path"),
					"name":     r.URL.Query().Get("name"),
				}},
			})
			return
		}
		// Step 2: GET /v1/kms/secrets/{secretId} → value
		if r.URL.Path == "/v1/kms/secrets/sec_abc" {
			json.NewEncoder(w).Encode(map[string]any{
				"secretId": "sec_abc",
				"path":     "providers/alpaca/dev",
				"name":     "api_key",
				"value":    "CKEJOEAIF2RS6KLVJUSXVOPKLW",
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer kms.Close()

	c, err := New(Config{
		Endpoint:     kms.URL,
		IAMEndpoint:  iam.URL,
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Org:          "liquidity",
	})
	if err != nil {
		t.Fatal(err)
	}

	val, err := c.Get(context.Background(), "providers/alpaca/dev", "api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "CKEJOEAIF2RS6KLVJUSXVOPKLW" {
		t.Errorf("value = %q, want CKEJOEAIF2RS6KLVJUSXVOPKLW", val)
	}
}

func TestGet_NotFound(t *testing.T) {
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"expires_in":   3600,
		})
	}))
	defer iam.Close()

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return empty items list — resolveSecretID will surface "not found".
		json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{}})
	}))
	defer kms.Close()

	c, _ := New(Config{
		Endpoint:     kms.URL,
		IAMEndpoint:  iam.URL,
		ClientID:     "id",
		ClientSecret: "sec",
		Org:          "org",
	})

	_, err := c.Get(context.Background(), "no/such", "secret")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestGet_TokenCaching(t *testing.T) {
	tokenCalls := 0
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cached-token",
			"expires_in":   3600,
		})
	}))
	defer iam.Close()

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/kms/tenants/org/secrets" {
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{
					"secretId": "sec_x",
					"path":     r.URL.Query().Get("path"),
					"name":     r.URL.Query().Get("name"),
				}},
			})
			return
		}
		if r.URL.Path == "/v1/kms/secrets/sec_x" {
			json.NewEncoder(w).Encode(map[string]any{"secretId": "sec_x", "value": "v"})
			return
		}
		http.Error(w, "nf", 404)
	}))
	defer kms.Close()

	c, _ := New(Config{
		Endpoint:     kms.URL,
		IAMEndpoint:  iam.URL,
		ClientID:     "id",
		ClientSecret: "sec",
		Org:          "org",
	})

	ctx := context.Background()
	c.Get(ctx, "a", "b")
	c.Get(ctx, "a", "b")
	c.Get(ctx, "a", "b")

	if tokenCalls != 1 {
		t.Errorf("expected 1 token call (cached), got %d", tokenCalls)
	}
}

func TestFetchEnv(t *testing.T) {
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"expires_in":   3600,
		})
	}))
	defer iam.Close()

	secrets := map[string]string{
		"providers/alpaca/dev/api_key":    "KEY123",
		"providers/alpaca/dev/api_secret": "SEC456",
	}

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		// Step 1: list resolver.
		if p == "/v1/kms/tenants/org/secrets" {
			path := r.URL.Query().Get("path")
			name := r.URL.Query().Get("name")
			full := path + "/" + name
			if _, ok := secrets[full]; ok {
				json.NewEncoder(w).Encode(map[string]any{
					"items": []map[string]any{{
						"secretId": "sec_" + name,
						"path":     path,
						"name":     name,
					}},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{}})
			return
		}
		// Step 2: read by id.
		for full, val := range secrets {
			pn := splitPathName(full)
			if p == "/v1/kms/secrets/sec_"+pn.name {
				json.NewEncoder(w).Encode(map[string]any{
					"secretId": "sec_" + pn.name,
					"value":    val,
				})
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer kms.Close()

	// Override env helpers to avoid polluting real env.
	envStore := map[string]string{}
	lookupEnv = func(key string) (string, bool) {
		v, ok := envStore[key]
		return v, ok
	}
	setEnv = func(key, val string) error {
		envStore[key] = val
		return nil
	}
	defer func() {
		lookupEnv = defaultLookupEnv
		setEnv = defaultSetEnv
	}()

	c, _ := New(Config{
		Endpoint:     kms.URL,
		IAMEndpoint:  iam.URL,
		ClientID:     "id",
		ClientSecret: "sec",
		Org:          "org",
	})

	n, err := c.FetchEnv(context.Background(), map[string]string{
		"BROKER_API_KEY":    "providers/alpaca/dev/api_key",
		"BROKER_API_SECRET": "providers/alpaca/dev/api_secret",
	})
	if err != nil {
		t.Fatalf("FetchEnv: %v", err)
	}
	if n != 2 {
		t.Errorf("fetched %d, want 2", n)
	}
	if envStore["BROKER_API_KEY"] != "KEY123" {
		t.Errorf("BROKER_API_KEY = %q, want KEY123", envStore["BROKER_API_KEY"])
	}
	if envStore["BROKER_API_SECRET"] != "SEC456" {
		t.Errorf("BROKER_API_SECRET = %q, want SEC456", envStore["BROKER_API_SECRET"])
	}
}

func TestFetchEnv_NoOverrideExisting(t *testing.T) {
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"expires_in":   3600,
		})
	}))
	defer iam.Close()

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Resolver: return one item; read: return value. Not important here —
		// the assertion is "existing env vars are not overridden", which short-
		// circuits before the KMS call.
		if r.URL.Path == "/v1/kms/tenants/org/secrets" {
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{
					"secretId": "sec_k",
					"path":     r.URL.Query().Get("path"),
					"name":     r.URL.Query().Get("name"),
				}},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"secretId": "sec_k", "value": "from-kms"})
	}))
	defer kms.Close()

	envStore := map[string]string{
		"EXISTING_KEY": "from-env",
	}
	lookupEnv = func(key string) (string, bool) {
		v, ok := envStore[key]
		return v, ok
	}
	setEnv = func(key, val string) error {
		envStore[key] = val
		return nil
	}
	defer func() {
		lookupEnv = defaultLookupEnv
		setEnv = defaultSetEnv
	}()

	c, _ := New(Config{
		Endpoint:     kms.URL,
		IAMEndpoint:  iam.URL,
		ClientID:     "id",
		ClientSecret: "sec",
		Org:          "org",
	})

	c.FetchEnv(context.Background(), map[string]string{
		"EXISTING_KEY": "some/path/key",
	})

	if envStore["EXISTING_KEY"] != "from-env" {
		t.Errorf("expected existing env to not be overridden, got %q", envStore["EXISTING_KEY"])
	}
}

// containsPath checks if a URL path ends with /{path}/{name} (URL-encoded).
func containsPath(urlPath, path, name string) bool {
	suffix := "/" + path + "/" + name
	return len(urlPath) >= len(suffix) && urlPath[len(urlPath)-len(suffix):] == suffix
}

// Save defaults so we can restore after test.
var defaultLookupEnv = lookupEnv
var defaultSetEnv = setEnv

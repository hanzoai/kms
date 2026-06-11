package kmsclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// mockIAM returns a test IAM that always mints the same bearer token.
func mockIAM(t *testing.T, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": token,
			"expires_in":   3600,
		})
	}))
}

func TestGet_WithMockServer(t *testing.T) {
	iam := mockIAM(t, "test-token-123")
	defer iam.Close()

	// Server: implements canonical GET /v1/kms/orgs/{org}/secrets/{path}/{name}.
	const wantPath = "/v1/kms/orgs/hanzo/secrets/providers/alpaca/dev/api_key"
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token-123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == wantPath {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secret": map[string]any{"value": "CKEJOEAIF2RS6KLVJUSXVOPKLW"},
			})
			return
		}
		http.Error(w, "not found: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}))
	defer kms.Close()

	c, err := New(Config{
		Endpoint:     kms.URL,
		IAMEndpoint:  iam.URL,
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Org:          "hanzo",
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

func TestGet_FlatValueShape(t *testing.T) {
	iam := mockIAM(t, "tok")
	defer iam.Close()
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"value": "bare"})
	}))
	defer kms.Close()
	c, _ := New(Config{Endpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "i", ClientSecret: "s", Org: "org"})
	v, err := c.Get(context.Background(), "a", "b")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if v != "bare" {
		t.Errorf("value = %q, want bare", v)
	}
}

func TestGet_NotFound(t *testing.T) {
	iam := mockIAM(t, "tok")
	defer iam.Close()

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
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
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want substring 'not found'", err)
	}
}

func TestGet_TokenCaching(t *testing.T) {
	tokenCalls := 0
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cached-token",
			"expires_in":   3600,
		})
	}))
	defer iam.Close()

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"secret": map[string]any{"value": "v"}})
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
	_, _ = c.Get(ctx, "a", "b")
	_, _ = c.Get(ctx, "a", "b")
	_, _ = c.Get(ctx, "a", "b")

	if tokenCalls != 1 {
		t.Errorf("expected 1 token call (cached), got %d", tokenCalls)
	}
}

func TestPut_SendsCanonicalPayload(t *testing.T) {
	iam := mockIAM(t, "tok")
	defer iam.Close()

	var gotPath string
	var gotBody map[string]string
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer kms.Close()

	c, _ := New(Config{Endpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "i", ClientSecret: "s", Org: "hanzo"})
	if err := c.Put(context.Background(), "providers/square/dev", "access_token", "sq_abc"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if gotPath != "/v1/kms/orgs/hanzo/secrets" {
		t.Errorf("path = %q, want /v1/kms/orgs/hanzo/secrets", gotPath)
	}
	if gotBody["path"] != "providers/square/dev" || gotBody["name"] != "access_token" || gotBody["value"] != "sq_abc" {
		t.Errorf("body = %+v, want path=providers/square/dev name=access_token value=sq_abc", gotBody)
	}
}

func TestList_UsesCanonicalPath(t *testing.T) {
	iam := mockIAM(t, "tok")
	defer iam.Close()

	var gotPath, gotQuery string
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{"path": "providers/square/dev", "name": "access_token"},
				{"path": "providers/alpaca/dev", "name": "api_key"},
			},
		})
	}))
	defer kms.Close()

	c, _ := New(Config{Endpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "i", ClientSecret: "s", Org: "hanzo"})
	got, err := c.List(context.Background(), "providers/square")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotPath != "/v1/kms/orgs/hanzo/secrets" {
		t.Errorf("path = %q, want /v1/kms/orgs/hanzo/secrets", gotPath)
	}
	if gotQuery != "prefix=providers%2Fsquare" {
		t.Errorf("query = %q, want prefix=providers%%2Fsquare", gotQuery)
	}
	// Client-side filter must drop the alpaca entry even if the server returned it.
	if len(got) != 1 || got[0] != "providers/square/dev/access_token" {
		t.Errorf("items = %v, want [providers/square/dev/access_token]", got)
	}
}

func TestDelete_UsesCanonicalPath(t *testing.T) {
	iam := mockIAM(t, "tok")
	defer iam.Close()
	var gotPath, gotMethod string
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer kms.Close()
	c, _ := New(Config{Endpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "i", ClientSecret: "s", Org: "hanzo"})
	if err := c.Delete(context.Background(), "providers/square/dev", "access_token"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/v1/kms/orgs/hanzo/secrets/providers/square/dev/access_token" {
		t.Errorf("path = %q, want canonical orgs path", gotPath)
	}
}

func TestSecretPath_EscapesSegments(t *testing.T) {
	c := &Client{endpoint: "http://kms:8443", org: "liq/uid"}
	got := c.secretPath("foo bar/baz", "k+q")
	// Segments individually escaped; "/" preserved as separator. Org escaped once.
	want := "http://kms:8443/v1/kms/orgs/liq%2Fuid/secrets/foo%20bar/baz/k+q"
	if got != want {
		t.Errorf("secretPath = %q, want %q", got, want)
	}
}

func TestFetchEnv(t *testing.T) {
	iam := mockIAM(t, "tok")
	defer iam.Close()

	secrets := map[string]string{
		"providers/alpaca/dev/api_key":    "KEY123",
		"providers/alpaca/dev/api_secret": "SEC456",
	}

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path: /v1/kms/orgs/org/secrets/<path>/<name>
		const prefix = "/v1/kms/orgs/org/secrets/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		rest := r.URL.Path[len(prefix):]
		if v, ok := secrets[rest]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"secret": map[string]any{"value": v}})
			return
		}
		http.Error(w, "nf", http.StatusNotFound)
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
	iam := mockIAM(t, "tok")
	defer iam.Close()

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Should never be called; existing env short-circuits before network.
		_ = json.NewEncoder(w).Encode(map[string]any{"secret": map[string]any{"value": "from-kms"}})
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

	_, _ = c.FetchEnv(context.Background(), map[string]string{
		"EXISTING_KEY": "some/path/key",
	})

	if envStore["EXISTING_KEY"] != "from-env" {
		t.Errorf("expected existing env to not be overridden, got %q", envStore["EXISTING_KEY"])
	}
}

// Save defaults so we can restore after test.
var defaultLookupEnv = lookupEnv
var defaultSetEnv = setEnv

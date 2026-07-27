package kms

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// TestMountBridge_NetHTTPOverZIP exercises the exact bridge mount.go builds:
// a net/http handler fronted on a zip wildcard route via zip.AdaptNetHTTP,
// served over a real TCP listener and driven by a real net/http client.
//
// This is the seam the ZAP frame format runs through — request headers,
// query, method and body have to survive the trip into the http.Request and
// the response headers/status/body have to survive the trip back out. A
// framing regression in zap-proto/http shows up here and nowhere else in
// this module's tests, since every other suite calls the handler directly.
func TestMountBridge_NetHTTPOverZIP(t *testing.T) {
	// The adapted subtree: echoes back everything it received so the
	// assertions can compare both directions of the frame.
	inner := http.NewServeMux()
	inner.HandleFunc("/v1/kms/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Kms-Resp", "resp-value")
		w.Header().Add("X-Kms-Multi", "one")
		w.Header().Add("X-Kms-Multi", "two")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.Query().Get("q"),
			"hdr":    r.Header.Get("X-Kms-Req"),
			"auth":   r.Header.Get("Authorization"),
			"body":   string(body),
		})
	})

	app := zip.New(zip.Config{
		Logger:                luxlog.New("test", "kms-mount-bridge"),
		DisableStartupMessage: true,
		AppName:               "kms",
	})
	// Same shape as mount.go: native health route + adapted wildcard subtree.
	app.Get("/v1/kms/health", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]any{"status": "ok", "service": "kms"})
	})
	app.All("/v1/kms/*", zip.AdaptNetHTTP(inner))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = app.Fiber().Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })
	base := "http://" + ln.Addr().String()

	client := &http.Client{Timeout: 10 * time.Second}
	waitReady(t, client, base+"/v1/kms/health")

	// Native zip route still answers alongside the adapted subtree.
	t.Run("native health", func(t *testing.T) {
		resp, err := client.Get(base + "/v1/kms/health")
		if err != nil {
			t.Fatalf("get health: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("health status = %d, want 200", resp.StatusCode)
		}
		var got map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode health: %v", err)
		}
		if got["service"] != "kms" || got["status"] != "ok" {
			t.Fatalf("health body = %v", got)
		}
	})

	// The adapted subtree: full round trip through the frame.
	t.Run("adapted subtree round trip", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost,
			base+"/v1/kms/echo?q=query-value", bytes.NewReader([]byte("payload-body")))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("X-Kms-Req", "req-value")
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "text/plain")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusTeapot {
			t.Fatalf("status = %d, want %d (status did not survive the bridge)",
				resp.StatusCode, http.StatusTeapot)
		}
		if got := resp.Header.Get("X-Kms-Resp"); got != "resp-value" {
			t.Errorf("response header X-Kms-Resp = %q, want %q", got, "resp-value")
		}
		if got := resp.Header.Values("X-Kms-Multi"); len(got) != 2 ||
			got[0] != "one" || got[1] != "two" {
			t.Errorf("repeated response header X-Kms-Multi = %v, want [one two]", got)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var got map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode echo: %v", err)
		}
		for _, c := range []struct{ field, want string }{
			{"method", http.MethodPost},
			{"path", "/v1/kms/echo"},
			{"query", "query-value"},
			{"hdr", "req-value"},
			{"auth", "Bearer test-token"},
			{"body", "payload-body"},
		} {
			if got[c.field] != c.want {
				t.Errorf("request %s = %q, want %q (did not survive the bridge)",
					c.field, got[c.field], c.want)
			}
		}
	})
}

// waitReady polls url until it answers or the deadline passes.
func waitReady(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener never became ready: %s", url)
}

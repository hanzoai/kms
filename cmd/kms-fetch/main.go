// Command kms-fetch is the canonical init-container that materialises secrets
// from Hanzo KMS into a tmpfs volume the main container reads.
//
// It exists so that K8s Secrets disappear from the cluster. The pod env
// carries at most one bootstrap credential pair (IAM_CLIENT_ID,
// IAM_CLIENT_SECRET) — every runtime secret is pulled from KMS at boot.
//
// Native ZAP is the preferred transport (KMS_ZAP=host:port). HTTP is the
// fallback for callers that can't reach ZAP. Both end in the same bytes
// written under OUT_DIR.
//
// Contract:
//
//	env  KMS_ZAP                 host:port for the ZAP listener (preferred)
//	env  KMS_ENV                 environment scope (dev / test / main)  — defaults to dev
//	env  KMS_ENDPOINT            REST endpoint (used only when KMS_ZAP is empty)
//	env  IAM_URL                 IAM endpoint (only needed for HTTP fallback)
//	env  IAM_ORG                 IAM organisation slug (only for HTTP fallback)
//	env  IAM_CLIENT_ID           service account id (only for HTTP fallback)
//	env  IAM_CLIENT_SECRET       service account secret (only for HTTP fallback)
//	env  KMS_SECRETS             comma-separated NAME=path/key list to fetch
//	env  OUT_DIR                 directory to write secrets into (default /secrets)
//	env  WRITE_ENV_FILE          if "true", also write OUT_DIR/env in KEY=value form
//	                             so a wrapper can `set -a; . /secrets/env; set +a`
//
// One and only one way: every consumer service uses this binary as its
// initContainer. The list of secrets is data, not code. The output layout
// is fixed (one file per key, plus an optional `env` aggregate).
//
// Exit codes:
//
//	0   all secrets resolved and written
//	2   bad configuration (missing env)
//	3   IAM token exchange / ZAP dial failed
//	4   one or more KMS fetches failed (no partial writes — atomic or abort)
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hanzoai/kms/sdk/go/kmsclient"
)

const (
	exitConfig = 2
	exitAuth   = 3
	exitFetch  = 4
)

// spec is one row of KMS_SECRETS.
type spec struct {
	envName string // KEY the app expects, e.g. ALPACA_API_KEY
	path    string // KMS path,             e.g. bd/alpaca/liq4
	name    string // KMS secret name,      e.g. api_key
}

// fetcher abstracts ZAP and HTTP behind a common Get(path,name)→value.
type fetcher interface {
	Get(ctx context.Context, path, name string) (string, error)
	Close() error
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "kms-fetch:", err)
		os.Exit(exitCodeFor(err))
	}
}

type cfgErr struct{ s string }

func (e *cfgErr) Error() string { return e.s }

type authErr struct{ err error }

func (e *authErr) Error() string { return "auth: " + e.err.Error() }
func (e *authErr) Unwrap() error { return e.err }

type fetchErr struct {
	name string
	err  error
}

func (e *fetchErr) Error() string { return fmt.Sprintf("fetch %s: %s", e.name, e.err) }
func (e *fetchErr) Unwrap() error { return e.err }

func exitCodeFor(err error) int {
	switch err.(type) {
	case *cfgErr:
		return exitConfig
	case *authErr:
		return exitAuth
	case *fetchErr:
		return exitFetch
	}
	return 1
}

func run(ctx context.Context) error {
	specsRaw := os.Getenv("KMS_SECRETS")
	if specsRaw == "" {
		return &cfgErr{"missing required env KMS_SECRETS"}
	}

	specs, err := parseSpecs(specsRaw)
	if err != nil {
		return &cfgErr{err.Error()}
	}

	kmsEnv := envOr("KMS_ENV", "dev")
	outDir := envOr("OUT_DIR", "/secrets")
	writeEnvFile := envOr("WRITE_ENV_FILE", "true") == "true"

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	f, err := newFetcher(dialCtx, kmsEnv)
	if err != nil {
		return &authErr{err: err}
	}
	defer f.Close()

	values := make(map[string]string, len(specs))
	for _, s := range specs {
		getCtx, c2 := context.WithTimeout(ctx, 10*time.Second)
		v, err := f.Get(getCtx, s.path, s.name)
		c2()
		if err != nil {
			return &fetchErr{name: s.envName, err: err}
		}
		values[s.envName] = v
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	for k, v := range values {
		dst := filepath.Join(outDir, k)
		if err := writeFileAtomic(dst, []byte(v), 0o400); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
	}

	if writeEnvFile {
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%s\n", k, shellQuote(values[k]))
		}
		dst := filepath.Join(outDir, "env")
		if err := writeFileAtomic(dst, []byte(b.String()), 0o400); err != nil {
			return fmt.Errorf("write env: %w", err)
		}
	}

	fmt.Fprintf(os.Stdout, "kms-fetch: wrote %d secret(s) to %s\n", len(values), outDir)
	return nil
}

// newFetcher returns a ZAP-backed fetcher when KMS_ZAP is set, else falls
// back to the HTTP path. The decision is per-process: there is no per-call
// fallback so failures fail loud (a partial mix would mask configuration
// drift).
//
// ZAP requires LUX_MNEMONIC + KMS_SERVICE_PATH for the consensus-native
// envelope path; HTTP requires the IAM client_credentials pair.
func newFetcher(ctx context.Context, kmsEnv string) (fetcher, error) {
	if addr := os.Getenv("KMS_ZAP"); addr != "" {
		org := os.Getenv("IAM_ORG")
		if org == "" {
			org = "hanzo"
		}
		servicePath := os.Getenv("KMS_SERVICE_PATH")
		if servicePath == "" {
			return nil, fmt.Errorf("KMS_ZAP set but KMS_SERVICE_PATH is missing (need a service path for envelope identity)")
		}
		ident, err := kmsclient.IdentityFromEnv(servicePath)
		if err != nil {
			return nil, fmt.Errorf("kms-fetch: identity: %w", err)
		}
		cli, err := kmsclient.New(kmsclient.Config{
			Endpoint:        "zap://" + addr,
			Org:             org,
			Env:             kmsEnv,
			Identity:        ident,
			TransportNodeID: "kms-fetch",
		})
		if err != nil {
			return nil, fmt.Errorf("kms-fetch: zap dial %s: %w", addr, err)
		}
		return &kmsclientFetcher{c: cli, identity: ident}, nil
	}
	// HTTP fallback. Requires the full IAM credential pair.
	endpoint := os.Getenv("KMS_ENDPOINT")
	iamURL := os.Getenv("IAM_URL")
	org := os.Getenv("IAM_ORG")
	cid := os.Getenv("IAM_CLIENT_ID")
	csec := os.Getenv("IAM_CLIENT_SECRET")
	if endpoint == "" || iamURL == "" || org == "" || cid == "" || csec == "" {
		return nil, fmt.Errorf("KMS_ZAP unset and HTTP fallback missing one of KMS_ENDPOINT, IAM_URL, IAM_ORG, IAM_CLIENT_ID, IAM_CLIENT_SECRET")
	}
	cli, err := kmsclient.New(kmsclient.Config{
		Endpoint: endpoint, IAMEndpoint: iamURL, ClientID: cid, ClientSecret: csec, Org: org,
	})
	if err != nil {
		return nil, err
	}
	return &kmsclientFetcher{c: cli}, nil
}

type kmsclientFetcher struct {
	c        *kmsclient.Client
	identity *kmsclient.Identity // owns the private key; wiped on Close
}

func (z *kmsclientFetcher) Get(ctx context.Context, path, name string) (string, error) {
	return z.c.Get(ctx, path, name)
}
func (z *kmsclientFetcher) Close() error {
	if z.identity != nil {
		z.identity.Wipe()
	}
	return z.c.Close()
}

// parseSpecs accepts the same format already established by the bd
// container's KMS_SECRETS env:
//
//	NAME1=path/to/secretA,NAME2=path/to/secretB,...
//
// `path/to/secretA` is split on the last "/" — everything before is the
// KMS `path`, everything after is the KMS `name`. This matches both
// kmsclient.Get(path, name) and zapclient.GetAt(path, name, env).
func parseSpecs(raw string) ([]spec, error) {
	var out []spec
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		eq := strings.IndexByte(item, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("malformed KMS_SECRETS entry %q (want NAME=path/key)", item)
		}
		envName, full := strings.TrimSpace(item[:eq]), strings.TrimSpace(item[eq+1:])
		if envName == "" || full == "" {
			return nil, fmt.Errorf("malformed KMS_SECRETS entry %q (empty side)", item)
		}
		slash := strings.LastIndexByte(full, '/')
		if slash <= 0 || slash == len(full)-1 {
			return nil, fmt.Errorf("malformed KMS_SECRETS entry %q (need path/key)", item)
		}
		out = append(out, spec{
			envName: envName,
			path:    full[:slash],
			name:    full[slash+1:],
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("KMS_SECRETS produced zero entries")
	}
	return out, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".kms-fetch-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // best-effort if anything below fails
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func shellQuote(v string) string {
	// Pick double-quote form so newlines pass through literally; escape "$ \ ` "
	// and the closing quote.
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`)
	return `"` + r.Replace(v) + `"`
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

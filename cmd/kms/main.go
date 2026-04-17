// Command kms is the admin CLI for KMS.
//
// Usage:
//
//	kms status [--addr http://localhost:8443]
//	kms put <path/name> <value> [--org liquidity]
//	kms get <path/name> [--org liquidity]
//	kms list [prefix] [--org liquidity]
//	kms rotate <path/name> <new-value> [--org liquidity]
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/kms/pkg/kmsclient"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	addr := envOr("KMS_ADDR", "http://localhost:8443")
	iamAddr := envOr("IAM_ADDR", "http://localhost:8000")
	clientID := envOr("KMS_CLIENT_ID", "")
	clientSecret := envOr("KMS_CLIENT_SECRET", "")
	org := envOr("KMS_ORG", "liquidity")

	// Parse global flags from any position.
	args := os.Args[1:]
	args = extractFlag(&addr, args, "--addr")
	args = extractFlag(&iamAddr, args, "--iam-addr")
	args = extractFlag(&clientID, args, "--client-id")
	args = extractFlag(&clientSecret, args, "--client-secret")
	args = extractFlag(&org, args, "--org")

	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	switch args[0] {
	case "status":
		cmdStatus(addr)
	case "put":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "kms: put requires <path/name> <value>")
			os.Exit(1)
		}
		c := mustClient(addr, iamAddr, clientID, clientSecret, org)
		cmdPut(c, args[1], args[2])
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "kms: get requires <path/name>")
			os.Exit(1)
		}
		c := mustClient(addr, iamAddr, clientID, clientSecret, org)
		cmdGet(c, args[1])
	case "list":
		c := mustClient(addr, iamAddr, clientID, clientSecret, org)
		prefix := ""
		if len(args) > 1 {
			prefix = args[1]
		}
		cmdList(c, prefix)
	case "rotate":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "kms: rotate requires <path/name> <new-value>")
			os.Exit(1)
		}
		c := mustClient(addr, iamAddr, clientID, clientSecret, org)
		cmdRotate(c, args[1], args[2])
	default:
		fmt.Fprintf(os.Stderr, "kms: unknown command %q\n", args[0])
		usage()
		os.Exit(1)
	}
}

func mustClient(addr, iamAddr, clientID, clientSecret, org string) *kmsclient.Client {
	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "kms: KMS_CLIENT_ID and KMS_CLIENT_SECRET are required (or --client-id/--client-secret)")
		os.Exit(1)
	}
	c, err := kmsclient.New(kmsclient.Config{
		Endpoint:     addr,
		IAMEndpoint:  iamAddr,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Org:          org,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "kms: %v\n", err)
		os.Exit(1)
	}
	return c
}

func cmdPut(c *kmsclient.Client, fullPath, value string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pn := splitPath(fullPath)
	if pn.path == "" || pn.name == "" {
		fmt.Fprintf(os.Stderr, "kms: invalid path %q (must be path/name, e.g. providers/alpaca/dev/api_key)\n", fullPath)
		os.Exit(1)
	}

	if err := c.Put(ctx, pn.path, pn.name, value); err != nil {
		fmt.Fprintf(os.Stderr, "kms: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ok: %s/%s\n", pn.path, pn.name)
}

func cmdGet(c *kmsclient.Client, fullPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pn := splitPath(fullPath)
	if pn.path == "" || pn.name == "" {
		fmt.Fprintf(os.Stderr, "kms: invalid path %q\n", fullPath)
		os.Exit(1)
	}

	val, err := c.Get(ctx, pn.path, pn.name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kms: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(val)
}

func cmdList(c *kmsclient.Client, prefix string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	names, err := c.List(ctx, prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kms: %v\n", err)
		os.Exit(1)
	}
	for _, n := range names {
		fmt.Println(n)
	}
}

func cmdRotate(c *kmsclient.Client, fullPath, newValue string) {
	// Rotate = put with upsert semantics (same as put).
	cmdPut(c, fullPath, newValue)
}

func cmdStatus(addr string) {
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(addr + "/healthz")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kms: health check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("healthz: %s\n", body)

	resp2, err := client.Get(addr + "/v1/kms/status")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kms: status check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)
	var pretty map[string]any
	if json.Unmarshal(body2, &pretty) == nil {
		out, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Printf("status: %s\n", out)
	} else {
		fmt.Printf("status: %s\n", body2)
	}
}

type pathParts struct {
	path string
	name string
}

func splitPath(s string) pathParts {
	idx := strings.LastIndex(s, "/")
	if idx < 0 {
		return pathParts{name: s}
	}
	return pathParts{
		path: s[:idx],
		name: s[idx+1:],
	}
}

func extractFlag(dst *string, args []string, flag string) []string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			*dst = args[i+1]
			return append(args[:i], args[i+2:]...)
		}
	}
	return args
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: kms <command> [flags]

Commands:
  status       Check kmsd health and MPC status
  put          Store a secret: kms-cli put <path/name> <value>
  get          Fetch a secret: kms-cli get <path/name>
  list         List secrets:   kms-cli list [prefix]
  rotate       Rotate a secret: kms-cli rotate <path/name> <new-value>

Global Flags:
  --addr            KMS server address (default: $KMS_ADDR or http://localhost:8443)
  --iam-addr        IAM server address (default: $IAM_ADDR or http://localhost:8000)
  --client-id       IAM client ID (default: $KMS_CLIENT_ID)
  --client-secret   IAM client secret (default: $KMS_CLIENT_SECRET)
  --org             Organization slug (default: $KMS_ORG or liquidity)

Environment Variables:
  KMS_ADDR          KMS server address
  IAM_ADDR          IAM server address
  KMS_CLIENT_ID     IAM service account client ID
  KMS_CLIENT_SECRET IAM service account client secret
  KMS_ORG           Organization slug`)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

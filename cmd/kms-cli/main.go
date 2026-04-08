// Command kms-cli is the admin CLI for KMS.
//
// Usage:
//
//	kms-cli status [--addr http://localhost:8090]
//	kms-cli bootstrap --passphrase <pass> [--addr http://localhost:8090]
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	addr := envOr("KMS_ADDR", "http://localhost:8090")

	// Parse --addr flag from any position.
	args := os.Args[1:]
	for i, a := range args {
		if a == "--addr" && i+1 < len(args) {
			addr = args[i+1]
			args = append(args[:i], args[i+2:]...)
			break
		}
	}

	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	switch args[0] {
	case "status":
		cmdStatus(addr)
	case "bootstrap":
		passphrase := ""
		for i, a := range args {
			if a == "--passphrase" && i+1 < len(args) {
				passphrase = args[i+1]
				break
			}
		}
		if passphrase == "" {
			fmt.Fprintln(os.Stderr, "kms-cli: --passphrase is required for bootstrap")
			os.Exit(1)
		}
		cmdBootstrap(addr, passphrase)
	default:
		fmt.Fprintf(os.Stderr, "kms-cli: unknown command %q\n", args[0])
		usage()
		os.Exit(1)
	}
}

func cmdStatus(addr string) {
	client := &http.Client{Timeout: 5 * time.Second}

	// Health check.
	resp, err := client.Get(addr + "/healthz")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kms-cli: health check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("healthz: %s\n", body)

	// Full status.
	resp2, err := client.Get(addr + "/v1/status")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kms-cli: status check failed: %v\n", err)
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

func cmdBootstrap(addr, passphrase string) {
	// Bootstrap is a placeholder -- the actual implementation will
	// initialize the org's root encryption key using the passphrase.
	_ = addr
	_ = passphrase
	fmt.Println("kms-cli: bootstrap not yet implemented (kmsd auto-bootstraps collections on startup)")
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: kms-cli <command> [flags]

Commands:
  status       Check kmsd health and MPC status
  bootstrap    Initialize org (--passphrase required)

Flags:
  --addr       KMS server address (default: $KMS_ADDR or http://localhost:8090)`)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

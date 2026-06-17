// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// zap.go — load a BIP-39 mnemonic from KMS over native ZAP.
//
// This file is the one canonical path every Lux-derived service uses
// to resolve the bootstrap mnemonic: luxd, netrunner, lux/cli, and any
// descending L1's bootstrap (hanzo/network-bootstrap, hanzo-bootstrap,
// zoo-bootstrap, …). No file mount, no projected volume, no per-consumer
// copy of the env-vs-KMS precedence chain.
//
// Separation of concerns:
//
//   - zap (the protocol)           → github.com/zap-proto/zap
//   - luxfi/kms (secret store)     → opaque Get/Put/List over ZAP
//   - luxfi/keys (THIS PACKAGE)    → BIP-39, BIP44 derivation, mnemonic
//                                    semantics. Composes luxfi/kms with
//                                    bip39 validation. KMS knows nothing
//                                    about mnemonics; this layer does.
//
// Precedence (env wins; KMS is the production fallback):
//
//   1. MNEMONIC env var               local dev + CI test seam
//   2. KMS at (addr, env, path)       native ZAP from KMS

package keys

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	bip39 "github.com/luxfi/go-bip39"
	"github.com/luxfi/kms/pkg/zapclient"
)

// MnemonicReader is the minimum surface LoadMnemonicFromKMS needs from
// a KMS client. The real *zapclient.Client satisfies it; tests inject
// fakes via the dialKMS seam below.
type MnemonicReader interface {
	GetAt(ctx context.Context, path, name, env string) (string, error)
	Close()
}

// dialKMS is the production seam. Tests override to inject a fake
// without touching the network.
var dialKMS = func(ctx context.Context, addr string) (MnemonicReader, error) {
	c, err := zapclient.Dial(ctx, addr, "")
	if err != nil {
		return nil, err
	}
	return c, nil
}

// LoadMnemonic returns the BIP-39 mnemonic for the calling service.
// MNEMONIC env wins when set; otherwise dials KMS over native ZAP at
// `addr` and reads the secret at `path` under `env`.
//
//	addr  KMS host:port (e.g. "kms.internal.svc:9999")
//	env   KMS env scope ("mainnet" | "testnet" | "devnet")
//	path  KMS secret path (e.g. "/mnemonic" or "/foo/master")
//
// Returns the validated BIP-39 phrase. Caller is responsible for
// keeping it on the goroutine stack and not logging / persisting it.
func LoadMnemonic(ctx context.Context, addr, env, path string) (string, error) {
	if e := strings.TrimSpace(os.Getenv("MNEMONIC")); e != "" {
		if !bip39.IsMnemonicValid(e) {
			return "", errors.New("MNEMONIC env is not a valid BIP-39 phrase")
		}
		return e, nil
	}
	return LoadMnemonicFromKMS(ctx, addr, env, path)
}

// LoadMnemonicFromKMS is the production-only path (no MNEMONIC env
// short-circuit). Useful when a caller wants to force the KMS read
// regardless of ambient env — e.g., a regression test pinning the
// production code path.
func LoadMnemonicFromKMS(ctx context.Context, addr, env, path string) (string, error) {
	if addr == "" {
		return "", errors.New("keys.LoadMnemonicFromKMS: KMS addr is required")
	}
	if env == "" {
		return "", errors.New("keys.LoadMnemonicFromKMS: KMS env is required")
	}
	if path == "" {
		return "", errors.New("keys.LoadMnemonicFromKMS: KMS path is required")
	}

	c, err := dialKMS(ctx, addr)
	if err != nil {
		return "", fmt.Errorf("dial KMS %s: %w", addr, err)
	}
	defer c.Close()

	dir, name := SplitSecretPath(path)
	v, err := c.GetAt(ctx, dir, name, env)
	if err != nil {
		return "", fmt.Errorf("read mnemonic (path=%q name=%q env=%q): %w",
			dir, name, env, err)
	}
	m := strings.TrimSpace(v)
	if m == "" {
		return "", fmt.Errorf("mnemonic at %q is empty", path)
	}
	if !bip39.IsMnemonicValid(m) {
		return "", errors.New("mnemonic from KMS is not a valid BIP-39 phrase")
	}
	return m, nil
}

// SplitSecretPath turns "/foo/bar/baz" into ("/foo/bar/", "baz"). When
// there is no '/' or only a leading one, the directory is "" and the
// whole remainder is the name (e.g., "/mnemonic" → ("", "mnemonic")).
//
// Exported so every consumer can address secrets with the same
// convention — one and only one addressing scheme across mnemonic,
// staking keys, gas-payer keys, etc.
func SplitSecretPath(full string) (dir, name string) {
	full = strings.TrimSpace(full)
	full = strings.TrimPrefix(full, "/")
	i := strings.LastIndex(full, "/")
	if i < 0 {
		return "", full
	}
	return "/" + full[:i+1], full[i+1:]
}

// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command basic demonstrates the ZK-KMS client SDK.
//
// All encryption and decryption happens client-side. The CEK (Customer
// Encryption Key) is derived from the passphrase and never leaves the client.
// MPC nodes only store encrypted blobs.
package main

import (
	"fmt"
	"log"

	kms "github.com/hanzoai/kms-sdk-go"
)

func main() {
	client, err := kms.NewClient(kms.Config{
		Nodes:     []string{"https://kms-mpc-0:9651", "https://kms-mpc-1:9651", "https://kms-mpc-2:9651"},
		OrgSlug:   "hanzo",
		Threshold: 2,
	})
	if err != nil {
		log.Fatal(err)
	}

	// First time: bootstrap creates the org and derives the master key.
	// client.Bootstrap("super-secret-passphrase")

	// Unlock derives the CEK client-side from the passphrase.
	// The passphrase is never transmitted to any node.
	if err := client.Unlock("super-secret-passphrase"); err != nil {
		log.Fatal(err)
	}
	defer client.Lock() // zeros CEK from memory

	// Set a secret — encrypted client-side with CEK, stored on MPC nodes.
	// Nodes never see the plaintext value or the key name.
	if err := client.Set("DATABASE_URL", []byte("postgresql://user:pass@db:5432/app")); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Set DATABASE_URL (encrypted on MPC nodes)")

	// Get a secret — fetched as encrypted blob, decrypted client-side.
	val, err := client.Get("DATABASE_URL")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("DATABASE_URL = %s\n", val)

	// List all secrets — names are encrypted on nodes, decrypted client-side.
	names, err := client.List()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Secrets: %v\n", names)

	// Check MPC node health.
	statuses, err := client.Status()
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range statuses {
		fmt.Printf("Node %s: healthy=%v latency=%dms\n", s.Address, s.Healthy, s.Latency)
	}
}

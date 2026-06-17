// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package crypto

import gocrypto "crypto"

// Certificate represents a TLS certificate
// This is a minimal representation needed for NodeID generation
type Certificate struct {
	// Raw contains the complete ASN.1 DER content of the certificate
	Raw []byte
	// PublicKey contains the public key from the certificate
	PublicKey gocrypto.PublicKey
}

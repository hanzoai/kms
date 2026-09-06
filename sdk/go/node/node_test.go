package node

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
)

// order is the secp256k1 group order, used to build the high-s twin of a valid
// signature.
var order, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

func key(t *testing.T) (*ecdsa.PrivateKey, Address) {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return k, Address(crypto.PubkeyToAddress(k.PublicKey))
}

func sign(t *testing.T, k *ecdsa.PrivateKey, d Hash) Signature {
	t.Helper()
	raw, err := crypto.Sign(d[:], k)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var sig Signature
	copy(sig[:], raw)
	return sig
}

func measure(seed byte) Measurement {
	var m Measurement
	for i := range m {
		m[i] = seed
	}
	return m
}

func TestAttestationDigestSeparatesEveryField(t *testing.T) {
	a := Attestation{Address: Address{0x11}, Measurement: measure(0xaa), Epoch: 1, Payload: []byte("p")}

	variants := map[string]Attestation{
		"address":     {Address: Address{0x22}, Measurement: a.Measurement, Epoch: a.Epoch, Payload: a.Payload},
		"measurement": {Address: a.Address, Measurement: measure(0xbb), Epoch: a.Epoch, Payload: a.Payload},
		"epoch":       {Address: a.Address, Measurement: a.Measurement, Epoch: 2, Payload: a.Payload},
		"payload":     {Address: a.Address, Measurement: a.Measurement, Epoch: a.Epoch, Payload: []byte("q")},
	}
	for name, other := range variants {
		if a.Digest() == other.Digest() {
			t.Fatalf("digest does not separate %s", name)
		}
	}

	// The two purposes occupy disjoint regions, and neither digest is the bare
	// hash of its payload — which is what an unprefixed signing oracle would be.
	succ := Succession{Prev: a.Address, Next: Address{0x22}, Epoch: a.Epoch}
	if a.Digest() == succ.Digest() {
		t.Fatal("attestation and succession digests collide")
	}
	if a.Digest() == hash(a.Payload) {
		t.Fatal("attestation digest is the bare payload hash")
	}
}

func TestSuccessionDigestSeparatesEveryField(t *testing.T) {
	s := Succession{Prev: Address{0x11}, Next: Address{0x22}, Epoch: 1}
	for name, other := range map[string]Succession{
		"prev":  {Prev: Address{0x33}, Next: s.Next, Epoch: s.Epoch},
		"next":  {Prev: s.Prev, Next: Address{0x33}, Epoch: s.Epoch},
		"epoch": {Prev: s.Prev, Next: s.Next, Epoch: 2},
		// Direction matters: a succession is not symmetric, or a successor could
		// hand the identity back to a retired key.
		"direction": {Prev: s.Next, Next: s.Prev, Epoch: s.Epoch},
	} {
		if s.Digest() == other.Digest() {
			t.Fatalf("digest does not separate %s", name)
		}
	}
}

func TestReceiptVerifiesAgainstThePayloadTheCallerHolds(t *testing.T) {
	k, addr := key(t)
	payload := []byte("boot report")
	a := Attestation{Address: addr, Measurement: measure(0xaa), Epoch: 7, Payload: payload}
	r := Receipt{Attestation: a, Digest: a.Digest(), Signature: sign(t, k, a.Digest())}

	if err := r.Verify(payload); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// A different payload does not verify, even though the signature is genuine
	// and the digest it names is the one that was signed. This is the check that
	// makes a receipt evidence about specific bytes.
	if err := r.Verify([]byte("other report")); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify with another payload: got %v, want ErrSignature", err)
	}

	// A receipt whose stated digest is not the statement's is refused before any
	// recovery happens, so a server cannot name a digest it did not derive.
	swapped := r
	swapped.Digest = measure(0x01)
	if err := swapped.Verify(payload); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify with a substituted digest: got %v, want ErrSignature", err)
	}

	// A genuine signature by the wrong node is refused: the recovered address is
	// compared against the one the statement names.
	other, _ := key(t)
	impostor := r
	impostor.Signature = sign(t, other, a.Digest())
	if err := impostor.Verify(payload); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify with another signer: got %v, want ErrSignature", err)
	}

	// Claiming a different image does not verify either: the measurement is in
	// the preimage, so a receipt cannot be re-labelled onto another image.
	relabelled := r
	relabelled.Measurement = measure(0xbb)
	if err := relabelled.Verify(payload); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify with a substituted measurement: got %v, want ErrSignature", err)
	}
}

func TestHandoverVerifiesWithoutOutsideInput(t *testing.T) {
	prev, prevAddr := key(t)
	_, nextAddr := key(t)
	s := Succession{Prev: prevAddr, Next: nextAddr, Epoch: 5}
	h := Handover{Succession: s, Digest: s.Digest(), Signature: sign(t, prev, s.Digest())}

	if err := h.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The successor cannot sign its own succession: only the outgoing key can
	// hand the identity on, or a stake would move on the say-so of the address
	// receiving it.
	nextKey, _ := key(t)
	forged := Handover{Succession: s, Digest: s.Digest(), Signature: sign(t, nextKey, s.Digest())}
	if err := forged.Verify(); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify signed by the successor: got %v, want ErrSignature", err)
	}

	// Redirecting the successor invalidates it: next is in the preimage.
	redirected := h
	redirected.Next = Address{0x99}
	if err := redirected.Verify(); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify with a redirected successor: got %v, want ErrSignature", err)
	}
}

// A signature has exactly one valid encoding. secp256k1 admits (r, s) and
// (r, n-s) as signatures by the same key, so without a canonical rule the same
// statement has two spellings and a verifier that deduplicates by signature
// bytes can be shown it twice.
func TestRecoverRefusesTheHighSTwin(t *testing.T) {
	k, addr := key(t)
	a := Attestation{Address: addr, Measurement: measure(0xaa), Epoch: 1, Payload: []byte("p")}
	d := a.Digest()
	sig := sign(t, k, d)

	if got, err := Recover(d, sig); err != nil || got != addr {
		t.Fatalf("Recover: got %s err=%v, want %s", got, err, addr)
	}

	// Build the twin: s' = n - s, with v flipped so it recovers the same key.
	twin := sig
	s := new(big.Int).SetBytes(sig[32:64])
	high := new(big.Int).Sub(order, s)
	copy(twin[32:64], high.FillBytes(make([]byte, 32)))
	twin[64] ^= 1

	if _, err := Recover(d, twin); !errors.Is(err, ErrSignature) {
		t.Fatalf("Recover of the high-s twin: got %v, want ErrSignature", err)
	}
	if err := a.Verify(twin); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify of the high-s twin: got %v, want ErrSignature", err)
	}
}

func TestRecoverRefusesMalformedSignatures(t *testing.T) {
	k, addr := key(t)
	a := Attestation{Address: addr, Measurement: measure(0xaa), Epoch: 1, Payload: []byte("p")}
	d := a.Digest()
	good := sign(t, k, d)

	for name, mutate := range map[string]func(Signature) Signature{
		"v out of range": func(s Signature) Signature { s[64] = 27; return s },
		"v garbage":      func(s Signature) Signature { s[64] = 0xff; return s },
		"zero r":         func(s Signature) Signature { copy(s[:32], make([]byte, 32)); return s },
		"zero s":         func(s Signature) Signature { copy(s[32:64], make([]byte, 32)); return s },
		"empty":          func(Signature) Signature { return Signature{} },
	} {
		if _, err := Recover(d, mutate(good)); !errors.Is(err, ErrSignature) {
			t.Fatalf("Recover with %s: got %v, want ErrSignature", name, err)
		}
	}
}

func TestFixedWidthValuesRoundTripAsHex(t *testing.T) {
	k, addr := key(t)
	var pub PublicKey
	copy(pub[:], crypto.FromECDSAPub(&k.PublicKey))

	t.Run("address is checksummed", func(t *testing.T) {
		blob, err := json.Marshal(addr)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(blob) != `"`+crypto.PubkeyToAddress(k.PublicKey).Hex()+`"` {
			t.Fatalf("address encodes as %s, want the checksummed form", blob)
		}
		var back Address
		if err := json.Unmarshal(blob, &back); err != nil || back != addr {
			t.Fatalf("round trip: %v %v", back, err)
		}
		// A lower-case spelling is the same address; an operator types it either
		// way and must reach the same identity.
		lower, err := ParseAddress("0x" + hexOf(addr[:]))
		if err != nil || lower != addr {
			t.Fatalf("lower-case parse: %v %v", lower, err)
		}
	})

	t.Run("hash and signature", func(t *testing.T) {
		m := measure(0xaa)
		var h Hash
		if err := json.Unmarshal([]byte(`"`+m.String()+`"`), &h); err != nil || h != m {
			t.Fatalf("hash round trip: %v %v", h, err)
		}
		sig := sign(t, k, m)
		blob, _ := json.Marshal(sig)
		var back Signature
		if err := json.Unmarshal(blob, &back); err != nil || back != sig {
			t.Fatalf("signature round trip: %v", err)
		}
	})

	t.Run("public key derives the address", func(t *testing.T) {
		blob, _ := json.Marshal(pub)
		var back PublicKey
		if err := json.Unmarshal(blob, &back); err != nil || back != pub {
			t.Fatalf("public key round trip: %v", err)
		}
		recovered, err := crypto.UnmarshalPubkey(back[:])
		if err != nil {
			t.Fatalf("unmarshal pubkey: %v", err)
		}
		if Address(crypto.PubkeyToAddress(*recovered)) != addr {
			t.Fatal("published public key does not derive the address")
		}
	})

	t.Run("wrong widths are refused", func(t *testing.T) {
		if _, err := ParseAddress("0xdeadbeef"); err == nil {
			t.Fatal("a short address was accepted")
		}
		if _, err := ParseMeasurement("0xdeadbeef"); err == nil {
			t.Fatal("a short measurement was accepted")
		}
		if _, err := ParseSignature("0xdeadbeef"); err == nil {
			t.Fatal("a short signature was accepted")
		}
		if _, err := ParsePublicKey("0xdeadbeef"); err == nil {
			t.Fatal("a short public key was accepted")
		}
		if _, err := ParseAddress("0xzz00000000000000000000000000000000000000"); err == nil {
			t.Fatal("non-hex was accepted")
		}
		var a Address
		if err := json.Unmarshal([]byte(`"0xdeadbeef"`), &a); err == nil {
			t.Fatal("a short address survived JSON decoding")
		}
		if err := json.Unmarshal([]byte(`123`), &a); err == nil {
			t.Fatal("a non-string address survived JSON decoding")
		}
	})
}

// The payload is committed to but never carried: a receipt that echoed it would
// invite verifying against the server's copy rather than the caller's own.
func TestReceiptDoesNotCarryThePayload(t *testing.T) {
	a := Attestation{Address: Address{0x11}, Measurement: measure(0xaa), Epoch: 1, Payload: []byte("secret boot detail")}
	blob, err := json.Marshal(Receipt{Attestation: a, Digest: a.Digest()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(blob, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := probe["payload"]; ok {
		t.Fatalf("receipt carries the payload: %s", blob)
	}
	// The statement's own fields are flattened alongside the signature, so one
	// object is the whole statement plus its proof.
	for _, want := range []string{"address", "measurement", "epoch", "digest", "signature"} {
		if _, ok := probe[want]; !ok {
			t.Fatalf("receipt is missing %q: %s", want, blob)
		}
	}
}

func TestTEEVocabulary(t *testing.T) {
	for _, known := range []TEE{"", None, SevSnp, Tdx, Sgx} {
		if !known.Known() {
			t.Fatalf("%q should be known", known)
		}
	}
	if TEE("sev-es").Known() {
		t.Fatal("an undefined family was accepted")
	}
	for _, hw := range []TEE{SevSnp, Tdx, Sgx} {
		if !hw.Hardware() {
			t.Fatalf("%q should require a report", hw)
		}
	}
	for _, soft := range []TEE{"", None} {
		if soft.Hardware() {
			t.Fatalf("%q should not require a report", soft)
		}
	}
	if ev := Declare(measure(0xaa)); ev.TEE != None || ev.Quote != nil {
		t.Fatalf("Declare produced %+v", ev)
	}
}

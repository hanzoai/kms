package custody

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hanzoai/kms/sdk/go/node"
	"github.com/luxfi/crypto"
	badger "github.com/luxfi/zapdb"
)

const org = "hanzo"

var masterKey = bytes.Repeat([]byte{0x2b}, 32)

func newStore(t *testing.T) (*Store, *badger.DB) {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions(filepath.Join(t.TempDir(), "kms")).WithLogger(nil))
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db, masterKey)
	if err != nil {
		t.Fatalf("custody.New: %v", err)
	}
	return s, db
}

// image returns declared evidence for an image digest, which is what a host
// with no SEV-SNP or TDX presents.
func image(seed byte) node.Evidence {
	var m node.Measurement
	for i := range m {
		m[i] = seed
	}
	return node.Declare(m)
}

func mustEnroll(t *testing.T, s *Store, subject string, ev node.Evidence) *node.Record {
	t.Helper()
	rec, created, err := s.Enroll(org, subject, ev)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !created {
		t.Fatal("Enroll: expected a new identity")
	}
	return rec
}

func TestEnrollMintsWalletAndKeepsTheKey(t *testing.T) {
	s, db := newStore(t)
	rec := mustEnroll(t, s, "node-a", image(0x11))

	if rec.Status != node.Active || rec.Attested || rec.TEE != node.None {
		t.Fatalf("unexpected record state: %+v", rec)
	}

	// The address is the wallet: it must derive from the public key the record
	// publishes, so a reader can check the identity without asking us.
	pk, err := crypto.UnmarshalPubkey(rec.PublicKey[:])
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	if got := node.Address(crypto.PubkeyToAddress(*pk)); got != rec.Address {
		t.Fatalf("address %s does not derive from the published public key (%s)", rec.Address, got)
	}

	// The record carries no key material, and its serialization cannot leak
	// any: the sealed blob lives under a different store key entirely.
	blob, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"ciphertext", "wrapped_dek", "private"} {
		if bytes.Contains(bytes.ToLower(blob), []byte(forbidden)) {
			t.Fatalf("record serialization mentions %q: %s", forbidden, blob)
		}
	}

	// The two keyspaces are disjoint: nothing under the record prefix is
	// material, so no enumeration of nodes can reach a key.
	if err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte("kms/nodes/")
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			var probe map[string]any
			if err := it.Item().Value(func(v []byte) error { return json.Unmarshal(v, &probe) }); err != nil {
				return err
			}
			if _, ok := probe["wrapped_dek"]; ok {
				return errors.New("material found under the record prefix")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollIsIdempotentPerSubject(t *testing.T) {
	s, _ := newStore(t)
	first := mustEnroll(t, s, "node-a", image(0x11))

	again, created, err := s.Enroll(org, "node-a", image(0x11))
	if err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if created {
		t.Fatal("second Enroll minted a second identity")
	}
	if again.Address != first.Address {
		t.Fatalf("second Enroll returned %s, want %s", again.Address, first.Address)
	}
}

func TestEnrollRefusesADifferentImage(t *testing.T) {
	s, _ := newStore(t)
	mustEnroll(t, s, "node-a", image(0x11))

	if _, _, err := s.Enroll(org, "node-a", image(0x22)); !errors.Is(err, ErrDrift) {
		t.Fatalf("Enroll under a changed image: got %v, want ErrDrift", err)
	}
}

func TestEnrollAfterRevocationMintsAFreshIdentity(t *testing.T) {
	s, _ := newStore(t)
	first := mustEnroll(t, s, "node-a", image(0x11))
	if _, err := s.Revoke(org, first.Address, "decommissioned"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	second := mustEnroll(t, s, "node-a", image(0x11))
	if second.Address == first.Address {
		t.Fatal("a revoked identity was handed back")
	}
}

// The receipt is checked through the protocol's own verifier — the same call
// the node daemon and the chain indexer make — rather than by re-deriving the
// digest here. A test that rebuilt the preimage would pass even if the preimage
// were wrong.
func TestSignProducesAReceiptThatVerifies(t *testing.T) {
	s, _ := newStore(t)
	ev := image(0x11)
	rec := mustEnroll(t, s, "node-a", ev)

	payload := []byte("boot measurement report")
	receipt, err := s.Sign(org, rec.Address, "node-a", ev, 1, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := receipt.Verify(payload); err != nil {
		t.Fatalf("receipt does not verify: %v", err)
	}
	if receipt.Address != rec.Address || receipt.Epoch != 1 {
		t.Fatalf("receipt names the wrong statement: %+v", receipt)
	}
	// The receipt states the image the key is sealed to, so a verifier learns
	// which image signed without a second lookup.
	if receipt.Measurement != ev.Measurement {
		t.Fatalf("receipt measurement %s, want %s", receipt.Measurement, ev.Measurement)
	}
	// It is evidence about these bytes and no others.
	if err := receipt.Verify([]byte("a different report")); err == nil {
		t.Fatal("the receipt verified against a payload that was never signed")
	}
}

func TestSignRefusesAnotherImage(t *testing.T) {
	s, _ := newStore(t)
	rec := mustEnroll(t, s, "node-a", image(0x11))

	// The refusal is the cipher's: the associated data the caller presents does
	// not authenticate the sealed record, so no comparison has to be trusted.
	if _, err := s.Sign(org, rec.Address, "node-a", image(0x22), 1, []byte("x")); !errors.Is(err, ErrDrift) {
		t.Fatalf("Sign under a changed image: got %v, want ErrDrift", err)
	}
}

func TestSignRefusesAReplayedEpoch(t *testing.T) {
	s, _ := newStore(t)
	ev := image(0x11)
	rec := mustEnroll(t, s, "node-a", ev)

	if _, err := s.Sign(org, rec.Address, "node-a", ev, 7, []byte("x")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for _, epoch := range []uint64{7, 6, 0} {
		if _, err := s.Sign(org, rec.Address, "node-a", ev, epoch, []byte("x")); !errors.Is(err, ErrEpoch) {
			t.Fatalf("Sign at epoch %d: got %v, want ErrEpoch", epoch, err)
		}
	}
	if _, err := s.Sign(org, rec.Address, "node-a", ev, 8, []byte("x")); err != nil {
		t.Fatalf("Sign at a later epoch: %v", err)
	}
}

func TestSignRefusesAnotherSubject(t *testing.T) {
	s, _ := newStore(t)
	ev := image(0x11)
	rec := mustEnroll(t, s, "node-a", ev)

	// A second node in the same tenant holds a credential for the same org.
	// Without this check it could keep a decommissioned node looking alive.
	if _, err := s.Sign(org, rec.Address, "node-b", ev, 1, []byte("x")); !errors.Is(err, ErrSubject) {
		t.Fatalf("Sign as another subject: got %v, want ErrSubject", err)
	}
}

func TestRotateSignsASuccessionAndEndsTheOldKey(t *testing.T) {
	s, _ := newStore(t)
	ev := image(0x11)
	prev := mustEnroll(t, s, "node-a", ev)

	next, handover, err := s.Rotate(org, prev.Address, "node-a", ev, 5)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if next.Address == prev.Address {
		t.Fatal("rotation reused the address; a wallet's key cannot change under a fixed address")
	}
	if next.Prev == nil || *next.Prev != prev.Address || next.Status != node.Active || next.Measurement != prev.Measurement {
		t.Fatalf("successor is not linked to its predecessor: %+v", next)
	}

	// The succession is verifiable against the address the L1 already knows, and
	// it is self-contained: nothing outside it has to be supplied.
	if err := handover.Verify(); err != nil {
		t.Fatalf("succession does not verify: %v", err)
	}
	if handover.Prev != prev.Address || handover.Next != next.Address || handover.Epoch != 5 {
		t.Fatalf("succession names the wrong handover: %+v", handover)
	}

	// The outgoing record survives, carries the statement it signed, and can
	// never sign again.
	old, err := s.Get(org, prev.Address)
	if err != nil {
		t.Fatalf("Get outgoing: %v", err)
	}
	if old.Status != node.Superseded || old.Next == nil || *old.Next != next.Address || old.Succession == nil {
		t.Fatalf("outgoing record is not a readable tombstone: %+v", old)
	}
	if err := old.Succession.Verify(); err != nil {
		t.Fatalf("the recorded succession does not verify: %v", err)
	}
	if _, err := s.Sign(org, prev.Address, "node-a", ev, 6, []byte("x")); !errors.Is(err, ErrNotActive) {
		t.Fatalf("Sign with a superseded identity: got %v, want ErrNotActive", err)
	}
	if _, err := s.material(org, prev.Address); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("outgoing key material survived rotation: %v", err)
	}

	// Revoking the predecessor would erase the record of the handover, and the
	// successor is the identity a compromise reaches.
	if _, err := s.Revoke(org, prev.Address, "late"); !errors.Is(err, ErrNotActive) {
		t.Fatalf("Revoke a superseded identity: got %v, want ErrNotActive", err)
	}

	// The successor signs from the epoch the succession fixed, not before it.
	if _, err := s.Sign(org, next.Address, "node-a", ev, 5, []byte("x")); !errors.Is(err, ErrEpoch) {
		t.Fatalf("successor signing at the succession epoch: got %v, want ErrEpoch", err)
	}
	if _, err := s.Sign(org, next.Address, "node-a", ev, 6, []byte("x")); err != nil {
		t.Fatalf("successor Sign: %v", err)
	}
}

func TestRotateLeavesExactlyOneActiveIdentityForTheSubject(t *testing.T) {
	s, _ := newStore(t)
	ev := image(0x11)
	prev := mustEnroll(t, s, "node-a", ev)

	next, _, err := s.Rotate(org, prev.Address, "node-a", ev, 5)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	active, err := s.activeBySubject(org, "node-a")
	if err != nil {
		t.Fatalf("activeBySubject: %v", err)
	}
	if active == nil || active.Address != next.Address {
		t.Fatalf("the subject's active identity is %v, want the successor %s", active, next.Address)
	}
	// A node that restarts after a rotation gets its successor, not a third
	// identity.
	back, created, err := s.Enroll(org, "node-a", ev)
	if err != nil || created || back.Address != next.Address {
		t.Fatalf("re-enroll after rotation: %s created=%v err=%v", back.Address, created, err)
	}
}

// The measurement gate is the cipher's, not a comparison's: the sealed blob is
// authenticated under the coordinates it was sealed at, so opening it under any
// other measurement fails inside AES-GCM.
func TestTheSealItselfRefusesAnotherMeasurement(t *testing.T) {
	s, _ := newStore(t)
	rec := mustEnroll(t, s, "node-a", image(0x11))

	sealed, err := s.material(org, rec.Address)
	if err != nil {
		t.Fatalf("material: %v", err)
	}
	if _, err := s.open(sealed, rec.Address, image(0x11).Measurement); err != nil {
		t.Fatalf("open under the sealed measurement: %v", err)
	}
	if _, err := s.open(sealed, rec.Address, image(0x22).Measurement); !errors.Is(err, ErrDrift) {
		t.Fatalf("open under another measurement: got %v, want ErrDrift", err)
	}
	// The address is bound too: the same blob under a neighbour's address is not
	// that neighbour's key.
	other := mustEnroll(t, s, "node-b", image(0x11))
	if _, err := s.open(sealed, other.Address, image(0x11).Measurement); !errors.Is(err, ErrDrift) {
		t.Fatalf("open under another address: got %v, want ErrDrift", err)
	}
}

func TestRebindMovesTheKeyToANewImage(t *testing.T) {
	s, _ := newStore(t)
	from, to := image(0x11), image(0x22)
	rec := mustEnroll(t, s, "node-a", from)

	moved, err := s.Rebind(org, rec.Address, from, to)
	if err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	if moved.Address != rec.Address {
		t.Fatal("rebinding changed the identity; it must only change the image")
	}
	if moved.Measurement != to.Measurement {
		t.Fatal("rebinding did not move the measurement")
	}
	if _, err := s.Sign(org, rec.Address, "node-a", from, 1, []byte("x")); !errors.Is(err, ErrDrift) {
		t.Fatalf("Sign under the retired image: got %v, want ErrDrift", err)
	}
	receipt, err := s.Sign(org, rec.Address, "node-a", to, 1, []byte("x"))
	if err != nil {
		t.Fatalf("Sign under the new image: %v", err)
	}
	// The statement follows the key onto the new image, so a receipt minted
	// after a rebinding attests the image the node is actually running.
	if receipt.Measurement != to.Measurement {
		t.Fatalf("receipt still attests the retired image: %s", receipt.Measurement)
	}
	if err := receipt.Verify([]byte("x")); err != nil {
		t.Fatalf("receipt after rebinding does not verify: %v", err)
	}
}

// Rebinding cannot be used to launder a hardware claim: the destination evidence
// goes through the same admission check as any other.
func TestRebindRefusesAnUnbackedHardwareClaim(t *testing.T) {
	s, _ := newStore(t)
	from := image(0x11)
	rec := mustEnroll(t, s, "node-a", from)

	to := node.Evidence{TEE: node.SevSnp, Measurement: image(0x22).Measurement, Quote: []byte("report")}
	if _, err := s.Rebind(org, rec.Address, from, to); !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("Rebind onto an unbacked TEE claim: got %v, want ErrNoVerifier", err)
	}
	// The identity is untouched: it still opens under the image it was sealed to.
	if _, err := s.Sign(org, rec.Address, "node-a", from, 1, []byte("x")); err != nil {
		t.Fatalf("identity was damaged by the refused rebinding: %v", err)
	}
}

func TestRevokeDestroysTheKeyAndKeepsTheRow(t *testing.T) {
	s, _ := newStore(t)
	ev := image(0x11)
	rec := mustEnroll(t, s, "node-a", ev)

	revoked, err := s.Revoke(org, rec.Address, "slashed: missing attestation")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if revoked.Status != node.Revoked || revoked.Reason == "" {
		t.Fatalf("revocation is not recorded: %+v", revoked)
	}
	if _, err := s.material(org, rec.Address); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("key material survived revocation: %v", err)
	}
	if _, err := s.Sign(org, rec.Address, "node-a", ev, 1, []byte("x")); !errors.Is(err, ErrNotActive) {
		t.Fatalf("Sign with a revoked identity: got %v, want ErrNotActive", err)
	}
	if _, err := s.Rebind(org, rec.Address, ev, image(0x22)); !errors.Is(err, ErrNotActive) {
		t.Fatalf("Rebind a revoked identity: got %v, want ErrNotActive", err)
	}
	if _, _, err := s.Rotate(org, rec.Address, "node-a", ev, 9); !errors.Is(err, ErrNotActive) {
		t.Fatalf("Rotate a revoked identity: got %v, want ErrNotActive", err)
	}
	// Revocation is terminal and idempotent: asking twice is not an error, and
	// there is no path that returns it to service.
	if again, err := s.Revoke(org, rec.Address, "again"); err != nil || again.Status != node.Revoked {
		t.Fatalf("second Revoke: %+v %v", again, err)
	}

	// The fleet still lists it: a slashed node has to stay attributable.
	fleet, err := s.List(org)
	if err != nil || fleet.Truncated {
		t.Fatalf("List: %v truncated=%v", err, fleet)
	}
	if len(fleet.Nodes) != 1 || fleet.Nodes[0].Status != node.Revoked {
		t.Fatalf("revoked identity dropped out of the fleet view: %+v", fleet.Nodes)
	}
}

func TestVerifyRefusesAnUnbackedHardwareClaim(t *testing.T) {
	m := image(0x11).Measurement

	if _, attested, err := Verify(node.Declare(m)); err != nil || attested {
		t.Fatalf("declared evidence: got attested=%v err=%v", attested, err)
	}
	for _, tee := range []node.TEE{node.SevSnp, node.Tdx, node.Sgx} {
		_, attested, err := Verify(node.Evidence{TEE: tee, Measurement: m, Quote: []byte("report")})
		if !errors.Is(err, ErrNoVerifier) || attested {
			t.Fatalf("%s claim: got attested=%v err=%v, want ErrNoVerifier", tee, attested, err)
		}
		// A hardware family is refused whether or not a report accompanies it —
		// the refusal is about the absent verifier, not the absent report.
		if _, _, err := Verify(node.Evidence{TEE: tee, Measurement: m}); !errors.Is(err, ErrNoVerifier) {
			t.Fatalf("%s claim with no report: got %v, want ErrNoVerifier", tee, err)
		}
	}
	if _, _, err := Verify(node.Evidence{TEE: node.None, Measurement: m, Quote: []byte("report")}); !errors.Is(err, ErrQuoteNoTEE) {
		t.Fatalf("quote without a TEE: got %v, want ErrQuoteNoTEE", err)
	}
	if _, _, err := Verify(node.Evidence{TEE: node.None}); !errors.Is(err, ErrMeasurement) {
		t.Fatalf("zero measurement: got %v, want ErrMeasurement", err)
	}
	if _, _, err := Verify(node.Evidence{TEE: "sev-es", Measurement: m}); err == nil {
		t.Fatal("an unknown TEE name was accepted")
	}
	// An empty family reads as None, so a caller that omits the field is not
	// silently treated as claiming hardware.
	if _, attested, err := Verify(node.Evidence{Measurement: m}); err != nil || attested {
		t.Fatalf("omitted family: got attested=%v err=%v", attested, err)
	}
}

func TestNewRefusesAWeakMasterKey(t *testing.T) {
	db, err := badger.Open(badger.DefaultOptions(filepath.Join(t.TempDir(), "kms")).WithLogger(nil))
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	defer db.Close()
	if _, err := New(db, []byte("short")); !errors.Is(err, ErrMasterKey) {
		t.Fatalf("New with a short key: got %v, want ErrMasterKey", err)
	}
	if _, err := New(nil, masterKey); err == nil {
		t.Fatal("New with no store was accepted")
	}
}

func TestUnknownNodeIsNotFound(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Get(org, node.Address{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get: got %v, want ErrNotFound", err)
	}
	if _, _, err := s.Enroll("bad/org", "node-a", image(0x11)); !errors.Is(err, ErrOrg) {
		t.Fatalf("Enroll into a path-shaped org: got %v, want ErrOrg", err)
	}
	if _, _, err := s.Enroll(org, "", image(0x11)); !errors.Is(err, ErrSubject) {
		t.Fatalf("Enroll with no subject: got %v, want ErrSubject", err)
	}
}

// One tenant's fleet is not another's. The org is part of every store key, so a
// record minted in one tenant is invisible and unreachable from the other even
// under the same address.
func TestTenantsAreIsolatedInTheKeyspace(t *testing.T) {
	s, _ := newStore(t)
	ev := image(0x11)
	mine := mustEnroll(t, s, "node-a", ev)

	other, created, err := s.Enroll("zoo", "node-a", ev)
	if err != nil || !created {
		t.Fatalf("Enroll into a second tenant: %v", err)
	}
	if other.Address == mine.Address {
		t.Fatal("two tenants were handed the same wallet")
	}
	if _, err := s.Get("zoo", mine.Address); !errors.Is(err, ErrNotFound) {
		t.Fatalf("one tenant reached another's identity: %v", err)
	}
	if _, err := s.Sign("zoo", mine.Address, "node-a", ev, 1, []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("one tenant signed with another's identity: %v", err)
	}
	fleet, err := s.List(org)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(fleet.Nodes) != 1 || fleet.Nodes[0].Address != mine.Address {
		t.Fatalf("fleet listing crossed the tenant boundary: %+v", fleet.Nodes)
	}
	// A tenant whose name is a prefix of another's does not inherit its rows.
	if _, _, err := s.Enroll("hanzoai", "node-b", ev); err != nil {
		t.Fatalf("Enroll into a prefix-shaped tenant: %v", err)
	}
	if fleet, err := s.List(org); err != nil || len(fleet.Nodes) != 1 {
		t.Fatalf("a tenant named as a prefix leaked rows: %+v %v", fleet, err)
	}
}

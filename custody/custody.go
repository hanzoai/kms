// Package custody holds a node's identity keypair on the node's behalf.
//
// A Hanzo node is named by a wallet: a secp256k1 keypair whose address is the
// node's identity on the settlement L1, the account its stake is bonded from,
// the account its AI-work rewards pay to, and the row the fleet view lists it
// under. One key, four uses — so a key that can be copied is an identity that
// can be forged and a stake that can be spent by someone else. This package is
// the answer to that: the private key is generated inside the KMS process,
// sealed before it reaches storage, and returned to no one. A node does not
// hold its key. It asks for signatures.
//
// The statements those signatures are over, the wire types, and the check a
// verifier runs all live in [github.com/hanzoai/kms/sdk/go/node], which the node
// daemon and the chain indexer import too. This package holds what they must
// not: the key, and the rules about when it may be used.
//
// # What the seal is bound to
//
// The envelope is the store's own — a fresh 256-bit DEK per record, AES-256-GCM
// over the key material, the DEK wrapped under the KMS master key (store.Seal).
// What custody supplies is the associated data. The three coordinates store.Seal
// authenticates are chosen to BE the custody binding:
//
//	path = "node"          separates custody material from the secret keyspace
//	name = wallet address  the identity the key is
//	env  = measurement     the image the key may be used from
//
// so the measurement is not compared, it is required. A record sealed under one
// measurement raises a GCM authentication failure under any other, and unseal
// accepts only the measurement the CALLER presents — never the one recorded
// beside the record. An edit that later drops a policy check therefore still
// cannot produce plaintext under the wrong image.
//
// # What the binding proves today, and what it will prove on TEE hardware
//
// The measurement is attestation.NodeAttestation's CpuTeeMeasurement. On a host
// running SEV-SNP or TDX it is the launch measurement the CPU computes over the
// guest image and signs into an attestation report: an unforgeable statement of
// which image is running. On the hardware this fleet runs today — Apple Silicon
// under the Virtualization framework, x86-64 and arm64 hosts with no SEV-SNP or
// TDX — no such report exists, and the node DECLARES the value: the digest of
// the microVM kernel and root filesystem it booted.
//
// The two cases differ in authenticity, not in mechanism. Declared evidence is
// recorded as declared (Record.Attested is false) and yields exactly one
// enforceable property: the key is usable from one image digest, and changing
// the image makes every unseal and every signature fail until an operator
// rebinds it. That detects drift. It does not prove the image, because the value
// it pins is one the node chose. Hardware evidence closes that gap and changes
// no other line of this package.
//
// A node that claims a TEE without supplying a verifiable report is refused
// rather than downgraded (see Verify). "Attested" is a fact this KMS records
// about a node; recording it on a claim would make the fleet view a lie.
package custody

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/kms/sdk/go/node"
	"github.com/luxfi/crypto"
	"github.com/luxfi/kms/pkg/attestation"
	"github.com/luxfi/kms/pkg/store"
	badger "github.com/luxfi/zapdb"
)

// Errors the caller distinguishes. Everything else is an internal failure and
// carries no detail outward.
var (
	ErrNotFound     = errors.New("custody: node not found")
	ErrDrift        = errors.New("custody: measurement differs from the one this identity is sealed to")
	ErrNotActive    = errors.New("custody: identity is not active")
	ErrSubject      = errors.New("custody: caller is not the subject this identity was enrolled to")
	ErrEpoch        = errors.New("custody: epoch must exceed the last epoch signed")
	ErrMeasurement  = errors.New("custody: measurement is required and must be non-zero")
	ErrQuoteNoTEE   = errors.New("custody: a quote was supplied but no TEE was named")
	ErrNoVerifier   = errors.New("custody: no verifier is linked for this TEE family, so its measurement cannot be recorded as attested")
	ErrMasterKey    = errors.New("custody: master key must be 32 bytes")
	ErrOrg          = errors.New("custody: org must be a single non-empty path segment")
	ErrKeyDestroyed = errors.New("custody: key material for this identity has been destroyed")
)

// kind maps a TEE name onto the upstream enum, so a custody record and an
// attestation.NodeAttestation agree on what a family is. It is where the report
// verifier will attach when one is linked.
func kind(t node.TEE) (attestation.CpuTeeKind, bool) {
	switch t {
	case "", node.None:
		return attestation.CpuTeeNone, true
	case node.SevSnp:
		return attestation.CpuTeeSevSnp, true
	case node.Tdx:
		return attestation.CpuTeeTdx, true
	case node.Sgx:
		return attestation.CpuTeeSgx, true
	}
	return attestation.CpuTeeNone, false
}

// Verify reads the measurement a node may be sealed under and reports whether
// hardware produced it.
//
// Under None the measurement is taken as declared: it is the node's own claim
// about its image, it is recorded as unattested, and it still binds the key to
// exactly that one image. Under any hardware family the report has to be checked
// against the vendor's root before the measurement means anything, and no such
// verifier is linked into this build — so the claim is refused. Refusing is the
// only safe direction: accepting an unchecked report would let any caller mark
// its node TEE-backed in the fleet view, which is worse than declaring nothing,
// because a reader would then treat an unverified claim as a verified one.
func Verify(ev node.Evidence) (node.Measurement, bool, error) {
	if ev.Measurement.IsZero() {
		return node.Measurement{}, false, ErrMeasurement
	}
	if _, ok := kind(ev.TEE); !ok {
		return node.Measurement{}, false, fmt.Errorf("custody: unknown tee %q", string(ev.TEE))
	}
	if !ev.TEE.Hardware() {
		if len(ev.Quote) != 0 {
			return node.Measurement{}, false, ErrQuoteNoTEE
		}
		return ev.Measurement, false, nil
	}
	return node.Measurement{}, false, fmt.Errorf("%w: %s", ErrNoVerifier, ev.TEE)
}

// Store keeps node identities and operates on them. The two keyspaces are
// disjoint by construction: a record is addressable, its material is not
// reachable from any enumeration of records.
type Store struct {
	db        *badger.DB
	masterKey []byte

	// mu serializes the read-modify-write paths (enroll, sign, rotate, rebind,
	// revoke). Custody operations run once per node boot at most, so one lock is
	// cheaper and clearer than optimistic retry over ZapDB transactions.
	mu sync.Mutex
}

// New returns a Store sealing under masterKey. The key is the KMS record master
// (KMS_MASTER_KEY_B64), not the volume key: a leaked volume key alone therefore
// does not yield a node private key.
func New(db *badger.DB, masterKey []byte) (*Store, error) {
	if db == nil {
		return nil, errors.New("custody: nil store")
	}
	if len(masterKey) != 32 {
		return nil, ErrMasterKey
	}
	k := make([]byte, len(masterKey))
	copy(k, masterKey)
	return &Store{db: db, masterKey: k}, nil
}

// maxList bounds one fleet enumeration. The scan is cheap per row, but an
// unbounded answer is an authenticated amplification lever; a caller that hits
// the cap is told so rather than handed a short list that reads as the whole
// fleet.
const maxList = 10000

func recordPrefix(org string) []byte { return []byte("kms/nodes/" + org + "/") }

func recordKey(org string, address node.Address) []byte {
	return append(recordPrefix(org), address.String()...)
}

func materialKey(org string, address node.Address) []byte {
	return []byte("kms/custody/" + org + "/" + address.String())
}

// validOrg rejects an org that would make a store key ambiguous. The HTTP layer
// validates it too; this package owns its own keyspace and does not delegate
// that.
func validOrg(org string) bool {
	if org == "" || strings.TrimSpace(org) != org {
		return false
	}
	for _, r := range org {
		if r == '/' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// seal binds priv to (address, measurement) through the record envelope's
// associated data. The plaintext is zeroed by the caller.
func (s *Store) seal(address node.Address, m node.Measurement, priv []byte) (*store.Secret, error) {
	return store.Seal(s.masterKey, "node", address.String(), m.String(), priv)
}

// open inverts seal under the measurement the CALLER presents. The coordinates
// recorded beside the sealed blob are overwritten before the open, so a stored
// measurement can never be the one that authorizes an unseal.
func (s *Store) open(sealed *store.Secret, address node.Address, m node.Measurement) ([]byte, error) {
	presented := *sealed
	presented.Path, presented.Name, presented.Env = "node", address.String(), m.String()
	priv, err := store.Open(s.masterKey, &presented)
	if err != nil {
		return nil, ErrDrift
	}
	return priv, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func ptr(a node.Address) *node.Address { return &a }

// Enroll mints a node identity for subject in org, or returns the one it
// already has.
//
// Enrollment is idempotent on the enrolling IAM subject: one active identity per
// subject per org. A second enrollment presenting the same measurement returns
// the same record (created is false). A second enrollment presenting a DIFFERENT
// measurement is refused with ErrDrift rather than minting a second identity —
// an image that was not approved must not be able to walk away with a fresh
// wallet, and the operator's sanctioned move is Rebind. Revoked and superseded
// records are ignored by this lookup, so a decommissioned node's operator can
// bring up a new identity without an administrator in the loop.
func (s *Store) Enroll(org, subject string, ev node.Evidence) (*node.Record, bool, error) {
	if !validOrg(org) {
		return nil, false, ErrOrg
	}
	if subject == "" {
		return nil, false, ErrSubject
	}
	m, attested, err := Verify(ev)
	if err != nil {
		return nil, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, err := s.activeBySubject(org, subject); err != nil {
		return nil, false, err
	} else if rec != nil {
		if rec.Measurement != m {
			return nil, false, ErrDrift
		}
		return rec, false, nil
	}

	priv, err := crypto.GenerateKey()
	if err != nil {
		return nil, false, fmt.Errorf("custody: generate: %w", err)
	}
	defer returnKey(priv)

	rec, sealed, err := s.mint(org, subject, priv, m, ev.TEE, attested, nil)
	if err != nil {
		return nil, false, err
	}
	if err := s.write(rec, sealed); err != nil {
		return nil, false, err
	}
	return rec, true, nil
}

// mint seals a freshly generated key and returns the two halves to be written.
// It writes nothing itself, so a caller that has more than one record to change
// can commit them together. The private scalar leaves memory zeroed either way.
func (s *Store) mint(org, subject string, priv *ecdsa.PrivateKey, m node.Measurement, tee node.TEE, attested bool, prev *node.Address) (*node.Record, *store.Secret, error) {
	if tee == "" {
		tee = node.None
	}
	address := node.Address(crypto.PubkeyToAddress(priv.PublicKey))
	raw := crypto.FromECDSA(priv)
	sealed, err := s.seal(address, m, raw)
	zero(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("custody: seal: %w", err)
	}

	var pub node.PublicKey
	copy(pub[:], crypto.FromECDSAPub(&priv.PublicKey))

	now := time.Now().UTC()
	return &node.Record{
		Address:     address,
		Org:         org,
		Subject:     subject,
		PublicKey:   pub,
		Measurement: m,
		TEE:         tee,
		Attested:    attested,
		Status:      node.Active,
		Prev:        prev,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, sealed, nil
}

// write persists a record and, when sealed is non-nil, its material. Both land
// in one ZapDB transaction so a record can never exist without the key it names.
func (s *Store) write(rec *node.Record, sealed *store.Secret) error {
	recBytes, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	var sealedBytes []byte
	if sealed != nil {
		if sealedBytes, err = json.Marshal(sealed); err != nil {
			return err
		}
	}
	return s.db.Update(func(txn *badger.Txn) error {
		if err := txn.Set(recordKey(rec.Org, rec.Address), recBytes); err != nil {
			return err
		}
		if sealedBytes != nil {
			return txn.Set(materialKey(rec.Org, rec.Address), sealedBytes)
		}
		return nil
	})
}

// destroy removes the sealed material and rewrites the record. After this the
// identity can never sign again, whatever later happens to the master key.
func (s *Store) destroy(rec *node.Record) error {
	recBytes, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		if err := txn.Set(recordKey(rec.Org, rec.Address), recBytes); err != nil {
			return err
		}
		if err := txn.Delete(materialKey(rec.Org, rec.Address)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return nil
	})
}

// Get returns one node record.
func (s *Store) Get(org string, address node.Address) (*node.Record, error) {
	if !validOrg(org) {
		return nil, ErrOrg
	}
	var rec node.Record
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(recordKey(org, address))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error { return json.Unmarshal(v, &rec) })
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// List returns every node identity in org, ordered by address so two runs over
// the same data are byte-identical. Fleet.Truncated reports that the fleet
// exceeded maxList and the answer is a bounded prefix.
func (s *Store) List(org string) (*node.Fleet, error) {
	if !validOrg(org) {
		return nil, ErrOrg
	}
	fleet := &node.Fleet{Nodes: []*node.Record{}}
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = recordPrefix(org)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			if len(fleet.Nodes) >= maxList {
				fleet.Truncated = true
				return nil
			}
			var rec node.Record
			if err := it.Item().Value(func(v []byte) error { return json.Unmarshal(v, &rec) }); err != nil {
				return err
			}
			fleet.Nodes = append(fleet.Nodes, &rec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fleet, nil
}

// activeBySubject finds the org's active identity for an IAM subject. It scans
// rather than consulting an index: enrollment happens once per node lifetime, and
// a second index is a second truth that can disagree with the first.
//
// The scan is deliberately not List's: List bounds its ANSWER, and a bounded
// answer here would mean a node past the cap failing to find the identity it
// already has and being handed a second one. This holds one record at a time, so
// there is nothing to bound.
func (s *Store) activeBySubject(org, subject string) (*node.Record, error) {
	var found *node.Record
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = recordPrefix(org)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			var rec node.Record
			if err := it.Item().Value(func(v []byte) error { return json.Unmarshal(v, &rec) }); err != nil {
				return err
			}
			if rec.Status == node.Active && rec.Subject == subject {
				found = &rec
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// material loads the sealed blob for a record.
func (s *Store) material(org string, address node.Address) (*store.Secret, error) {
	var sealed store.Secret
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(materialKey(org, address))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrKeyDestroyed
		}
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error { return json.Unmarshal(v, &sealed) })
	})
	if err != nil {
		return nil, err
	}
	return &sealed, nil
}

// unseal opens a record's key under the presented evidence. The returned key is
// the caller's to use and to discard; use returnKey.
func (s *Store) unseal(rec *node.Record, ev node.Evidence) (*ecdsa.PrivateKey, error) {
	m, _, err := Verify(ev)
	if err != nil {
		return nil, err
	}
	sealed, err := s.material(rec.Org, rec.Address)
	if err != nil {
		return nil, err
	}
	raw, err := s.open(sealed, rec.Address, m)
	if err != nil {
		return nil, err
	}
	priv, err := crypto.ToECDSA(raw)
	zero(raw)
	if err != nil {
		return nil, fmt.Errorf("custody: key material is not a valid secp256k1 scalar: %w", err)
	}
	return priv, nil
}

// returnKey overwrites the scalar a private key was reconstructed from. The
// big.Int the ecdsa key holds cannot be wiped in place, so this bounds the
// lifetime of the copy this package made rather than eliminating every copy the
// runtime may hold.
func returnKey(priv *ecdsa.PrivateKey) {
	if priv != nil && priv.D != nil {
		priv.D.SetInt64(0)
	}
}

// sign produces a signature over a statement's digest. It is the only place a
// node key is applied to anything, and the digest reaching it is always one the
// node package built from a fixed-length preimage.
func sign(d node.Hash, priv *ecdsa.PrivateKey) (node.Signature, error) {
	var sig node.Signature
	raw, err := crypto.Sign(d[:], priv)
	if err != nil {
		return sig, fmt.Errorf("custody: sign: %w", err)
	}
	if len(raw) != len(sig) {
		return sig, fmt.Errorf("custody: signature is %d bytes, want %d", len(raw), len(sig))
	}
	copy(sig[:], raw)
	return sig, nil
}

// signable checks the three preconditions every signing path shares: the record
// is active, the caller is the subject it was enrolled to, and the epoch moves
// forward. Anything else refuses before key material is touched.
func signable(rec *node.Record, subject string, epoch uint64) error {
	if rec.Status != node.Active {
		return fmt.Errorf("%w: %s", ErrNotActive, rec.Status)
	}
	if subject == "" || rec.Subject != subject {
		return ErrSubject
	}
	if epoch <= rec.Epoch {
		return fmt.Errorf("%w: last %d, presented %d", ErrEpoch, rec.Epoch, epoch)
	}
	return nil
}

// Sign issues one attestation signature on the node's behalf.
//
// The node presents its evidence, an epoch and the payload it wants attested.
// The private key is unsealed under that evidence, used once, and discarded.
// What comes back commits to the node's address and to the measurement it is
// sealed to, so a verifier reading the receipt learns which node signed and
// which image it was running without trusting either claim separately.
func (s *Store) Sign(org string, address node.Address, subject string, ev node.Evidence, epoch uint64, payload []byte) (*node.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.Get(org, address)
	if err != nil {
		return nil, err
	}
	if err := signable(rec, subject, epoch); err != nil {
		return nil, err
	}
	priv, err := s.unseal(rec, ev)
	if err != nil {
		return nil, err
	}
	defer returnKey(priv)

	// The measurement in the statement is the record's, not the presented one.
	// They are equal whenever the unseal above succeeded — that is what the seal
	// enforces — and taking the record's makes the statement independent of
	// anything the caller supplied.
	statement := node.Attestation{
		Address:     rec.Address,
		Measurement: rec.Measurement,
		Epoch:       epoch,
		Payload:     payload,
	}
	digest := statement.Digest()
	sig, err := sign(digest, priv)
	if err != nil {
		return nil, err
	}

	rec.Epoch = epoch
	rec.UpdatedAt = time.Now().UTC()
	if err := s.write(rec, nil); err != nil {
		return nil, err
	}
	statement.Payload = nil
	return &node.Receipt{Attestation: statement, Digest: digest, Signature: sig}, nil
}

// Rotate replaces a node's keypair and links the old identity to the new one.
//
// A wallet's private key cannot be changed while its address stays the same, so
// rotation is a change of identity and has to be provable as one. The outgoing
// key signs a succession naming its successor, that statement is recorded on the
// outgoing record where it can be read again, and the outgoing material is then
// destroyed. The settlement L1 moves stake by verifying the succession against
// the address it already knows — no second authority is involved.
//
// The successor is sealed under the same measurement: rotation changes the key,
// not the image. Rebind changes the image.
func (s *Store) Rotate(org string, address node.Address, subject string, ev node.Evidence, epoch uint64) (*node.Record, *node.Handover, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev, err := s.Get(org, address)
	if err != nil {
		return nil, nil, err
	}
	if err := signable(prev, subject, epoch); err != nil {
		return nil, nil, err
	}
	priv, err := s.unseal(prev, ev)
	if err != nil {
		return nil, nil, err
	}
	defer returnKey(priv)

	successor, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("custody: generate: %w", err)
	}
	defer returnKey(successor)

	nextRec, sealed, err := s.mint(org, subject, successor, prev.Measurement, prev.TEE, prev.Attested, ptr(prev.Address))
	if err != nil {
		return nil, nil, err
	}
	nextRec.Epoch = epoch

	statement := node.Succession{Prev: prev.Address, Next: nextRec.Address, Epoch: epoch}
	digest := statement.Digest()
	sig, err := sign(digest, priv)
	if err != nil {
		return nil, nil, err
	}
	handover := &node.Handover{Succession: statement, Digest: digest, Signature: sig}

	prev.Status = node.Superseded
	prev.Next = ptr(nextRec.Address)
	prev.Succession = handover
	prev.Epoch = epoch
	prev.UpdatedAt = time.Now().UTC()

	// One transaction, because the intermediate states are both wrong: two
	// active identities for one subject if the successor lands alone, and a node
	// with no usable key if the predecessor is retired alone.
	if err := s.handOver(prev, nextRec, sealed); err != nil {
		return nil, nil, err
	}
	return nextRec, handover, nil
}

// handOver commits a rotation: the successor and its material appear, the
// predecessor becomes a tombstone, and the predecessor's material is gone.
func (s *Store) handOver(prev, next *node.Record, sealed *store.Secret) error {
	prevBytes, err := json.Marshal(prev)
	if err != nil {
		return err
	}
	nextBytes, err := json.Marshal(next)
	if err != nil {
		return err
	}
	sealedBytes, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		if err := txn.Set(recordKey(next.Org, next.Address), nextBytes); err != nil {
			return err
		}
		if err := txn.Set(materialKey(next.Org, next.Address), sealedBytes); err != nil {
			return err
		}
		if err := txn.Set(recordKey(prev.Org, prev.Address), prevBytes); err != nil {
			return err
		}
		if err := txn.Delete(materialKey(prev.Org, prev.Address)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return nil
	})
}

// Rebind re-seals a node's key under a new measurement.
//
// This is what an image upgrade needs and the only thing that provides it: a key
// bound to one measurement stops working the moment the node boots a different
// image, which is the property the binding exists for. Rebinding requires the
// CURRENT evidence, because the key can only be recovered under it, and it is an
// administrative act — the new measurement is an assertion about which image the
// fleet is now allowed to run, and a node must not be able to make that assertion
// about itself.
func (s *Store) Rebind(org string, address node.Address, from, to node.Evidence) (*node.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.Get(org, address)
	if err != nil {
		return nil, err
	}
	if rec.Status != node.Active {
		return nil, fmt.Errorf("%w: %s", ErrNotActive, rec.Status)
	}
	next, attested, err := Verify(to)
	if err != nil {
		return nil, err
	}
	priv, err := s.unseal(rec, from)
	if err != nil {
		return nil, err
	}
	defer returnKey(priv)

	raw := crypto.FromECDSA(priv)
	sealed, err := s.seal(rec.Address, next, raw)
	zero(raw)
	if err != nil {
		return nil, fmt.Errorf("custody: seal: %w", err)
	}
	rec.Measurement = next
	if to.TEE != "" {
		rec.TEE = to.TEE
	}
	rec.Attested = attested
	rec.UpdatedAt = time.Now().UTC()
	if err := s.write(rec, sealed); err != nil {
		return nil, err
	}
	return rec, nil
}

// Revoke ends an identity. The record survives as a tombstone the fleet view and
// the settlement L1 can still read; the material does not, so a revoked node
// cannot sign again even if the master key later leaks. Revocation is terminal:
// there is no un-revoke, and the operator's path back is a fresh enrollment.
func (s *Store) Revoke(org string, address node.Address, reason string) (*node.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.Get(org, address)
	if err != nil {
		return nil, err
	}
	if rec.Status == node.Revoked {
		return rec, nil
	}
	// A superseded identity is already ended and its material already destroyed.
	// Overwriting its status would erase the fact that it was rotated, and the
	// successor is the identity a compromise reaches — revoke that one.
	if rec.Status != node.Active {
		return nil, fmt.Errorf("%w: %s", ErrNotActive, rec.Status)
	}
	rec.Status = node.Revoked
	rec.Reason = reason
	rec.UpdatedAt = time.Now().UTC()
	if err := s.destroy(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

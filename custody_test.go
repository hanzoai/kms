package kms

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	badger "github.com/luxfi/zapdb"
)

// embedded builds the minimum Embedded the custody accessor needs, without
// booting a listener: Custody reads the database and the record master key and
// nothing else.
func embedded(t *testing.T) *Embedded {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions(filepath.Join(t.TempDir(), "kms")).WithLogger(nil))
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &Embedded{db: db}
}

// The serving side gets the store, never the database it lives in and never the
// master key. One store per Embedded, because that store's lock is what
// serializes enrolment and rotation.
func TestCustodyHandsOutOneStore(t *testing.T) {
	t.Setenv("KMS_MASTER_KEY_B64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	e := embedded(t)

	first, err := e.Custody()
	if err != nil {
		t.Fatalf("Custody: %v", err)
	}
	second, err := e.Custody()
	if err != nil {
		t.Fatalf("second Custody: %v", err)
	}
	if first != second {
		t.Fatal("Custody built a second store; two locks over one database can interleave a rotation")
	}
}

// No key, no custody. A store that cannot seal must refuse rather than come up
// and hold node wallets under something weaker.
func TestCustodyRefusesWithoutTheRecordMasterKey(t *testing.T) {
	for name, key := range map[string]struct {
		value string
		want  error
	}{
		"absent":     {"", errNoMasterKey},
		"not base64": {"not-base64-at-all!!", errBadMasterKey},
		"too short":  {base64.StdEncoding.EncodeToString(make([]byte, 16)), errBadMasterKey},
		"too long":   {base64.StdEncoding.EncodeToString(make([]byte, 64)), errBadMasterKey},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("KMS_MASTER_KEY_B64", key.value)
			e := embedded(t)
			store, err := e.Custody()
			if !errors.Is(err, key.want) {
				t.Fatalf("Custody with a %s key: got %v, want %v", name, err, key.want)
			}
			if store != nil {
				t.Fatal("Custody returned a store it could not seal with")
			}
		})
	}
}

func TestCustodyOnNothingIsRefused(t *testing.T) {
	t.Setenv("KMS_MASTER_KEY_B64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	var nilEmbedded *Embedded
	if _, err := nilEmbedded.Custody(); err == nil {
		t.Fatal("Custody on a nil Embedded returned a store")
	}
	if _, err := (&Embedded{}).Custody(); err == nil {
		t.Fatal("Custody with no database returned a store")
	}
}

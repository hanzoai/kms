package kms

// custody.go — how a serving side reaches node identity custody.
//
// The custody store holds node wallets (see ./custody). This file is the only
// way to obtain one from a running KMS, and it hands out the store rather than
// the database it lives in: a caller that needs to enrol a node has no business
// reading the secret keyspace, and it never sees the master key at all.
//
// Authorization is deliberately not here. This repository answers who signed a
// token and derives no permission from one; the org-scoped plane that decides
// who may enrol, sign, rebind or revoke lives in cloud (apps/kms), which passes
// the org and subject it derived from the verified bearer into the calls below.
// custody/mount_test.go is the reference for that mount.

import (
	"encoding/base64"
	"errors"

	"github.com/hanzoai/kms/custody"
)

// Reasons the record master key is unusable. Both are refusals: no caller has a
// plaintext fallback, so a surface that needs the key does not come up without
// it.
var (
	errNoMasterKey  = errors.New("KMS_MASTER_KEY_B64 is not set")
	errBadMasterKey = errors.New("KMS_MASTER_KEY_B64 must decode to 32 raw bytes")
)

// recordMasterKey resolves the 32-byte record master. It is what the ZAP
// transport and node custody seal individual records under, and it is distinct
// from the volume key (KMS_ENCRYPTION_KEY_B64) on purpose: a leaked volume key
// alone must not yield a sealed record.
func recordMasterKey() ([]byte, error) {
	b64 := envOr("KMS_MASTER_KEY_B64", "")
	if b64 == "" {
		return nil, errNoMasterKey
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) != 32 {
		return nil, errBadMasterKey
	}
	return key, nil
}

// Custody returns the node identity store backed by this KMS.
//
// It fails when KMS_MASTER_KEY_B64 is absent or malformed, because nothing can
// be sealed without it and a custody surface that cannot seal must refuse rather
// than degrade. The same store is returned on every call, so the lock that
// serializes enrolment and rotation is one lock.
func (e *Embedded) Custody() (*custody.Store, error) {
	if e == nil || e.db == nil {
		return nil, errors.New("kms: no store")
	}
	e.custodyOnce.Do(func() {
		key, err := recordMasterKey()
		if err != nil {
			e.custodyErr = err
			return
		}
		e.custodyStore, e.custodyErr = custody.New(e.db, key)
	})
	return e.custodyStore, e.custodyErr
}

package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/hanzoai/base/core"
)

const auditCollection = "kms_audit_log"

// AuditEntry is a single WORM audit log entry.
type AuditEntry struct {
	OrgID    string `json:"org_id"`
	Seq      int    `json:"seq"`
	Entry    any    `json:"entry"`
	Hash     string `json:"hash"`
	PrevHash string `json:"prev_hash"`
}

// AuditStore provides append-only audit logging.
type AuditStore struct {
	app core.App
	mu  sync.Mutex
}

// NewAuditStore creates an audit store backed by Base.
func NewAuditStore(app core.App) *AuditStore {
	return &AuditStore{app: app}
}

// Append adds a new entry to the WORM audit log. The hash chain is computed
// as SHA-256(prev_hash || json(entry)).
func (s *AuditStore) Append(orgID string, entry any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevHash := ""
	seq := 1

	// Find the latest entry for this org.
	last, err := s.app.FindFirstRecordByFilter(
		auditCollection,
		"org_id = {:org}",
		map[string]any{"org": orgID},
	)
	if err == nil {
		seq = int(last.GetFloat("seq")) + 1
		prevHash = last.GetString("hash")
	}

	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}

	h := sha256.Sum256(append([]byte(prevHash), entryJSON...))
	hash := hex.EncodeToString(h[:])

	col, colErr := s.app.FindCollectionByNameOrId(auditCollection)
	if colErr != nil {
		return fmt.Errorf("audit: %w", colErr)
	}

	rec := core.NewRecord(col)
	rec.Set("org_id", orgID)
	rec.Set("seq", seq)
	rec.Set("entry", string(entryJSON))
	rec.Set("hash", hash)
	rec.Set("prev_hash", prevHash)
	return s.app.Save(rec)
}

// List returns audit entries for an org.
func (s *AuditStore) List(orgID string) ([]*AuditEntry, error) {
	records, err := s.app.FindRecordsByFilter(
		auditCollection,
		"org_id = {:org}",
		"seq", 0, 0,
		map[string]any{"org": orgID},
	)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	out := make([]*AuditEntry, 0, len(records))
	for _, r := range records {
		out = append(out, &AuditEntry{
			OrgID:    r.GetString("org_id"),
			Seq:      int(r.GetFloat("seq")),
			Hash:     r.GetString("hash"),
			PrevHash: r.GetString("prev_hash"),
		})
	}
	return out, nil
}

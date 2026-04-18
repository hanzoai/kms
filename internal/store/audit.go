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
	OrgID       string         `json:"org_id"`
	TenantID    string         `json:"tenantId"`
	Seq         int            `json:"seq"`
	Entry       any            `json:"entry,omitempty"`
	Hash        string         `json:"hash"`
	PrevHash    string         `json:"prev_hash"`
	EntryID     string         `json:"entryId,omitempty"`
	ActorID     string         `json:"actorId,omitempty"`
	Action      string         `json:"action,omitempty"`
	SubjectID   string         `json:"subjectId,omitempty"`
	SubjectType string         `json:"subjectType,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	IP          string         `json:"ip,omitempty"`
	UserAgent   string         `json:"userAgent,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
}

// AuditQuery filters an audit search.
type AuditQuery struct {
	TenantID  string
	ActorID   string
	SubjectID string
	Action    string
	Since     string
	Until     string
	Page      int
	PerPage   int
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
	// Attempt to denormalize a few well-known top-level fields for query speed.
	if m, ok := entry.(map[string]any); ok {
		if v, ok := m["actor_id"].(string); ok {
			rec.Set("actor_id", v)
		}
		if v, ok := m["action"].(string); ok {
			rec.Set("action", v)
		}
		if v, ok := m["subject_id"].(string); ok {
			rec.Set("subject_id", v)
		}
	}
	return s.app.Save(rec)
}

// List returns audit entries for a specific org (tenant).
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
		out = append(out, recordToAuditEntry(r))
	}
	return out, nil
}

// Query performs a multi-filter search across tenants. Callers must gate
// cross-tenant reads on the `kms.admin` role claim. An empty TenantID means
// "all tenants" (admin only).
func (s *AuditStore) Query(q AuditQuery) ([]*AuditEntry, int, error) {
	var clauses []string
	params := map[string]any{}
	if q.TenantID != "" {
		clauses = append(clauses, "org_id = {:org}")
		params["org"] = q.TenantID
	}
	if q.ActorID != "" {
		clauses = append(clauses, "actor_id = {:act}")
		params["act"] = q.ActorID
	}
	if q.SubjectID != "" {
		clauses = append(clauses, "subject_id = {:sub}")
		params["sub"] = q.SubjectID
	}
	if q.Action != "" {
		clauses = append(clauses, "action = {:action}")
		params["action"] = q.Action
	}
	if q.Since != "" {
		clauses = append(clauses, "created >= {:since}")
		params["since"] = q.Since
	}
	if q.Until != "" {
		clauses = append(clauses, "created <= {:until}")
		params["until"] = q.Until
	}
	filter := strings.Join(clauses, " && ")

	per := q.PerPage
	if per <= 0 {
		per = 100
	}
	page := q.Page
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * per

	records, err := s.app.FindRecordsByFilter(auditCollection, filter, "-created", per, offset, params)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("audit: query: %w", err)
	}
	out := make([]*AuditEntry, 0, len(records))
	for _, r := range records {
		out = append(out, recordToAuditEntry(r))
	}
	return out, len(out), nil
}

func recordToAuditEntry(r *core.Record) *AuditEntry {
	a := &AuditEntry{
		OrgID:     r.GetString("org_id"),
		TenantID:  r.GetString("org_id"),
		Seq:       int(r.GetFloat("seq")),
		Hash:      r.GetString("hash"),
		PrevHash:  r.GetString("prev_hash"),
		EntryID:   r.Id,
		ActorID:   r.GetString("actor_id"),
		Action:    r.GetString("action"),
		SubjectID: r.GetString("subject_id"),
		Timestamp: r.GetString("created"),
	}
	if raw := r.GetString("entry"); raw != "" {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
			if v, ok := decoded["metadata"].(map[string]any); ok {
				a.Metadata = v
			}
			if v, ok := decoded["subject_type"].(string); ok {
				a.SubjectType = v
			}
			if v, ok := decoded["ip"].(string); ok {
				a.IP = v
			}
			if v, ok := decoded["user_agent"].(string); ok {
				a.UserAgent = v
			}
		}
		a.Entry = decoded
	}
	return a
}

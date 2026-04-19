package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/search"
	"github.com/hanzoai/dbx"
)

const auditCollection = "kms_audit_log"

// maxAuditAppendAttempts bounds the retry loop when two goroutines race to
// append the same seq. With a UNIQUE index on (org_id, seq) the loser's
// INSERT fails with SQLite's UNIQUE constraint error and we re-read the tail
// and bump.
//
// SQLite note: the global write mutex + per-org app-layer mutex guarantee
// that the tail-read-and-insert pair is strictly serialized for a given org.
// The retry loop exists as a safety net for the rare case where the mutex
// is bypassed (e.g., test harnesses driving the store from multiple app
// instances against the same DB file).
const maxAuditAppendAttempts = 16

// orgMutexes synchronizes audit writers for a single org across goroutines in
// the same process. Paired with BEGIN IMMEDIATE inside RunInTransaction, this
// closes the tail-read → INSERT TOCTOU window that would otherwise let two
// concurrent callers observe the same tail seq and race on the UNIQUE
// constraint.
//
// Rationale for two layers:
//
//   - The app-layer mutex removes the UNIQUE-constraint path in the common
//     case, so the retry loop is effectively unreachable in steady state.
//   - BEGIN IMMEDIATE (driven by the SQLite RunInTransaction code path) takes
//     the reserved lock on the DB file, serializing across processes that
//     may share the file (e.g., a replica in the middle of promotion).
var orgMutexes sync.Map // map[string]*sync.Mutex

func orgMutexFor(orgID string) *sync.Mutex {
	if mu, ok := orgMutexes.Load(orgID); ok {
		return mu.(*sync.Mutex)
	}
	m := &sync.Mutex{}
	actual, _ := orgMutexes.LoadOrStore(orgID, m)
	return actual.(*sync.Mutex)
}

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
//
// Concurrency model (SQLite-only):
//
//   - An app-layer per-org sync.Mutex serializes goroutines in the same
//     process. This keeps the common path free of UNIQUE-constraint retries.
//   - The enclosing Base transaction runs against SQLite, which itself holds
//     the reserved lock across the tx, serializing writers across any
//     additional processes that share the file.
//
// The retry loop below is a safety net: it catches the UNIQUE constraint
// error SQLite emits if, for any reason, two writers still land on the same
// seq (e.g., a test harness bypassing the mutex) and re-reads the tail.
type AuditStore struct {
	app core.App
}

// NewAuditStore creates an audit store backed by Base.
func NewAuditStore(app core.App) *AuditStore {
	return &AuditStore{app: app}
}

// Append adds a new entry to the WORM audit log. The hash chain is computed
// as SHA-256(prev_hash || json(entry)).
//
// SQLite-only path: the per-org app-layer mutex + Base's transaction
// (RunInTransaction serializes writes through the driver's write mutex)
// together provide linearizable tail-read → INSERT. The UNIQUE(org_id, seq)
// index is the DB-level safety net; any conflict triggers a fresh tail read
// under the same lock.
func (s *AuditStore) Append(orgID string, entry any) error {
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	col, err := s.app.FindCollectionByNameOrId(auditCollection)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	// Per-org app-layer mutex closes the tail-read → INSERT TOCTOU for
	// goroutines in this process. Paired with SQLite's RunInTransaction
	// (which holds the write mutex across the tx) this gives linearizable
	// appends per org.
	mu := orgMutexFor(orgID)
	mu.Lock()
	defer mu.Unlock()

	for attempt := 0; attempt < maxAuditAppendAttempts; attempt++ {
		var saveErr error
		txErr := s.app.RunInTransaction(func(txApp core.App) error {
			recs, ferr := txApp.FindRecordsByFilter(
				auditCollection,
				"org_id = {:org}",
				"-seq", 1, 0,
				map[string]any{"org": orgID},
			)
			if ferr != nil && !strings.Contains(ferr.Error(), "no rows") {
				return fmt.Errorf("audit: read tail: %w", ferr)
			}
			prevHash := ""
			seq := 1
			if len(recs) > 0 {
				seq = int(recs[0].GetFloat("seq")) + 1
				prevHash = recs[0].GetString("hash")
			}

			h := sha256.Sum256(append([]byte(prevHash), entryJSON...))
			hash := hex.EncodeToString(h[:])

			rec := core.NewRecord(col)
			rec.Set("org_id", orgID)
			rec.Set("seq", seq)
			rec.Set("entry", string(entryJSON))
			rec.Set("hash", hash)
			rec.Set("prev_hash", prevHash)
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
			saveErr = txApp.Save(rec)
			return saveErr
		})
		if txErr == nil {
			return nil
		}
		// SQLite UNIQUE constraint error — retry with a fresh tail read.
		emsg := txErr.Error()
		if strings.Contains(emsg, "UNIQUE constraint failed") ||
			strings.Contains(emsg, "SQLITE_CONSTRAINT") {
			continue
		}
		return fmt.Errorf("audit: save: %w", txErr)
	}
	return fmt.Errorf("audit: %d concurrent writers, giving up", maxAuditAppendAttempts)
}

// List returns audit entries for a specific org (tenant).
//
// F11: Verifies the prev-hash chain before returning results. If any entry's
// stored hash or prev_hash does not match the recomputed chain, returns an
// error — the caller must treat this as a potential tampering event. At the
// app layer we forbid UPDATE/DELETE on audit entries; DB-layer hardening
// (revoke UPDATE/DELETE on audit table for the service role) is documented
// in kms/SECURITY.md.
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
	if err := verifyHashChain(records); err != nil {
		return out, fmt.Errorf("audit: tamper detected: %w", err)
	}
	return out, nil
}

// verifyHashChain recomputes the SHA-256 chain over records (assumed ordered
// by seq ascending) and reports an error if any stored hash deviates from
// the expected chain. Empty input is valid (no-op).
func verifyHashChain(records []*core.Record) error {
	prevHash := ""
	for i, r := range records {
		entryJSON := r.GetString("entry")
		expected := sha256.Sum256(append([]byte(prevHash), []byte(entryJSON)...))
		want := hex.EncodeToString(expected[:])
		got := r.GetString("hash")
		storedPrev := r.GetString("prev_hash")
		if storedPrev != prevHash {
			return fmt.Errorf("seq=%d prev_hash mismatch: want %q got %q", i+1, prevHash, storedPrev)
		}
		if got != want {
			return fmt.Errorf("seq=%d hash mismatch", i+1)
		}
		prevHash = got
	}
	return nil
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

	// F10: totalItems must reflect the full filtered result count, not the
	// current page size. Count first (via filter → dbx.Expression), then
	// fetch the page.
	total, err := s.countByFilter(filter, params)
	if err != nil {
		return nil, 0, err
	}
	records, err := s.app.FindRecordsByFilter(auditCollection, filter, "-created", per, offset, params)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, total, nil
		}
		return nil, total, fmt.Errorf("audit: query: %w", err)
	}
	out := make([]*AuditEntry, 0, len(records))
	for _, r := range records {
		out = append(out, recordToAuditEntry(r))
	}
	return out, total, nil
}

// countByFilter runs CountRecords with the same Base filter language used by
// FindRecordsByFilter. Empty filter counts everything.
func (s *AuditStore) countByFilter(filter string, params map[string]any) (int, error) {
	col, err := s.app.FindCollectionByNameOrId(auditCollection)
	if err != nil {
		return 0, fmt.Errorf("audit: count: %w", err)
	}
	var exprs []dbx.Expression
	if filter != "" {
		resolver := core.NewRecordFieldResolver(s.app, col, nil, true)
		expr, err := search.FilterData(filter).BuildExpr(resolver, dbx.Params(params))
		if err != nil {
			return 0, fmt.Errorf("audit: count build expr: %w", err)
		}
		exprs = append(exprs, expr)
	}
	total, err := s.app.CountRecords(col, exprs...)
	if err != nil {
		return 0, fmt.Errorf("audit: count records: %w", err)
	}
	return int(total), nil
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

package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/search"
	"github.com/hanzoai/dbx"
)

const auditCollection = "kms_audit_log"

// maxAuditAppendAttempts bounds the retry loop when two replicas race to
// append the same seq. With a UNIQUE index on (org_id, seq) the loser's
// INSERT fails with SQLSTATE 23505 and we simply re-read the tail and bump.
//
// R3-1: under Postgres we now acquire pg_advisory_xact_lock on (audit_ns,
// org_id) BEFORE the tail read, so the "read tail then insert" window is
// serialized across replicas. The retry loop still exists as a safety net
// for the 23505 path (e.g. if the lock module is disabled by ops), but with
// the advisory lock in place it is effectively unreachable in production.
const maxAuditAppendAttempts = 16

// auditAdvisoryNamespace is the first int32 passed to pg_advisory_xact_lock.
// It scopes the lock to the KMS audit table so we don't collide with any
// other advisory lock users in the same Postgres instance. Picked via
// FNV-1a(hash_text("kms_audit_log")) at package init to avoid magic numbers.
var auditAdvisoryNamespace = func() int32 {
	h := fnv.New32a()
	h.Write([]byte("kms_audit_log"))
	return int32(h.Sum32())
}()

// orgAdvisoryKey returns the per-org int32 key for pg_advisory_xact_lock.
// FNV-1a is stable, fast, and collision tolerant for this use — a collision
// means two orgs share a lock namespace and one pays a tiny serialization
// penalty, never a correctness issue.
func orgAdvisoryKey(orgID string) int32 {
	h := fnv.New32a()
	h.Write([]byte(orgID))
	return int32(h.Sum32())
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
// R2-6: the process-local sync.Mutex that was here before is GONE. With
// multiple KMS replicas behind a service, an in-process lock cannot serialize
// across pods — two replicas would both read `last.seq == N`, both compute
// `seq = N+1`, and the one that committed last would either: (a) silently
// clobber the first under non-UNIQUE indexes, or (b) after the UNIQUE index
// added in base.go, fail with 23505. We now:
//
//   - rely on the DB UNIQUE(org_id, seq) index as the ordering authority;
//   - retry on duplicate-key errors with a fresh tail read.
type AuditStore struct {
	app core.App
}

// NewAuditStore creates an audit store backed by Base.
func NewAuditStore(app core.App) *AuditStore {
	return &AuditStore{app: app}
}

// isPostgresBuilder reports whether the backing dbx.Builder speaks Postgres.
// We look at the *dbx.DB DriverName (outside tx) or inspect the tx's embedded
// builder. The only two drivers we support are "pgx"/"postgres" and "sqlite3".
func isPostgresBuilder(b dbx.Builder) bool {
	if db, ok := b.(*dbx.DB); ok {
		switch db.DriverName() {
		case "pgx", "postgres", "postgresql":
			return true
		}
	}
	if tx, ok := b.(*dbx.Tx); ok {
		// tx.Builder wraps the same executor whose underlying *dbx.DB we
		// already checked at outer scope; fall through to the hack below.
		_ = tx
	}
	return false
}

// Append adds a new entry to the WORM audit log. The hash chain is computed
// as SHA-256(prev_hash || json(entry)).
//
// R3-1: Tail-read and INSERT happen inside a single transaction. On Postgres
// we additionally hold pg_advisory_xact_lock(auditNs, orgKey) for the whole
// transaction — that serializes every writer to this org's audit chain
// across replicas, eliminating the TOCTOU window that could link non-causal
// prev_hash values under READ COMMITTED. On SQLite the driver's write-side
// mutex already serializes writers on the same DB file, so the advisory
// lock is a no-op and we skip it.
//
// The 23505 retry loop is preserved as a safety net (ops disables the lock,
// writer migration, etc.) — but under normal operation the advisory lock
// means every attempt on the same org is strictly linearizable.
func (s *AuditStore) Append(orgID string, entry any) error {
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	col, err := s.app.FindCollectionByNameOrId(auditCollection)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	usePG := isPostgresBuilder(s.app.NonconcurrentDB())
	orgKey := orgAdvisoryKey(orgID)

	for attempt := 0; attempt < maxAuditAppendAttempts; attempt++ {
		var saveErr error
		txErr := s.app.RunInTransaction(func(txApp core.App) error {
			// (R3-1) Postgres: acquire an advisory xact lock scoped to
			// (auditNs, orgKey). The lock is released automatically at
			// COMMIT/ROLLBACK. Any concurrent writer targeting the same
			// org blocks here until we release. This closes the TOCTOU
			// window between tail read and INSERT.
			if usePG {
				if _, lockErr := txApp.NonconcurrentDB().NewQuery(
					"SELECT pg_advisory_xact_lock({:ns}, {:k})",
				).Bind(dbx.Params{
					"ns": auditAdvisoryNamespace,
					"k":  orgKey,
				}).Execute(); lockErr != nil {
					return fmt.Errorf("audit: advisory lock: %w", lockErr)
				}
			}

			// Now read the tail under the lock — no other writer can
			// observe this tail value until we commit.
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
		// 23505 (postgres unique_violation) or SQLite's UNIQUE constraint
		// error — retry with a fresh tail read. Any other error is fatal.
		emsg := txErr.Error()
		if strings.Contains(emsg, "23505") ||
			strings.Contains(emsg, "UNIQUE constraint failed") ||
			strings.Contains(emsg, "duplicate key") {
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
// (revoke UPDATE/DELETE on audit table for the service role, optional S3
// WORM export) is documented in kms/SECURITY.md.
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

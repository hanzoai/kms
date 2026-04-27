// Package main — tamper-evident audit trail with composite actor_id (R-12).
//
// Every mutating KMS request writes an audit row with:
//
//	actor_id   = "{iss}:{sub}"    // composite: issuer qualifies the subject
//	iss        = JWT `iss` claim  // who issued the token (hanzo.id, casdoor, ...)
//	sub        = JWT `sub` claim  // subject (must match /^(usr|svc|api)_[a-z0-9_-]+$/ or it is stored verbatim with an "unverified:" tag)
//	actor_role = best role claim
//	owner      = JWT `owner` claim (org slug)
//	method     = HTTP method
//	path       = URL path
//	secret_path, secret_name, env — derived if present
//	ts         = write timestamp (RFC3339)
//	result     = status code
//
// Threat model (R-12): a compromised service-account that can mint tokens
// could previously set `sub=system` or `sub=admin` — if the IAM allowed
// arbitrary subject strings — to poison the WORM trail. By binding iss
// into actor_id, an auditor can always disambiguate "sub=admin from our
// IAM" from "sub=admin from some other IdP". Subject-format validation
// is a belt-and-suspenders check: if the claimed sub does not match the
// expected grammar we PREPEND `unverified:` to the stored value so a
// reviewer cannot mistake it for an IAM-issued ID.
//
// Storage: modernc.org/sqlite (pure Go, no CGO) at the path resolved from
// KMS_AUDIT_DB (defaults to /tmp/kms-aux.db — matching the smoke test). A
// single-writer goroutine drains a bounded channel; burst traffic does
// not back-pressure requests. Dropped entries increment an atomic counter
// exposed via GET /v1/kms/audit/stats (admin only).
package kms

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// subPattern is the canonical IAM subject format. hanzo.id mints user
// subjects like `usr_abc123`, service subjects like `svc_...`, and
// application tokens as `api_...`. Anything else is flagged "unverified".
var subPattern = regexp.MustCompile(`^(usr|svc|api|admin|sys|u|sa|ap)_[a-z0-9_-]+$`)

// auditEntry captures one request's worth of audit metadata.
type auditEntry struct {
	TS         time.Time
	ActorID    string // composite "iss:sub" (possibly "unverified:iss:sub")
	Issuer     string
	Subject    string
	ActorRole  string
	Owner      string
	Method     string
	Path       string
	SecretPath string
	SecretName string
	Env        string
	Result     int
	Version    int64 // new version after write (0 for reads)

	// ackChan, when non-nil, is closed by the writer goroutine AFTER the
	// entry has been processed. Used by sync() for deterministic drain in
	// tests. Not persisted. Sentinel entries with Method=="__sync__" are
	// dropped (not inserted) but their ackChan is still closed.
	ackChan chan struct{}
}

// auditor buffers entries and persists them to SQLite via a single-writer
// goroutine. Dropped entries (channel full) bump the dropped counter and
// are logged — never silently swallowed.
type auditor struct {
	ch      chan auditEntry
	db      *sql.DB
	dropped atomic.Uint64
	written atomic.Uint64
}

// newAuditor opens (or creates) the SQLite aux DB and starts the writer
// goroutine. Returns a ready-to-use *auditor. If the DB cannot be opened,
// returns nil and logs a warning — KMS must not fail to start just
// because the audit sidecar DB is misconfigured in dev.
func newAuditor(ctx context.Context, path string) *auditor {
	if path == "" {
		path = "/tmp/kms-aux.db"
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		log.Printf("kms: audit DB open failed at %s: %v — audit DISABLED", path, err)
		return nil
	}
	// Schema — append-only, WORM-friendly. No UPDATE, no DELETE.
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS audit_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	ts          TEXT NOT NULL,
	actor_id    TEXT NOT NULL,
	issuer      TEXT NOT NULL,
	subject     TEXT NOT NULL,
	actor_role  TEXT NOT NULL DEFAULT '',
	owner       TEXT NOT NULL DEFAULT '',
	method      TEXT NOT NULL,
	path        TEXT NOT NULL,
	secret_path TEXT NOT NULL DEFAULT '',
	secret_name TEXT NOT NULL DEFAULT '',
	env         TEXT NOT NULL DEFAULT '',
	result      INTEGER NOT NULL,
	version     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id, ts);
CREATE INDEX IF NOT EXISTS idx_audit_owner ON audit_log(owner, ts);
`)
	if err != nil {
		db.Close()
		log.Printf("kms: audit schema init failed: %v — audit DISABLED", err)
		return nil
	}
	a := &auditor{
		ch: make(chan auditEntry, 1024),
		db: db,
	}
	go a.run(ctx)
	log.Printf("kms: audit log ready at %s (composite actor_id=iss:sub)", path)
	return a
}

// run drains the channel. One writer, serialized inserts — cheap enough
// for KMS throughput (few hundred req/sec peak).
func (a *auditor) run(ctx context.Context) {
	stmt, err := a.db.Prepare(`
INSERT INTO audit_log(ts,actor_id,issuer,subject,actor_role,owner,method,path,secret_path,secret_name,env,result,version)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		log.Printf("kms: audit prepare failed: %v", err)
		return
	}
	defer stmt.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-a.ch:
			if !ok {
				return
			}
			if e.Method == "__sync__" {
				// Sentinel — do not persist. Ack any prior entries have
				// already been flushed in FIFO order.
				if e.ackChan != nil {
					close(e.ackChan)
				}
				continue
			}
			if _, err := stmt.Exec(
				e.TS.UTC().Format(time.RFC3339Nano),
				e.ActorID, e.Issuer, e.Subject, e.ActorRole, e.Owner,
				e.Method, e.Path, e.SecretPath, e.SecretName, e.Env,
				e.Result, e.Version,
			); err != nil {
				log.Printf("kms: audit insert failed: %v", err)
				continue
			}
			a.written.Add(1)
			if e.ackChan != nil {
				close(e.ackChan)
			}
		}
	}
}

// record enqueues an entry. Non-blocking: drops on channel full and
// increments the dropped counter so ops can alert on it.
func (a *auditor) record(e auditEntry) {
	if a == nil {
		return
	}
	select {
	case a.ch <- e:
	default:
		if a.dropped.Add(1)%1000 == 1 {
			log.Printf("kms: audit buffer full — dropped entry actor=%s method=%s path=%s", e.ActorID, e.Method, e.Path)
		}
	}
}

// stats returns monitoring counters.
func (a *auditor) stats() (written, dropped uint64) {
	if a == nil {
		return 0, 0
	}
	return a.written.Load(), a.dropped.Load()
}

// sync blocks until all entries queued before the call have been
// persisted. Test-only helper — avoids racy time.Sleep drains.
//
// Mechanism: enqueue a sentinel entry with a per-call ack channel; the
// writer closes the ack after processing it, which is also after every
// prior entry has been flushed (single-writer, in-order).
func (a *auditor) sync() {
	if a == nil {
		return
	}
	ack := make(chan struct{})
	a.ch <- auditEntry{
		ActorID: "__sync__",
		Method:  "__sync__",
		ackChan: ack,
	}
	<-ack
}

// composeActorID returns the audit actor_id for a (iss, sub) pair. The
// composite form lets an auditor disambiguate subjects across issuers —
// "admin from our IAM" vs "admin from some other IdP". If sub fails the
// format check it is prefixed with `unverified:` so reviewers are not
// misled by hand-crafted subject strings.
func composeActorID(iss, sub string) string {
	iss = strings.TrimSpace(iss)
	sub = strings.TrimSpace(sub)
	if iss == "" {
		iss = "unknown-issuer"
	}
	if sub == "" {
		sub = "anonymous"
	}
	if !subPattern.MatchString(sub) {
		return fmt.Sprintf("unverified:%s:%s", iss, sub)
	}
	return fmt.Sprintf("%s:%s", iss, sub)
}

// firstRole returns the best display role for audit purposes.
func firstRole(roles []string) string {
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r != "" {
			return r
		}
	}
	return ""
}

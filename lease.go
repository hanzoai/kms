// lease.go — a minimal, dependency-free Kubernetes Lease writer-fence for the
// kms-luxfi PRIMARY. It closes the one split-brain hole the StatefulSet ordinal
// invariant alone does not: if the current primary is partitioned from S3 (but
// still running and pushing) and an operator promotes a DIFFERENT ordinal, both
// nodes would push to the same S3 log and interleave the inc/<version>
// keyspace, corrupting it. With the fence a node PUSHES only while it holds a
// fresh coordination.k8s.io/v1 Lease; it renews continuously and fails CLOSED
// (stops pushing) the instant it cannot renew. A promoted node may acquire the
// Lease only AFTER the previous holder's lease has expired — so at most one
// writer is ever live, even across a partition.
//
// It talks to the in-cluster REST API directly (ServiceAccount token + CA)
// instead of pulling k8s.io/client-go: kms has zero k8s client dependencies and
// a single Lease does not justify client-go's transitive weight. The optimistic
// resourceVersion on update is the actual mutual-exclusion primitive — two
// nodes racing to renew/take over cannot both win, because the loser's PUT
// 409-conflicts and it fences itself.
//
// Gated by KMS_WRITER_LEASE=true. When off, behaviour is unchanged and the
// ordinal invariant remains the sole guarantee.
package kms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luxfi/log"
)

const (
	saTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	defaultLeaseDuration = 15 * time.Second
)

// leaseSpec is the subset of coordination.k8s.io/v1 LeaseSpec we read/write.
type leaseSpec struct {
	HolderIdentity       *string `json:"holderIdentity,omitempty"`
	LeaseDurationSeconds *int32  `json:"leaseDurationSeconds,omitempty"`
	AcquireTime          *string `json:"acquireTime,omitempty"`
	RenewTime            *string `json:"renewTime,omitempty"`
	LeaseTransitions     *int32  `json:"leaseTransitions,omitempty"`
}

type leaseMeta struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

type leaseObject struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Metadata   leaseMeta `json:"metadata"`
	Spec       leaseSpec `json:"spec"`
}

// writerLease fences the primary's push loop. Held() reflects the last renew;
// it is authoritative only while run() is renewing.
type writerLease struct {
	base       string // https://host:port
	namespace  string
	name       string
	holder     string
	duration   time.Duration
	renewEvery time.Duration
	client     *http.Client
	token      string
	held       atomic.Bool
}

// newWriterLease builds the in-cluster fence from the ServiceAccount projection.
// It returns an error (fatal to the caller) when KMS_WRITER_LEASE is requested
// but we are not running in a cluster or lack the SA files — we must never run
// an UNFENCED writer once the fence has been asked for.
func newWriterLease(holder string) (*writerLease, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return nil, fmt.Errorf("KMS_WRITER_LEASE=true but not in a cluster (KUBERNETES_SERVICE_HOST unset)")
	}
	port := envOr("KUBERNETES_SERVICE_PORT", "443")
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("read ServiceAccount token: %w", err)
	}
	caPEM, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, fmt.Errorf("read ServiceAccount CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("ServiceAccount CA is not valid PEM")
	}
	ns := firstNonEmpty(os.Getenv("KMS_POD_NAMESPACE"), readFileTrim(saNamespacePath), "hanzo")
	dur := defaultLeaseDuration
	if d, ok := durationEnv("KMS_WRITER_LEASE_DURATION"); ok {
		dur = d
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	return newWriterLeaseWith(fmt.Sprintf("https://%s:%s", host, port), ns,
		envOr("KMS_WRITER_LEASE_NAME", "kms-luxfi-writer"), holder, dur,
		client, strings.TrimSpace(string(token))), nil
}

// newWriterLeaseWith is the dependency-injected constructor (tests point base at
// an httptest server with a plain client + token).
func newWriterLeaseWith(base, namespace, name, holder string, dur time.Duration, client *http.Client, token string) *writerLease {
	if dur <= 0 {
		dur = defaultLeaseDuration
	}
	renew := dur / 3
	if renew < time.Second {
		renew = time.Second
	}
	return &writerLease{
		base: strings.TrimRight(base, "/"), namespace: namespace, name: name,
		holder: holder, duration: dur, renewEvery: renew, client: client, token: token,
	}
}

func (l *writerLease) Held() bool { return l.held.Load() }

// run renews the lease on a cadence tighter than its duration and keeps Held()
// current. It fails CLOSED: any error or a lost lease drops Held() to false so
// the push loop stops immediately. On shutdown it best-effort RELEASES the
// lease (stamps it expired) so a standby can take over without waiting a full
// lease duration.
func (l *writerLease) run(ctx context.Context) {
	l.tick(ctx)
	t := time.NewTicker(l.renewEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			l.release()
			return
		case <-t.C:
			l.tick(ctx)
		}
	}
}

func (l *writerLease) tick(ctx context.Context) {
	held, err := l.acquireOrRenew(ctx)
	if err != nil {
		if l.held.Load() {
			log.Warn("kms: writer-lease renew failed — FENCING writes (fail-closed)", "err", err)
		}
		l.held.Store(false)
		return
	}
	switch {
	case held && !l.held.Load():
		log.Info("kms: writer-lease ACQUIRED — primary may push", "holder", l.holder, "lease", l.name)
	case !held && l.held.Load():
		log.Warn("kms: writer-lease LOST to another holder — FENCING writes", "holder", l.holder, "lease", l.name)
	}
	l.held.Store(held)
}

// acquireOrRenew is the fence decision. Returns held=true only when this node
// owns a fresh lease after the call. It creates the lease if absent, renews it
// if already ours, takes it over only if the current holder's lease has
// EXPIRED, and refuses (held=false, no error) when another holder is still
// fresh. Any transport/conflict error is returned so the caller fails closed.
func (l *writerLease) acquireOrRenew(ctx context.Context) (bool, error) {
	cur, status, err := l.get(ctx)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)
	durSecs := int32(l.duration / time.Second)
	if durSecs < 1 {
		durSecs = 1
	}

	if status == http.StatusNotFound {
		obj := &leaseObject{
			APIVersion: "coordination.k8s.io/v1",
			Kind:       "Lease",
			Metadata:   leaseMeta{Name: l.name, Namespace: l.namespace},
			Spec: leaseSpec{
				HolderIdentity:       &l.holder,
				LeaseDurationSeconds: &durSecs,
				AcquireTime:          &nowStr,
				RenewTime:            &nowStr,
				LeaseTransitions:     int32Ptr(0),
			},
		}
		return l.create(ctx, obj)
	}

	mine := cur.Spec.HolderIdentity != nil && *cur.Spec.HolderIdentity == l.holder
	if !mine && !leaseExpired(cur, now) {
		return false, nil // another holder, still fresh → fence ourselves
	}

	transitions := int32(0)
	if cur.Spec.LeaseTransitions != nil {
		transitions = *cur.Spec.LeaseTransitions
	}
	if !mine {
		transitions++ // a takeover is a transition
		cur.Spec.AcquireTime = &nowStr
	} else if cur.Spec.AcquireTime == nil {
		cur.Spec.AcquireTime = &nowStr
	}
	cur.Spec.HolderIdentity = &l.holder
	cur.Spec.LeaseDurationSeconds = &durSecs
	cur.Spec.RenewTime = &nowStr
	cur.Spec.LeaseTransitions = &transitions
	return l.update(ctx, cur)
}

// leaseExpired reports whether an observed lease is past its advertised
// expiry. Missing/unparseable renewTime is treated as expired (a takeover will
// re-stamp it). We honour the HOLDER's advertised duration, matching standard
// leader-election observers.
func leaseExpired(o *leaseObject, now time.Time) bool {
	if o.Spec.RenewTime == nil {
		return true
	}
	renew, err := time.Parse(time.RFC3339Nano, *o.Spec.RenewTime)
	if err != nil {
		return true
	}
	dur := defaultLeaseDuration
	if o.Spec.LeaseDurationSeconds != nil && *o.Spec.LeaseDurationSeconds > 0 {
		dur = time.Duration(*o.Spec.LeaseDurationSeconds) * time.Second
	}
	return now.After(renew.Add(dur))
}

// release best-effort stamps our lease expired so a standby takes over
// promptly on graceful shutdown. Silent on failure — the lease expires on its
// own duration regardless.
func (l *writerLease) release() {
	if !l.held.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cur, status, err := l.get(ctx)
	if err != nil || status != http.StatusOK {
		return
	}
	if cur.Spec.HolderIdentity == nil || *cur.Spec.HolderIdentity != l.holder {
		return
	}
	past := time.Now().UTC().Add(-2 * l.duration).Format(time.RFC3339Nano)
	cur.Spec.RenewTime = &past
	_, _ = l.update(ctx, cur)
	l.held.Store(false)
}

func (l *writerLease) collURL() string {
	return fmt.Sprintf("%s/apis/coordination.k8s.io/v1/namespaces/%s/leases", l.base, l.namespace)
}

func (l *writerLease) get(ctx context.Context) (*leaseObject, int, error) {
	body, status, err := l.do(ctx, http.MethodGet, l.collURL()+"/"+l.name, nil)
	if err != nil {
		return nil, 0, err
	}
	if status == http.StatusNotFound {
		return nil, status, nil
	}
	if status != http.StatusOK {
		return nil, status, fmt.Errorf("lease GET: unexpected status %d: %s", status, snippet(body))
	}
	var o leaseObject
	if err := json.Unmarshal(body, &o); err != nil {
		return nil, status, fmt.Errorf("lease GET decode: %w", err)
	}
	return &o, status, nil
}

func (l *writerLease) create(ctx context.Context, obj *leaseObject) (bool, error) {
	raw, _ := json.Marshal(obj)
	body, status, err := l.do(ctx, http.MethodPost, l.collURL(), raw)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusCreated, http.StatusOK:
		return true, nil
	case http.StatusConflict: // lost the create race → not ours this round
		return false, nil
	default:
		return false, fmt.Errorf("lease create: status %d: %s", status, snippet(body))
	}
}

func (l *writerLease) update(ctx context.Context, obj *leaseObject) (bool, error) {
	raw, _ := json.Marshal(obj)
	body, status, err := l.do(ctx, http.MethodPut, l.collURL()+"/"+obj.Metadata.Name, raw)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusConflict: // another node updated first (stale resourceVersion)
		return false, nil
	default:
		return false, fmt.Errorf("lease update: status %d: %s", status, snippet(body))
	}
}

func (l *writerLease) do(ctx context.Context, method, url string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+l.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

func int32Ptr(v int32) *int32 { return &v }

func readFileTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func snippet(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max])
	}
	return string(b)
}

package kmsclient

// node.go — the node identity custody calls.
//
// A node's identity is a wallet the KMS holds for it: the private key is
// generated inside the KMS, sealed to the node's address and to the image it is
// running, and returned to nobody. A node daemon does not sign; it enrols, then
// asks for signatures, and gets back statements anyone can check. The statement
// types and the check are in sdk/go/node, which the settlement chain's indexer
// imports too.
//
// These calls are HTTP only. A node asks for its identity BEFORE it has joined
// the cluster, so the in-cluster ZAP transport is not reachable to it yet; a
// client configured for ZAP is refused here rather than silently failing later.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hanzoai/kms/sdk/go/node"
)

// maxResponse bounds a response body. The node daemon reaches the KMS over the
// network before it has joined anything, so a hostile or broken endpoint must
// not be able to exhaust its memory with an unbounded body.
const maxResponse = 1 << 20 // 1 MiB

// Failure is a refusal the KMS explained. It carries the status so a caller can
// act on the distinction the surface draws — 409 for a measurement that no
// longer matches the sealed image or an epoch that did not advance, 403 for a
// credential that does not own the identity, 410 for material already
// destroyed — instead of matching on message text.
type Failure struct {
	Status  int
	Message string
}

func (f *Failure) Error() string {
	return fmt.Sprintf("kmsclient: node surface refused with %d: %s", f.Status, f.Message)
}

// ErrTransport reports a node call attempted on a client configured for ZAP.
var ErrTransport = errors.New("kmsclient: node custody is reachable over HTTP only")

// nodeURL builds a URL under the node surface. suffix is "" for the collection,
// or "/{address}[/{action}]".
//
// The path carries no tenant. The server takes the org from the credential the
// request is made with and folds it into the storage key, exactly as the secret
// surface does — an org in the URL would be a second answer to a question the
// bearer already settles, and the two could disagree.
func (c *Client) nodeURL(suffix string) string {
	return c.endpoint + "/v1/kms/nodes" + suffix
}

// ask performs one authenticated JSON request against the node surface and
// decodes the response into out. It returns the status so a caller can read the
// distinction the surface makes between a fresh answer and an existing one.
//
// Every node call goes through here, so the bearer, the body cap, the error
// shape and the decode happen once and identically.
func (c *Client) ask(ctx context.Context, method, suffix string, body, out any, want ...int) (int, error) {
	if c.transport != "http" {
		return 0, ErrTransport
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("kmsclient: encode request: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}
	token, err := c.getToken(ctx)
	if err != nil {
		return 0, fmt.Errorf("kmsclient: auth: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.nodeURL(suffix), payload)
	if err != nil {
		return 0, fmt.Errorf("kmsclient: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("kmsclient: request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("kmsclient: read response: %w", err)
	}

	if !accepted(resp.StatusCode, want) {
		return resp.StatusCode, &Failure{Status: resp.StatusCode, Message: message(raw)}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("kmsclient: decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func accepted(status int, want []int) bool {
	for _, w := range want {
		if status == w {
			return true
		}
	}
	return false
}

// message pulls the KMS's explanation out of a refusal body, falling back to the
// raw bytes when the body is not the shape the surface documents.
func message(raw []byte) string {
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &body); err == nil && body.Message != "" {
		return body.Message
	}
	return string(raw)
}

// Enroll mints this node's identity, or returns the one it already has. created
// reports which happened, so a daemon can tell a first boot from a restart.
//
// Enrolment is idempotent on the caller's IAM subject: one active identity per
// subject per tenant. Presenting a DIFFERENT measurement than the identity is
// sealed to is refused with 409 rather than minting a second wallet — an image
// that was not approved must not walk away with a fresh identity, and the
// sanctioned move is an administrator's Rebind.
//
// Each node therefore needs its own IAM machine identity. A credential shared
// across a fleet collapses the fleet onto one wallet.
func (c *Client) Enroll(ctx context.Context, ev node.Evidence) (rec *node.Record, created bool, err error) {
	rec = new(node.Record)
	status, err := c.ask(ctx, http.MethodPost, "", map[string]any{"evidence": ev}, rec,
		http.StatusCreated, http.StatusOK)
	if err != nil {
		return nil, false, err
	}
	return rec, status == http.StatusCreated, nil
}

// Fleet lists the tenant's node identities by wallet. Fleet.Truncated reports
// that the answer is a bounded prefix rather than the whole fleet.
func (c *Client) Fleet(ctx context.Context) (*node.Fleet, error) {
	fleet := new(node.Fleet)
	_, err := c.ask(ctx, http.MethodGet, "", nil, fleet, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return fleet, nil
}

// Node reads one identity.
func (c *Client) Node(ctx context.Context, address node.Address) (*node.Record, error) {
	rec := new(node.Record)
	_, err := c.ask(ctx, http.MethodGet, "/"+address.String(), nil, rec, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// Sign asks the KMS to attest payload with the node's key.
//
// The key opens only under evidence naming the image it was sealed to, is used
// once, and is discarded. The receipt commits to the node's address, that image
// and the epoch, so a verifier learns which node signed and what it was running
// without trusting either claim separately. Check it with
// [node.Receipt.Verify], passing the same payload.
//
// epoch must exceed the last epoch this identity signed at, which is what stops
// a captured receipt being replayed forward.
func (c *Client) Sign(ctx context.Context, address node.Address, ev node.Evidence, epoch uint64, payload []byte) (*node.Receipt, error) {
	receipt := new(node.Receipt)
	_, err := c.ask(ctx, http.MethodPost, "/"+address.String()+"/sign",
		map[string]any{"evidence": ev, "epoch": epoch, "payload": payload},
		receipt, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return receipt, nil
}

// Rotate replaces this node's keypair and returns the successor together with
// the succession its outgoing key signed.
//
// A wallet's private key cannot change under a fixed address, so rotation is a
// change of identity: the successor's address is the node's new identity, and
// the handover is what moves the stake — the settlement L1 verifies it against
// the address it already knows. The outgoing key is destroyed in the same
// transaction, so it can never sign again.
func (c *Client) Rotate(ctx context.Context, address node.Address, ev node.Evidence, epoch uint64) (*node.Record, *node.Handover, error) {
	var out struct {
		Node       *node.Record   `json:"node"`
		Succession *node.Handover `json:"succession"`
	}
	if _, err := c.ask(ctx, http.MethodPost, "/"+address.String()+"/rotate",
		map[string]any{"evidence": ev, "epoch": epoch}, &out, http.StatusCreated); err != nil {
		return nil, nil, err
	}
	return out.Node, out.Succession, nil
}

// Rebind re-seals an identity under a new image, which is what an image upgrade
// requires: a key bound to one measurement stops working the moment the node
// boots a different one.
//
// It needs the CURRENT evidence, because the key is recoverable only under it,
// and it is administrative — the new measurement asserts which image the fleet
// may now run, so a node's own credential cannot make it.
func (c *Client) Rebind(ctx context.Context, address node.Address, from, to node.Evidence) (*node.Record, error) {
	rec := new(node.Record)
	_, err := c.ask(ctx, http.MethodPost, "/"+address.String()+"/rebind",
		map[string]any{"from": from, "to": to}, rec, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// Revoke ends an identity: a decommissioned node, or one whose stake was
// slashed. The key material is destroyed, so it cannot sign again even if the
// master key later leaks; the record survives as a tombstone so the address
// stays attributable. Administrative, and terminal — the way back is a fresh
// enrolment.
func (c *Client) Revoke(ctx context.Context, address node.Address, reason string) (*node.Record, error) {
	rec := new(node.Record)
	_, err := c.ask(ctx, http.MethodPost, "/"+address.String()+"/revoke",
		map[string]any{"reason": reason}, rec, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

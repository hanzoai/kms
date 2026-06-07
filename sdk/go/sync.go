// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kms

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// SecretEvent represents a change event from the CRDT sync stream.
type SecretEvent struct {
	// Type is the event type: "set", "delete", or "rotate".
	Type string `json:"type"`

	// SecretID is the (encrypted) identifier of the affected secret.
	SecretID string `json:"secret_id"`

	// Timestamp is the server-observed event time (epoch milliseconds).
	Timestamp int64 `json:"timestamp"`
}

// Sync triggers CRDT sync across all MPC nodes for this org.
// This is normally automatic; use this to force immediate convergence.
func (c *Client) Sync() error {
	path := fmt.Sprintf("/v1/orgs/%s/zk/sync", url.PathEscape(c.orgSlug))
	return c.broadcastPost(path, []byte(`{}`))
}

// Watch subscribes to secret change events via server-sent events (SSE).
// Events are encrypted CRDT operations — the client observes which secrets
// changed without seeing plaintext values.
//
// The returned channel is closed when the context is cancelled or the
// connection drops. Errors during streaming are silently dropped; reconnect
// by calling Watch again.
func (c *Client) Watch(ctx context.Context) (<-chan SecretEvent, error) {
	if len(c.nodes) == 0 {
		return nil, fmt.Errorf("kms: no nodes configured")
	}

	// Connect to the first available node for SSE.
	var (
		resp *http.Response
		err  error
	)

	path := fmt.Sprintf("/v1/orgs/%s/zk/watch", url.PathEscape(c.orgSlug))

	for _, node := range c.nodes {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, node+path, nil)
		if reqErr != nil {
			err = reqErr
			continue
		}
		req.Header.Set("Accept", "text/event-stream")

		resp, err = c.http.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	if err != nil {
		return nil, fmt.Errorf("kms: watch: connect: %w", err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kms: watch: no node available")
	}

	ch := make(chan SecretEvent, 64)

	go func() {
		defer resp.Body.Close()
		defer close(ch)

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := scanner.Text()
			if len(line) == 0 {
				continue
			}

			var event SecretEvent
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				continue
			}

			select {
			case ch <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, nil
}

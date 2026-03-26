// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kms

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// encryptedSecret is the JSON payload sent to and received from MPC nodes.
type encryptedSecret struct {
	Key   []byte `json:"key"`   // encrypted secret name
	Value []byte `json:"value"` // encrypted secret value
}

// secretListResponse is the JSON response from List.
type secretListResponse struct {
	Secrets []encryptedSecret `json:"secrets"`
}

// Set encrypts value client-side with the CEK and sends the encrypted blob
// to the MPC nodes. The key (name) is also encrypted — the nodes never see
// plaintext names or values.
func (c *Client) Set(key string, value []byte) error {
	cek, err := c.getCEK()
	if err != nil {
		return err
	}
	defer clear(cek)

	aad := []byte(c.orgSlug)

	encKey, err := sealAESGCM(cek, []byte(key), aad)
	if err != nil {
		return fmt.Errorf("kms: encrypt key: %w", err)
	}

	encValue, err := sealAESGCM(cek, value, aad)
	if err != nil {
		return fmt.Errorf("kms: encrypt value: %w", err)
	}

	payload := encryptedSecret{
		Key:   encKey,
		Value: encValue,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("kms: marshal secret: %w", err)
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/secrets", url.PathEscape(c.orgSlug))
	return c.broadcastPost(path, data)
}

// Get retrieves an encrypted blob from the MPC nodes and decrypts it
// client-side with the CEK.
func (c *Client) Get(key string) ([]byte, error) {
	cek, err := c.getCEK()
	if err != nil {
		return nil, err
	}
	defer clear(cek)

	aad := []byte(c.orgSlug)

	// Encrypt the key name for lookup (nodes store encrypted names).
	encKey, err := sealAESGCM(cek, []byte(key), aad)
	if err != nil {
		return nil, fmt.Errorf("kms: encrypt key for lookup: %w", err)
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/secrets/%s",
		url.PathEscape(c.orgSlug),
		url.PathEscape(encodeBase64(encKey)),
	)

	body, err := c.quorumGet(path)
	if err != nil {
		return nil, fmt.Errorf("kms: get secret: %w", err)
	}

	var es encryptedSecret
	if err := json.Unmarshal(body, &es); err != nil {
		return nil, fmt.Errorf("kms: unmarshal secret response: %w", err)
	}

	plaintext, err := openAESGCM(cek, es.Value, aad)
	if err != nil {
		return nil, fmt.Errorf("kms: decrypt value: %w", err)
	}

	return plaintext, nil
}

// Delete removes a secret from all MPC nodes.
func (c *Client) Delete(key string) error {
	cek, err := c.getCEK()
	if err != nil {
		return err
	}
	defer clear(cek)

	aad := []byte(c.orgSlug)

	encKey, err := sealAESGCM(cek, []byte(key), aad)
	if err != nil {
		return fmt.Errorf("kms: encrypt key for delete: %w", err)
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/secrets/%s",
		url.PathEscape(c.orgSlug),
		url.PathEscape(encodeBase64(encKey)),
	)

	// Broadcast DELETE to all nodes.
	type result struct {
		err error
	}
	ch := make(chan result, len(c.nodes))

	for _, node := range c.nodes {
		go func(addr string) {
			ch <- result{err: c.deleteRequest(addr + path)}
		}(node)
	}

	var successes int
	var lastErr error
	for range c.nodes {
		r := <-ch
		if r.err != nil {
			lastErr = r.err
		} else {
			successes++
		}
	}

	if successes < c.threshold {
		return fmt.Errorf("kms: delete: only %d of %d nodes responded (need %d): %w",
			successes, len(c.nodes), c.threshold, lastErr)
	}
	return nil
}

// List returns the names of all secrets for this org. Names are encrypted
// on the nodes and decrypted client-side.
func (c *Client) List() ([]string, error) {
	cek, err := c.getCEK()
	if err != nil {
		return nil, err
	}
	defer clear(cek)

	aad := []byte(c.orgSlug)

	path := fmt.Sprintf("/v1/orgs/%s/zk/secrets", url.PathEscape(c.orgSlug))

	body, err := c.quorumGet(path)
	if err != nil {
		return nil, fmt.Errorf("kms: list secrets: %w", err)
	}

	var resp secretListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("kms: unmarshal list response: %w", err)
	}

	names := make([]string, 0, len(resp.Secrets))
	for _, es := range resp.Secrets {
		name, err := openAESGCM(cek, es.Key, aad)
		if err != nil {
			return nil, fmt.Errorf("kms: decrypt secret name: %w", err)
		}
		names = append(names, string(name))
	}

	return names, nil
}

// encodeBase64 encodes bytes to URL-safe base64 without padding.
func encodeBase64(data []byte) string {
	return base64URLEncode(data)
}

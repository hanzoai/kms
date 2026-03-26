// Copyright (C) 2020-2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kms

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// inviteMemberRequest is the JSON payload sent to add a member.
type inviteMemberRequest struct {
	MemberPubKey []byte `json:"member_pub_key"`
	WrappedCEK   []byte `json:"wrapped_cek"`
}

// memberListResponse is the JSON response from ListMembers.
type memberListResponse struct {
	Members []string `json:"members"`
}

// InviteMember wraps the CEK with the new member's HPKE public key
// (ML-KEM-768+X25519 hybrid) and distributes the wrapped CEK to the MPC nodes.
// Returns the wrapped CEK so the caller can deliver it out-of-band if needed.
func (c *Client) InviteMember(memberPubKey []byte) ([]byte, error) {
	cek, err := c.getCEK()
	if err != nil {
		return nil, err
	}
	defer clear(cek)

	wrapped, err := WrapCEKForMember(cek, memberPubKey)
	if err != nil {
		return nil, fmt.Errorf("kms: invite member: %w", err)
	}

	payload := inviteMemberRequest{
		MemberPubKey: memberPubKey,
		WrappedCEK:   wrapped,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("kms: invite member: marshal: %w", err)
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/members", url.PathEscape(c.orgSlug))
	if err := c.broadcastPost(path, data); err != nil {
		return nil, fmt.Errorf("kms: invite member: %w", err)
	}

	return wrapped, nil
}

// RevokeMember removes a member's access. This rotates the CEK and re-wraps
// for all remaining members. The member ID should be the IAM user identifier.
func (c *Client) RevokeMember(memberID string) error {
	if memberID == "" {
		return fmt.Errorf("kms: member ID must not be empty")
	}

	path := fmt.Sprintf("/v1/orgs/%s/zk/members/%s",
		url.PathEscape(c.orgSlug),
		url.PathEscape(memberID),
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
		return fmt.Errorf("kms: revoke member: only %d of %d nodes responded (need %d): %w",
			successes, len(c.nodes), c.threshold, lastErr)
	}
	return nil
}

// ListMembers returns the IDs of all members with access to this org's secrets.
func (c *Client) ListMembers() ([]string, error) {
	path := fmt.Sprintf("/v1/orgs/%s/zk/members", url.PathEscape(c.orgSlug))

	body, err := c.quorumGet(path)
	if err != nil {
		return nil, fmt.Errorf("kms: list members: %w", err)
	}

	var resp memberListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("kms: list members: unmarshal: %w", err)
	}

	return resp.Members, nil
}

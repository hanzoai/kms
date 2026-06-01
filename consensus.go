// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// consensus.go — wires the kmsd ZAP secret-server to its consensus
// authority. Mirror of luxfi/kms cmd/kms/consensus.go but lives in
// hanzo/kms because the Hanzo daemon (cmd/kmsd) is the consumer.
//
// The ZAP server fails closed: with no validator/operator snapshot, the
// authorizer cannot be constructed and the ZAP server stays off. The
// HTTP path (JWT-gated, IAM-issued) is unaffected. The kms-operator is
// the component that drops the snapshot file onto the pod; when it has
// shipped, ZAP comes up. Until then HTTP carries the load.

package kms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/kms/pkg/zapserver"
)

const (
	envConsensusValidators = "KMS_CONSENSUS_VALIDATORS"
	envConsensusOperators  = "KMS_CONSENSUS_OPERATORS"
	envConsensusFile       = "KMS_CONSENSUS_FILE"
	envConsensusTTL        = "KMS_CONSENSUS_TTL"

	defaultConsensusTTL = 30 * time.Second
)

// consensusSnapshot is the wire shape of the JSON file the kms-operator
// drops into the kmsd container. Identical to the env-var carriage so
// the operator can pick either delivery.
type consensusSnapshot struct {
	Validators []string `json:"validators"`
	Operators  []string `json:"operators"`
}

// buildConsensusAuthorizer constructs the ConsensusAuthorizer wired at
// boot. Reads either KMS_CONSENSUS_FILE or KMS_CONSENSUS_VALIDATORS +
// KMS_CONSENSUS_OPERATORS. Returns (nil, nil) when no source is
// configured — the caller treats that as "ZAP server off, HTTP only"
// rather than a fatal. Returns (nil, err) when a source is configured
// but malformed; the caller refuses to start the ZAP server in that
// case (fail-closed on bad input).
func buildConsensusAuthorizer() (zapserver.ConsensusAuthorizer, error) {
	validators, operators, err := loadConsensusSnapshot()
	if err != nil {
		return nil, err
	}
	if len(validators) == 0 && len(operators) == 0 {
		// No snapshot configured. Caller turns off ZAP.
		return nil, nil
	}
	if len(validators) == 0 {
		return nil, errors.New("consensus validator authority is empty (refusing to fail open)")
	}
	if len(operators) == 0 {
		return nil, errors.New("consensus operator authority is empty (refusing to fail open)")
	}
	ttl := defaultConsensusTTL
	if v := strings.TrimSpace(os.Getenv(envConsensusTTL)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envConsensusTTL, err)
		}
		ttl = d
	}
	az, err := zapserver.NewInProcessAuthorizer(zapserver.InProcessAuthorizerConfig{
		Validators: zapserver.NewStaticAuthorityProvider(validators),
		Operator:   zapserver.NewStaticAuthorityProvider(operators),
		CacheTTL:   ttl,
	})
	if err != nil {
		return nil, err
	}
	// Probe both providers once so a malformed snapshot surfaces here
	// (fatal path) rather than on the first inbound request.
	if _, err := az.Authorize(context.Background(), zapserver.Identity{
		NodeID: validators[0],
	}, "self-test", zapserver.OpAuthGet); err != nil {
		return nil, fmt.Errorf("authorizer self-test: %w", err)
	}
	return az, nil
}

// loadConsensusSnapshot returns the (validators, operators) NodeID
// sets, sourcing from KMS_CONSENSUS_FILE first then falling back to
// the two env vars.
func loadConsensusSnapshot() ([]ids.NodeID, []ids.NodeID, error) {
	if path := strings.TrimSpace(os.Getenv(envConsensusFile)); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			// Missing file is not fatal at boot — operator hasn't
			// shipped the snapshot yet. Return empty sets so caller
			// disables ZAP rather than crashing.
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil, nil
			}
			return nil, nil, fmt.Errorf("%s: %w", envConsensusFile, err)
		}
		var snap consensusSnapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", envConsensusFile, err)
		}
		validators, err := parseConsensusNodeIDs(snap.Validators)
		if err != nil {
			return nil, nil, fmt.Errorf("%s validators: %w", envConsensusFile, err)
		}
		operators, err := parseConsensusNodeIDs(snap.Operators)
		if err != nil {
			return nil, nil, fmt.Errorf("%s operators: %w", envConsensusFile, err)
		}
		return validators, operators, nil
	}
	validators, err := parseConsensusNodeIDs(splitConsensusList(os.Getenv(envConsensusValidators)))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", envConsensusValidators, err)
	}
	operators, err := parseConsensusNodeIDs(splitConsensusList(os.Getenv(envConsensusOperators)))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", envConsensusOperators, err)
	}
	return validators, operators, nil
}

// splitConsensusList splits on newlines, commas, and whitespace. Empty
// elements are dropped. Operators pick whichever delimiter suits their
// templating.
func splitConsensusList(raw string) []string {
	if raw == "" {
		return nil
	}
	out := make([]string, 0, 8)
	field := strings.Builder{}
	for _, r := range raw {
		if r == '\n' || r == ',' || r == ' ' || r == '\t' || r == '\r' {
			if field.Len() > 0 {
				out = append(out, field.String())
				field.Reset()
			}
			continue
		}
		field.WriteRune(r)
	}
	if field.Len() > 0 {
		out = append(out, field.String())
	}
	return out
}

// parseConsensusNodeIDs returns the parsed NodeID slice; any malformed
// entry is a hard failure (refuses to boot with a typo in the snapshot).
func parseConsensusNodeIDs(items []string) ([]ids.NodeID, error) {
	out := make([]ids.NodeID, 0, len(items))
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		id, err := ids.NodeIDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", s, err)
		}
		out = append(out, id)
	}
	return out, nil
}

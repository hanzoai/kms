// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package compliance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Cloud logging backends for enterprise audit trails.
// WORM audit log can sink to:
// - Local ZapDB (always, as primary — handled by AuditLog)
// - Google Cloud Logging (GCP) — build tag "gcp"
// - Google Cloud Storage (GCS buckets, WORM retention lock) — build tag "gcp"
// - AWS CloudWatch Logs — build tag "aws"
// - AWS S3 (Object Lock for WORM) — build tag "aws"
// - Azure Monitor / Azure Blob (immutable storage) — build tag "azure"
// - Custom webhook (POST JSON) — always available

// LogSinkType identifies the type of remote log sink.
type LogSinkType int

const (
	SinkZapDB         LogSinkType = iota // Always on (local, primary)
	SinkGCPLogging                       // Google Cloud Logging
	SinkGCSBucket                        // GCS with retention lock
	SinkAWSCloudWatch                    // CloudWatch Logs
	SinkAWSS3                            // S3 with Object Lock
	SinkAzureMonitor                     // Azure Monitor
	SinkAzureBlob                        // Azure Blob immutable
	SinkWebhook                          // Custom webhook (POST JSON)
)

// String returns a human-readable name for the sink type.
func (s LogSinkType) String() string {
	switch s {
	case SinkZapDB:
		return "zapdb"
	case SinkGCPLogging:
		return "gcp-logging"
	case SinkGCSBucket:
		return "gcs-bucket"
	case SinkAWSCloudWatch:
		return "aws-cloudwatch"
	case SinkAWSS3:
		return "aws-s3"
	case SinkAzureMonitor:
		return "azure-monitor"
	case SinkAzureBlob:
		return "azure-blob"
	case SinkWebhook:
		return "webhook"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// LogSinkConfig configures a remote log sink.
type LogSinkConfig struct {
	Type LogSinkType `json:"type"`

	// GCP
	GCPProject string `json:"gcp_project,omitempty"`
	GCPLogName string `json:"gcp_log_name,omitempty"`
	GCSBucket  string `json:"gcs_bucket,omitempty"`

	// AWS
	AWSRegion   string `json:"aws_region,omitempty"`
	AWSLogGroup string `json:"aws_log_group,omitempty"`
	AWSS3Bucket string `json:"aws_s3_bucket,omitempty"`

	// Azure
	AzureWorkspace string `json:"azure_workspace,omitempty"`
	AzureContainer string `json:"azure_container,omitempty"`

	// Webhook
	WebhookURL     string            `json:"webhook_url,omitempty"`
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`
}

// Validate checks the sink configuration for the selected type.
func (c *LogSinkConfig) Validate() error {
	switch c.Type {
	case SinkZapDB:
		return nil // always valid
	case SinkGCPLogging:
		if c.GCPProject == "" {
			return errors.New("compliance/logging: gcp_project required for GCP Logging sink")
		}
	case SinkGCSBucket:
		if c.GCSBucket == "" {
			return errors.New("compliance/logging: gcs_bucket required for GCS sink")
		}
	case SinkAWSCloudWatch:
		if c.AWSRegion == "" || c.AWSLogGroup == "" {
			return errors.New("compliance/logging: aws_region and aws_log_group required for CloudWatch sink")
		}
	case SinkAWSS3:
		if c.AWSRegion == "" || c.AWSS3Bucket == "" {
			return errors.New("compliance/logging: aws_region and aws_s3_bucket required for S3 sink")
		}
	case SinkAzureMonitor:
		if c.AzureWorkspace == "" {
			return errors.New("compliance/logging: azure_workspace required for Azure Monitor sink")
		}
	case SinkAzureBlob:
		if c.AzureContainer == "" {
			return errors.New("compliance/logging: azure_container required for Azure Blob sink")
		}
	case SinkWebhook:
		if c.WebhookURL == "" {
			return errors.New("compliance/logging: webhook_url required for webhook sink")
		}
	default:
		return fmt.Errorf("compliance/logging: unknown sink type %d", int(c.Type))
	}
	return nil
}

// LogSink writes audit entries to a remote logging backend.
type LogSink interface {
	// Write sends a single audit entry to the remote sink.
	Write(entry AuditEntry) error

	// Flush ensures all buffered entries are sent.
	Flush() error

	// Close flushes and releases resources.
	Close() error
}

// NewLogSink creates a LogSink for the given configuration.
func NewLogSink(cfg LogSinkConfig) (LogSink, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	switch cfg.Type {
	case SinkZapDB:
		return &noopSink{}, nil
	case SinkGCPLogging, SinkGCSBucket:
		return nil, fmt.Errorf("compliance/logging: %s not compiled — add build tag `gcp`", cfg.Type)
	case SinkAWSCloudWatch, SinkAWSS3:
		return nil, fmt.Errorf("compliance/logging: %s not compiled — add build tag `aws`", cfg.Type)
	case SinkAzureMonitor, SinkAzureBlob:
		return nil, fmt.Errorf("compliance/logging: %s not compiled — add build tag `azure`", cfg.Type)
	case SinkWebhook:
		return newWebhookSink(cfg), nil
	default:
		return nil, fmt.Errorf("compliance/logging: unknown sink type %d", int(cfg.Type))
	}
}

// noopSink is used for SinkZapDB — the primary store is already handled by AuditLog.
type noopSink struct{}

func (s *noopSink) Write(_ AuditEntry) error { return nil }
func (s *noopSink) Flush() error             { return nil }
func (s *noopSink) Close() error             { return nil }

// webhookSink sends audit entries as JSON POST requests to a configured URL.
type webhookSink struct {
	url     string
	headers map[string]string
	client  *http.Client
	mu      sync.Mutex
	buf     []AuditEntry
}

func newWebhookSink(cfg LogSinkConfig) *webhookSink {
	return &webhookSink{
		url:     cfg.WebhookURL,
		headers: cfg.WebhookHeaders,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Write sends a single audit entry to the webhook endpoint.
func (s *webhookSink) Write(entry AuditEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("compliance/logging/webhook: marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("compliance/logging/webhook: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// Buffer for retry on next flush.
		s.mu.Lock()
		s.buf = append(s.buf, entry)
		s.mu.Unlock()
		return fmt.Errorf("compliance/logging/webhook: send: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		// Buffer for retry.
		s.mu.Lock()
		s.buf = append(s.buf, entry)
		s.mu.Unlock()
		return fmt.Errorf("compliance/logging/webhook: HTTP %d from %s", resp.StatusCode, s.url)
	}

	return nil
}

// Flush retries sending any buffered entries that failed on Write.
func (s *webhookSink) Flush() error {
	s.mu.Lock()
	pending := s.buf
	s.buf = nil
	s.mu.Unlock()

	if len(pending) == 0 {
		return nil
	}

	var failed []AuditEntry
	for _, entry := range pending {
		data, err := json.Marshal(entry)
		if err != nil {
			failed = append(failed, entry)
			continue
		}

		req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(data))
		if err != nil {
			failed = append(failed, entry)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range s.headers {
			req.Header.Set(k, v)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			failed = append(failed, entry)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			failed = append(failed, entry)
		}
	}

	if len(failed) > 0 {
		s.mu.Lock()
		s.buf = append(s.buf, failed...)
		s.mu.Unlock()
		return fmt.Errorf("compliance/logging/webhook: %d entries failed to flush", len(failed))
	}

	return nil
}

// Close flushes remaining entries and releases the HTTP client.
func (s *webhookSink) Close() error {
	err := s.Flush()
	s.client.CloseIdleConnections()
	return err
}

// SinkFanout writes to multiple sinks. If any sink fails, the error is returned
// but remaining sinks still receive the entry (best-effort fan-out).
type SinkFanout struct {
	sinks []LogSink
}

// NewSinkFanout creates a fan-out sink that writes to all provided sinks.
func NewSinkFanout(sinks ...LogSink) *SinkFanout {
	return &SinkFanout{sinks: sinks}
}

// Write sends the entry to all sinks. Returns the first error encountered.
func (f *SinkFanout) Write(entry AuditEntry) error {
	var firstErr error
	for _, s := range f.sinks {
		if err := s.Write(entry); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Flush flushes all sinks.
func (f *SinkFanout) Flush() error {
	var firstErr error
	for _, s := range f.sinks {
		if err := s.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close closes all sinks.
func (f *SinkFanout) Close() error {
	var firstErr error
	for _, s := range f.sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

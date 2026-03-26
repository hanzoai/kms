// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// SPDX-License-Identifier: Proprietary

package compliance

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestLogSinkTypeString(t *testing.T) {
	tests := []struct {
		sink LogSinkType
		want string
	}{
		{SinkZapDB, "zapdb"},
		{SinkGCPLogging, "gcp-logging"},
		{SinkGCSBucket, "gcs-bucket"},
		{SinkAWSCloudWatch, "aws-cloudwatch"},
		{SinkAWSS3, "aws-s3"},
		{SinkAzureMonitor, "azure-monitor"},
		{SinkAzureBlob, "azure-blob"},
		{SinkWebhook, "webhook"},
		{LogSinkType(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.sink.String(); got != tt.want {
			t.Errorf("LogSinkType(%d).String() = %q, want %q", int(tt.sink), got, tt.want)
		}
	}
}

func TestLogSinkConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     LogSinkConfig
		wantErr bool
	}{
		{"zapdb always valid", LogSinkConfig{Type: SinkZapDB}, false},
		{"gcp logging needs project", LogSinkConfig{Type: SinkGCPLogging}, true},
		{"gcp logging valid", LogSinkConfig{Type: SinkGCPLogging, GCPProject: "proj"}, false},
		{"gcs needs bucket", LogSinkConfig{Type: SinkGCSBucket}, true},
		{"gcs valid", LogSinkConfig{Type: SinkGCSBucket, GCSBucket: "b"}, false},
		{"cloudwatch needs region+group", LogSinkConfig{Type: SinkAWSCloudWatch}, true},
		{"cloudwatch valid", LogSinkConfig{Type: SinkAWSCloudWatch, AWSRegion: "us-east-1", AWSLogGroup: "g"}, false},
		{"s3 needs region+bucket", LogSinkConfig{Type: SinkAWSS3}, true},
		{"s3 valid", LogSinkConfig{Type: SinkAWSS3, AWSRegion: "us-east-1", AWSS3Bucket: "b"}, false},
		{"azure monitor needs workspace", LogSinkConfig{Type: SinkAzureMonitor}, true},
		{"azure monitor valid", LogSinkConfig{Type: SinkAzureMonitor, AzureWorkspace: "ws"}, false},
		{"azure blob needs container", LogSinkConfig{Type: SinkAzureBlob}, true},
		{"azure blob valid", LogSinkConfig{Type: SinkAzureBlob, AzureContainer: "c"}, false},
		{"webhook needs url", LogSinkConfig{Type: SinkWebhook}, true},
		{"webhook valid", LogSinkConfig{Type: SinkWebhook, WebhookURL: "https://example.com"}, false},
		{"unknown type", LogSinkConfig{Type: LogSinkType(99)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewLogSink_ZapDB(t *testing.T) {
	sink, err := NewLogSink(LogSinkConfig{Type: SinkZapDB})
	if err != nil {
		t.Fatalf("NewLogSink(ZapDB) error: %v", err)
	}
	// noopSink should work without error.
	if err := sink.Write(AuditEntry{}); err != nil {
		t.Errorf("noopSink.Write error: %v", err)
	}
	if err := sink.Flush(); err != nil {
		t.Errorf("noopSink.Flush error: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("noopSink.Close error: %v", err)
	}
}

func TestNewLogSink_GCPNotCompiled(t *testing.T) {
	_, err := NewLogSink(LogSinkConfig{Type: SinkGCPLogging, GCPProject: "proj"})
	if err == nil {
		t.Fatal("expected error for GCP sink without build tag")
	}
}

func TestNewLogSink_AWSNotCompiled(t *testing.T) {
	_, err := NewLogSink(LogSinkConfig{Type: SinkAWSCloudWatch, AWSRegion: "us-east-1", AWSLogGroup: "g"})
	if err == nil {
		t.Fatal("expected error for AWS sink without build tag")
	}
}

func TestNewLogSink_AzureNotCompiled(t *testing.T) {
	_, err := NewLogSink(LogSinkConfig{Type: SinkAzureMonitor, AzureWorkspace: "ws"})
	if err == nil {
		t.Fatal("expected error for Azure sink without build tag")
	}
}

func TestWebhookSink_Write(t *testing.T) {
	var mu sync.Mutex
	var received []AuditEntry

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		// Check custom header.
		if auth := r.Header.Get("X-API-Key"); auth != "test-key" {
			t.Errorf("expected X-API-Key test-key, got %s", auth)
		}

		body, _ := io.ReadAll(r.Body)
		var entry AuditEntry
		if err := json.Unmarshal(body, &entry); err != nil {
			t.Errorf("unmarshal body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, entry)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewLogSink(LogSinkConfig{
		Type:       SinkWebhook,
		WebhookURL: srv.URL,
		WebhookHeaders: map[string]string{
			"X-API-Key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("NewLogSink error: %v", err)
	}
	defer sink.Close()

	entry := AuditEntry{
		Timestamp: time.Now().UTC(),
		OrgSlug:   "test-org",
		ActorID:   "user-1",
		Action:    "read",
		SecretKey: "db-password",
		SourceIP:  "10.0.0.1",
	}

	if err := sink.Write(entry); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(received))
	}
	if received[0].OrgSlug != "test-org" {
		t.Errorf("OrgSlug = %q, want %q", received[0].OrgSlug, "test-org")
	}
	if received[0].Action != "read" {
		t.Errorf("Action = %q, want %q", received[0].Action, "read")
	}
}

func TestWebhookSink_WriteFailsBuffers(t *testing.T) {
	// Server that returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink, err := NewLogSink(LogSinkConfig{
		Type:       SinkWebhook,
		WebhookURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewLogSink error: %v", err)
	}

	entry := AuditEntry{OrgSlug: "test", Action: "write"}
	err = sink.Write(entry)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	// The entry should be buffered for retry.
	ws := sink.(*webhookSink)
	ws.mu.Lock()
	buffered := len(ws.buf)
	ws.mu.Unlock()
	if buffered != 1 {
		t.Errorf("expected 1 buffered entry, got %d", buffered)
	}
}

func TestWebhookSink_FlushRetries(t *testing.T) {
	var callCount int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		c := callCount
		mu.Unlock()
		if c <= 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := newWebhookSink(LogSinkConfig{
		Type:       SinkWebhook,
		WebhookURL: srv.URL,
	})

	// First write fails.
	entry := AuditEntry{OrgSlug: "test", Action: "rotate"}
	_ = ws.Write(entry) // errors on 500, buffers the entry

	// Flush should retry and succeed (callCount > 1 returns 200).
	if err := ws.Flush(); err != nil {
		t.Fatalf("Flush error: %v", err)
	}

	ws.mu.Lock()
	remaining := len(ws.buf)
	ws.mu.Unlock()
	if remaining != 0 {
		t.Errorf("expected 0 buffered after successful flush, got %d", remaining)
	}
}

func TestSinkFanout(t *testing.T) {
	var count1, count2 int
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count1++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count2++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	s1 := newWebhookSink(LogSinkConfig{Type: SinkWebhook, WebhookURL: srv1.URL})
	s2 := newWebhookSink(LogSinkConfig{Type: SinkWebhook, WebhookURL: srv2.URL})
	fanout := NewSinkFanout(s1, s2)

	entry := AuditEntry{OrgSlug: "org", Action: "read"}
	if err := fanout.Write(entry); err != nil {
		t.Fatalf("fanout.Write error: %v", err)
	}

	if count1 != 1 || count2 != 1 {
		t.Errorf("expected both sinks to receive entry: count1=%d, count2=%d", count1, count2)
	}

	if err := fanout.Close(); err != nil {
		t.Fatalf("fanout.Close error: %v", err)
	}
}

func TestSinkFanout_PartialFailure(t *testing.T) {
	// One sink that works, one that fails.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer good.Close()

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	s1 := newWebhookSink(LogSinkConfig{Type: SinkWebhook, WebhookURL: good.URL})
	s2 := newWebhookSink(LogSinkConfig{Type: SinkWebhook, WebhookURL: bad.URL})
	fanout := NewSinkFanout(s1, s2)

	entry := AuditEntry{OrgSlug: "org", Action: "write"}
	err := fanout.Write(entry)
	if err == nil {
		t.Fatal("expected error from partial failure")
	}
	// Both sinks should have received the entry (best-effort).
}

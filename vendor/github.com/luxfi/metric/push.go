// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PushOpts configures a metrics push request.
type PushOpts struct {
	URL      string
	Job      string
	Instance string
	Gatherer Gatherer
	Client   *http.Client
	Timeout  time.Duration
}

// Push gathers metrics and pushes them to a remote HTTP endpoint.
func Push(opts PushOpts) error {
	if opts.Gatherer == nil {
		return fmt.Errorf("missing gatherer")
	}
	if opts.URL == "" {
		return fmt.Errorf("missing URL")
	}
	base, err := url.Parse(opts.URL)
	if err != nil {
		return err
	}

	path := strings.TrimSuffix(base.Path, "/")
	if opts.Job != "" {
		path += "/metrics/job/" + url.PathEscape(opts.Job)
	}
	if opts.Instance != "" {
		path += "/instance/" + url.PathEscape(opts.Instance)
	}
	if path == "" {
		path = "/"
	}
	base.Path = path

	families, err := opts.Gatherer.Gather()
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := EncodeText(&buf, families); err != nil {
		return err
	}

	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain; version=0.0.4")

	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

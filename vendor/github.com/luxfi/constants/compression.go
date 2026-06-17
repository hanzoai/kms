// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import (
	"errors"
	"strings"
)

var errUnknownCompressionType = errors.New("unknown compression type")

type CompressionType byte

const (
	CompressionTypeNone CompressionType = iota + 1
	CompressionTypeZstd
)

func (t CompressionType) String() string {
	switch t {
	case CompressionTypeNone:
		return "none"
	case CompressionTypeZstd:
		return "zstd"
	default:
		return "unknown"
	}
}

func CompressionTypeFromString(s string) (CompressionType, error) {
	switch s {
	case CompressionTypeNone.String():
		return CompressionTypeNone, nil
	case CompressionTypeZstd.String():
		return CompressionTypeZstd, nil
	default:
		return CompressionTypeNone, errUnknownCompressionType
	}
}

func (t CompressionType) MarshalJSON() ([]byte, error) {
	var b strings.Builder
	if _, err := b.WriteString(`"`); err != nil {
		return nil, err
	}
	if _, err := b.WriteString(t.String()); err != nil {
		return nil, err
	}
	if _, err := b.WriteString(`"`); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

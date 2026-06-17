// Copyright 2025 The Lux Authors
// This file is part of the Lux library.
//
// The Lux library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Lux library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Lux library. If not, see <http://www.gnu.org/licenses/>.

// Package rlp implements the RLP serialization format.
// This is a minimal implementation for crypto package needs.
package rlp

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/luxfi/crypto/common"
)

// EncodeToBytes returns the RLP encoding of val.
func EncodeToBytes(val interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, val); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, val interface{}) error {
	switch v := val.(type) {
	case []byte:
		return encodeBytes(buf, v)
	case string:
		return encodeBytes(buf, []byte(v))
	case uint64:
		return encodeUint64(buf, v)
	case *big.Int:
		return encodeBigInt(buf, v)
	case []interface{}:
		return encodeList(buf, v)
	case common.Address:
		return encodeBytes(buf, v.Bytes())
	case common.Hash:
		return encodeBytes(buf, v.Bytes())
	default:
		// For now, we only need these types
		return nil
	}
}

func encodeBytes(buf *bytes.Buffer, b []byte) error {
	if len(b) == 1 && b[0] <= 0x7f {
		// Single byte < 128 is its own encoding
		buf.WriteByte(b[0])
	} else if len(b) <= 55 {
		// Short string
		buf.WriteByte(byte(0x80 + len(b)))
		buf.Write(b)
	} else {
		// Long string
		lenBytes := encodeLength(uint64(len(b)))
		buf.WriteByte(byte(0xb7 + len(lenBytes)))
		buf.Write(lenBytes)
		buf.Write(b)
	}
	return nil
}

func encodeUint64(buf *bytes.Buffer, i uint64) error {
	if i == 0 {
		return encodeBytes(buf, []byte{})
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	// Trim leading zeros
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return encodeBytes(buf, b)
}

func encodeBigInt(buf *bytes.Buffer, i *big.Int) error {
	if i.Sign() == 0 {
		return encodeBytes(buf, []byte{})
	}
	return encodeBytes(buf, i.Bytes())
}

func encodeList(buf *bytes.Buffer, list []interface{}) error {
	// First encode all elements to get total length
	var content bytes.Buffer
	for _, elem := range list {
		if err := encode(&content, elem); err != nil {
			return err
		}
	}

	contentBytes := content.Bytes()
	if len(contentBytes) <= 55 {
		// Short list
		buf.WriteByte(byte(0xc0 + len(contentBytes)))
		buf.Write(contentBytes)
	} else {
		// Long list
		lenBytes := encodeLength(uint64(len(contentBytes)))
		buf.WriteByte(byte(0xf7 + len(lenBytes)))
		buf.Write(lenBytes)
		buf.Write(contentBytes)
	}
	return nil
}

func encodeLength(i uint64) []byte {
	if i < 256 {
		return []byte{byte(i)}
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	// Trim leading zeros
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

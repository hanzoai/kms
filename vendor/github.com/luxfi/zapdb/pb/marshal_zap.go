//go:build !grpc

/*
 * SPDX-FileCopyrightText: 2017-2025 Istari Digital, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package pb

// Marshaler is the interface for types that can marshal themselves.
type Marshaler interface {
	Marshal() ([]byte, error)
}

// Unmarshaler is the interface for types that can unmarshal themselves.
type Unmarshaler interface {
	Unmarshal([]byte) error
}

// Sizer is the interface for types that can report their encoded size.
type Sizer interface {
	Size() int
}

// Marshal marshals a Marshaler to bytes.
func Marshal(m Marshaler) ([]byte, error) {
	return m.Marshal()
}

// Unmarshal unmarshals bytes into an Unmarshaler.
func Unmarshal(data []byte, m Unmarshaler) error {
	return m.Unmarshal(data)
}

// Size returns the encoded size of a Sizer.
func Size(m Sizer) int {
	return m.Size()
}

// MarshalOptions provides options for marshaling (compatibility with protobuf API).
type MarshalOptions struct{}

// MarshalAppend appends the marshaled form to the provided buffer.
func (MarshalOptions) MarshalAppend(b []byte, m Marshaler) ([]byte, error) {
	data, err := m.Marshal()
	if err != nil {
		return nil, err
	}
	return append(b, data...), nil
}

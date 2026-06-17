//go:build !grpc

/*
 * SPDX-FileCopyrightText: 2017-2025 Istari Digital, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package pb provides native binary encoding for badger protobuf types.
// This implementation replaces protobuf with direct binary encoding for
// reduced dependencies and faster serialization.
package pb

import (
	"encoding/binary"
	"errors"
	"io"
)

// EncryptionAlgo defines encryption algorithm type.
type EncryptionAlgo int32

const (
	EncryptionAlgo_aes EncryptionAlgo = 0
)

// ManifestChange_Operation defines manifest change operations.
type ManifestChange_Operation int32

const (
	ManifestChange_CREATE ManifestChange_Operation = 0
	ManifestChange_DELETE ManifestChange_Operation = 1
)

// Checksum_Algorithm defines checksum algorithm type.
type Checksum_Algorithm int32

const (
	Checksum_CRC32C   Checksum_Algorithm = 0
	Checksum_XXHash64 Checksum_Algorithm = 1
)

var (
	errBufferTooSmall = errors.New("buffer too small for unmarshaling")
	errInvalidData    = errors.New("invalid data format")
)

// KV represents a key-value pair.
type KV struct {
	Key        []byte
	Value      []byte
	UserMeta   []byte
	Version    uint64
	ExpiresAt  uint64
	Meta       []byte
	StreamId   uint32
	StreamDone bool
}

func (k *KV) GetKey() []byte       { return k.Key }
func (k *KV) GetValue() []byte     { return k.Value }
func (k *KV) GetUserMeta() []byte  { return k.UserMeta }
func (k *KV) GetVersion() uint64   { return k.Version }
func (k *KV) GetExpiresAt() uint64 { return k.ExpiresAt }
func (k *KV) GetMeta() []byte      { return k.Meta }
func (k *KV) GetStreamId() uint32  { return k.StreamId }
func (k *KV) GetStreamDone() bool  { return k.StreamDone }
func (k *KV) Reset()               { *k = KV{} }
func (k *KV) String() string       { return "KV{...}" }

// Size returns the encoded size of KV.
// Format: [keyLen:4][key][valueLen:4][value][userMetaLen:4][userMeta]
//         [version:8][expiresAt:8][metaLen:4][meta][streamId:4][streamDone:1]
func (k *KV) Size() int {
	return 4 + len(k.Key) +
		4 + len(k.Value) +
		4 + len(k.UserMeta) +
		8 + // version
		8 + // expiresAt
		4 + len(k.Meta) +
		4 + // streamId
		1 // streamDone
}

// Marshal encodes KV to binary format.
func (k *KV) Marshal() ([]byte, error) {
	buf := make([]byte, k.Size())
	_, err := k.MarshalToSizedBuffer(buf)
	return buf, err
}

// MarshalToSizedBuffer marshals KV to a pre-allocated buffer.
func (k *KV) MarshalToSizedBuffer(buf []byte) (int, error) {
	if len(buf) < k.Size() {
		return 0, io.ErrShortBuffer
	}
	offset := 0

	// Key
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(k.Key)))
	offset += 4
	copy(buf[offset:], k.Key)
	offset += len(k.Key)

	// Value
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(k.Value)))
	offset += 4
	copy(buf[offset:], k.Value)
	offset += len(k.Value)

	// UserMeta
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(k.UserMeta)))
	offset += 4
	copy(buf[offset:], k.UserMeta)
	offset += len(k.UserMeta)

	// Version
	binary.LittleEndian.PutUint64(buf[offset:], k.Version)
	offset += 8

	// ExpiresAt
	binary.LittleEndian.PutUint64(buf[offset:], k.ExpiresAt)
	offset += 8

	// Meta
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(k.Meta)))
	offset += 4
	copy(buf[offset:], k.Meta)
	offset += len(k.Meta)

	// StreamId
	binary.LittleEndian.PutUint32(buf[offset:], k.StreamId)
	offset += 4

	// StreamDone
	if k.StreamDone {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset++

	return offset, nil
}

// Unmarshal decodes KV from binary format.
func (k *KV) Unmarshal(data []byte) error {
	if len(data) < 37 { // minimum size: 4+0+4+0+4+0+8+8+4+0+4+1
		return errBufferTooSmall
	}
	offset := 0

	// Key
	keyLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+keyLen > len(data) {
		return errBufferTooSmall
	}
	k.Key = make([]byte, keyLen)
	copy(k.Key, data[offset:offset+keyLen])
	offset += keyLen

	// Value
	if offset+4 > len(data) {
		return errBufferTooSmall
	}
	valueLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+valueLen > len(data) {
		return errBufferTooSmall
	}
	k.Value = make([]byte, valueLen)
	copy(k.Value, data[offset:offset+valueLen])
	offset += valueLen

	// UserMeta
	if offset+4 > len(data) {
		return errBufferTooSmall
	}
	userMetaLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+userMetaLen > len(data) {
		return errBufferTooSmall
	}
	k.UserMeta = make([]byte, userMetaLen)
	copy(k.UserMeta, data[offset:offset+userMetaLen])
	offset += userMetaLen

	// Version
	if offset+8 > len(data) {
		return errBufferTooSmall
	}
	k.Version = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	// ExpiresAt
	if offset+8 > len(data) {
		return errBufferTooSmall
	}
	k.ExpiresAt = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	// Meta
	if offset+4 > len(data) {
		return errBufferTooSmall
	}
	metaLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+metaLen > len(data) {
		return errBufferTooSmall
	}
	k.Meta = make([]byte, metaLen)
	copy(k.Meta, data[offset:offset+metaLen])
	offset += metaLen

	// StreamId
	if offset+4 > len(data) {
		return errBufferTooSmall
	}
	k.StreamId = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// StreamDone
	if offset+1 > len(data) {
		return errBufferTooSmall
	}
	k.StreamDone = data[offset] != 0

	return nil
}

// KVList represents a list of KV pairs.
type KVList struct {
	Kv       []*KV
	AllocRef uint64
}

func (l *KVList) GetKv() []*KV        { return l.Kv }
func (l *KVList) GetAllocRef() uint64 { return l.AllocRef }
func (l *KVList) Reset()              { *l = KVList{} }
func (l *KVList) String() string      { return "KVList{...}" }

// Size returns the encoded size of KVList.
func (l *KVList) Size() int {
	size := 4 + 8 // count + allocRef
	for _, kv := range l.Kv {
		size += 4 + kv.Size() // length prefix + kv data
	}
	return size
}

// Marshal encodes KVList to binary format.
func (l *KVList) Marshal() ([]byte, error) {
	buf := make([]byte, l.Size())
	offset := 0

	// Count
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(l.Kv)))
	offset += 4

	// KVs
	for _, kv := range l.Kv {
		kvSize := kv.Size()
		binary.LittleEndian.PutUint32(buf[offset:], uint32(kvSize))
		offset += 4
		kv.MarshalToSizedBuffer(buf[offset : offset+kvSize])
		offset += kvSize
	}

	// AllocRef
	binary.LittleEndian.PutUint64(buf[offset:], l.AllocRef)

	return buf, nil
}

// Unmarshal decodes KVList from binary format.
func (l *KVList) Unmarshal(data []byte) error {
	if len(data) < 12 { // minimum: count(4) + allocRef(8)
		return errBufferTooSmall
	}
	offset := 0

	// Count
	count := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4

	l.Kv = make([]*KV, count)
	for i := 0; i < count; i++ {
		if offset+4 > len(data) {
			return errBufferTooSmall
		}
		kvSize := int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if offset+kvSize > len(data) {
			return errBufferTooSmall
		}
		l.Kv[i] = &KV{}
		if err := l.Kv[i].Unmarshal(data[offset : offset+kvSize]); err != nil {
			return err
		}
		offset += kvSize
	}

	// AllocRef
	if offset+8 > len(data) {
		return errBufferTooSmall
	}
	l.AllocRef = binary.LittleEndian.Uint64(data[offset:])

	return nil
}

// ManifestChange represents a change to the manifest.
type ManifestChange struct {
	Id             uint64
	Op             ManifestChange_Operation
	Level          uint32
	KeyId          uint64
	EncryptionAlgo EncryptionAlgo
	Compression    uint32
}

func (m *ManifestChange) GetId() uint64                       { return m.Id }
func (m *ManifestChange) GetOp() ManifestChange_Operation     { return m.Op }
func (m *ManifestChange) GetLevel() uint32                    { return m.Level }
func (m *ManifestChange) GetKeyId() uint64                    { return m.KeyId }
func (m *ManifestChange) GetEncryptionAlgo() EncryptionAlgo   { return m.EncryptionAlgo }
func (m *ManifestChange) GetCompression() uint32              { return m.Compression }
func (m *ManifestChange) Reset()                              { *m = ManifestChange{} }
func (m *ManifestChange) String() string                      { return "ManifestChange{...}" }

// Size returns the encoded size of ManifestChange.
// Format: [id:8][op:4][level:4][keyId:8][encryptionAlgo:4][compression:4]
func (m *ManifestChange) Size() int {
	return 8 + 4 + 4 + 8 + 4 + 4 // 32 bytes
}

// Marshal encodes ManifestChange to binary format.
func (m *ManifestChange) Marshal() ([]byte, error) {
	buf := make([]byte, m.Size())
	offset := 0

	binary.LittleEndian.PutUint64(buf[offset:], m.Id)
	offset += 8

	binary.LittleEndian.PutUint32(buf[offset:], uint32(m.Op))
	offset += 4

	binary.LittleEndian.PutUint32(buf[offset:], m.Level)
	offset += 4

	binary.LittleEndian.PutUint64(buf[offset:], m.KeyId)
	offset += 8

	binary.LittleEndian.PutUint32(buf[offset:], uint32(m.EncryptionAlgo))
	offset += 4

	binary.LittleEndian.PutUint32(buf[offset:], m.Compression)

	return buf, nil
}

// Unmarshal decodes ManifestChange from binary format.
func (m *ManifestChange) Unmarshal(data []byte) error {
	if len(data) < 32 {
		return errBufferTooSmall
	}
	offset := 0

	m.Id = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	m.Op = ManifestChange_Operation(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4

	m.Level = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	m.KeyId = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	m.EncryptionAlgo = EncryptionAlgo(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4

	m.Compression = binary.LittleEndian.Uint32(data[offset:])

	return nil
}

// ManifestChangeSet represents a set of manifest changes.
type ManifestChangeSet struct {
	Changes []*ManifestChange
}

func (m *ManifestChangeSet) GetChanges() []*ManifestChange { return m.Changes }
func (m *ManifestChangeSet) Reset()                        { *m = ManifestChangeSet{} }
func (m *ManifestChangeSet) String() string                { return "ManifestChangeSet{...}" }

// Size returns the encoded size of ManifestChangeSet.
func (m *ManifestChangeSet) Size() int {
	size := 4 // count
	for range m.Changes {
		size += 4 + 32 // length prefix + ManifestChange size
	}
	return size
}

// Marshal encodes ManifestChangeSet to binary format.
func (m *ManifestChangeSet) Marshal() ([]byte, error) {
	buf := make([]byte, m.Size())
	offset := 0

	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(m.Changes)))
	offset += 4

	for _, change := range m.Changes {
		changeData, err := change.Marshal()
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(changeData)))
		offset += 4
		copy(buf[offset:], changeData)
		offset += len(changeData)
	}

	return buf, nil
}

// Unmarshal decodes ManifestChangeSet from binary format.
func (m *ManifestChangeSet) Unmarshal(data []byte) error {
	if len(data) < 4 {
		return errBufferTooSmall
	}
	offset := 0

	count := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4

	m.Changes = make([]*ManifestChange, count)
	for i := 0; i < count; i++ {
		if offset+4 > len(data) {
			return errBufferTooSmall
		}
		changeSize := int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if offset+changeSize > len(data) {
			return errBufferTooSmall
		}
		m.Changes[i] = &ManifestChange{}
		if err := m.Changes[i].Unmarshal(data[offset : offset+changeSize]); err != nil {
			return err
		}
		offset += changeSize
	}

	return nil
}

// DataKey represents an encryption data key.
type DataKey struct {
	KeyId     uint64
	Data      []byte
	Iv        []byte
	CreatedAt int64
}

func (d *DataKey) GetKeyId() uint64     { return d.KeyId }
func (d *DataKey) GetData() []byte      { return d.Data }
func (d *DataKey) GetIv() []byte        { return d.Iv }
func (d *DataKey) GetCreatedAt() int64  { return d.CreatedAt }
func (d *DataKey) Reset()               { *d = DataKey{} }
func (d *DataKey) String() string       { return "DataKey{...}" }

// Size returns the encoded size of DataKey.
// Format: [keyId:8][dataLen:4][data][ivLen:4][iv][createdAt:8]
func (d *DataKey) Size() int {
	return 8 + 4 + len(d.Data) + 4 + len(d.Iv) + 8
}

// Marshal encodes DataKey to binary format.
func (d *DataKey) Marshal() ([]byte, error) {
	buf := make([]byte, d.Size())
	offset := 0

	binary.LittleEndian.PutUint64(buf[offset:], d.KeyId)
	offset += 8

	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(d.Data)))
	offset += 4
	copy(buf[offset:], d.Data)
	offset += len(d.Data)

	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(d.Iv)))
	offset += 4
	copy(buf[offset:], d.Iv)
	offset += len(d.Iv)

	binary.LittleEndian.PutUint64(buf[offset:], uint64(d.CreatedAt))

	return buf, nil
}

// Unmarshal decodes DataKey from binary format.
func (d *DataKey) Unmarshal(data []byte) error {
	if len(data) < 24 { // minimum: keyId(8) + dataLen(4) + ivLen(4) + createdAt(8)
		return errBufferTooSmall
	}
	offset := 0

	d.KeyId = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	dataLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+dataLen > len(data) {
		return errBufferTooSmall
	}
	d.Data = make([]byte, dataLen)
	copy(d.Data, data[offset:offset+dataLen])
	offset += dataLen

	if offset+4 > len(data) {
		return errBufferTooSmall
	}
	ivLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+ivLen > len(data) {
		return errBufferTooSmall
	}
	d.Iv = make([]byte, ivLen)
	copy(d.Iv, data[offset:offset+ivLen])
	offset += ivLen

	if offset+8 > len(data) {
		return errBufferTooSmall
	}
	d.CreatedAt = int64(binary.LittleEndian.Uint64(data[offset:]))

	return nil
}

// Checksum represents a checksum with algorithm.
type Checksum struct {
	Algo Checksum_Algorithm
	Sum  uint64
}

func (c *Checksum) GetAlgo() Checksum_Algorithm { return c.Algo }
func (c *Checksum) GetSum() uint64              { return c.Sum }
func (c *Checksum) Reset()                      { *c = Checksum{} }
func (c *Checksum) String() string              { return "Checksum{...}" }

// Size returns the encoded size of Checksum.
// Format: [algo:4][sum:8]
func (c *Checksum) Size() int {
	return 4 + 8 // 12 bytes
}

// Marshal encodes Checksum to binary format.
func (c *Checksum) Marshal() ([]byte, error) {
	buf := make([]byte, c.Size())

	binary.LittleEndian.PutUint32(buf[0:], uint32(c.Algo))
	binary.LittleEndian.PutUint64(buf[4:], c.Sum)

	return buf, nil
}

// Unmarshal decodes Checksum from binary format.
func (c *Checksum) Unmarshal(data []byte) error {
	if len(data) < 12 {
		return errBufferTooSmall
	}

	c.Algo = Checksum_Algorithm(binary.LittleEndian.Uint32(data[0:]))
	c.Sum = binary.LittleEndian.Uint64(data[4:])

	return nil
}

// Match represents a match pattern.
type Match struct {
	Prefix      []byte
	IgnoreBytes string
}

func (m *Match) GetPrefix() []byte       { return m.Prefix }
func (m *Match) GetIgnoreBytes() string  { return m.IgnoreBytes }
func (m *Match) Reset()                  { *m = Match{} }
func (m *Match) String() string          { return "Match{...}" }

// Size returns the encoded size of Match.
// Format: [prefixLen:4][prefix][ignoreBytesLen:4][ignoreBytes]
func (m *Match) Size() int {
	return 4 + len(m.Prefix) + 4 + len(m.IgnoreBytes)
}

// Marshal encodes Match to binary format.
func (m *Match) Marshal() ([]byte, error) {
	buf := make([]byte, m.Size())
	offset := 0

	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(m.Prefix)))
	offset += 4
	copy(buf[offset:], m.Prefix)
	offset += len(m.Prefix)

	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(m.IgnoreBytes)))
	offset += 4
	copy(buf[offset:], m.IgnoreBytes)

	return buf, nil
}

// Unmarshal decodes Match from binary format.
func (m *Match) Unmarshal(data []byte) error {
	if len(data) < 8 { // minimum: prefixLen(4) + ignoreBytesLen(4)
		return errBufferTooSmall
	}
	offset := 0

	prefixLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+prefixLen > len(data) {
		return errBufferTooSmall
	}
	m.Prefix = make([]byte, prefixLen)
	copy(m.Prefix, data[offset:offset+prefixLen])
	offset += prefixLen

	if offset+4 > len(data) {
		return errBufferTooSmall
	}
	ignoreBytesLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+ignoreBytesLen > len(data) {
		return errBufferTooSmall
	}
	m.IgnoreBytes = string(data[offset : offset+ignoreBytesLen])

	return nil
}

// Clone returns a deep copy of KV.
func (k *KV) Clone() *KV {
	if k == nil {
		return nil
	}
	clone := &KV{
		Version:    k.Version,
		ExpiresAt:  k.ExpiresAt,
		StreamId:   k.StreamId,
		StreamDone: k.StreamDone,
	}
	if k.Key != nil {
		clone.Key = make([]byte, len(k.Key))
		copy(clone.Key, k.Key)
	}
	if k.Value != nil {
		clone.Value = make([]byte, len(k.Value))
		copy(clone.Value, k.Value)
	}
	if k.UserMeta != nil {
		clone.UserMeta = make([]byte, len(k.UserMeta))
		copy(clone.UserMeta, k.UserMeta)
	}
	if k.Meta != nil {
		clone.Meta = make([]byte, len(k.Meta))
		copy(clone.Meta, k.Meta)
	}
	return clone
}

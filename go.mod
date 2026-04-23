module github.com/hanzoai/kms

// Hanzo KMS is a thin wrapper over the canonical luxfi/kms implementation.
// All server logic lives in github.com/luxfi/kms. This module provides:
//   - cmd/kmsd  : daemon with Hanzo defaults (port 8443, /data/hanzo-kms, branding)
//   - cmd/kms   : admin CLI (uses pkg/kmsclient)
//   - pkg/kmsclient : Go client library used by other Hanzo services
//
// Wire-compatible with luxfi clients on both HTTP (/v1/kms/*) and ZAP
// (opcodes 0x0040..0x0043).

go 1.26.1

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/luxfi/kms v1.5.1
	github.com/luxfi/zap v0.2.1
	github.com/luxfi/zapdb v1.9.0
	modernc.org/sqlite v1.49.1
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.4.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/flatbuffers v25.12.19+incompatible // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grandcat/zeroconf v1.0.0 // indirect
	github.com/klauspost/compress v1.18.4 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/luxfi/age v1.4.0 // indirect
	github.com/luxfi/mdns v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/minio/minio-go/v7 v7.0.100 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/tinylib/msgp v1.6.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.40.0 // indirect
	go.opentelemetry.io/otel/metric v1.40.0 // indirect
	go.opentelemetry.io/otel/trace v1.40.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	modernc.org/libc v1.72.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// Local development: point at sibling lux/kms checkout. CI overrides with
// the published version via GOPROXY.

module github.com/hanzoai/kms

// Hanzo KMS is a thin wrapper over the canonical luxfi/kms implementation.
// All server logic lives in github.com/luxfi/kms. This module provides:
//   - cmd/kmsd  : daemon with Hanzo defaults (port 8443, /data/hanzo-kms, branding)
//   - cmd/kms   : admin CLI (uses pkg/kmsclient)
//   - pkg/kmsclient : Go client library used by other Hanzo services
//
// Wire-compatible with luxfi clients on both HTTP (/v1/kms/*) and ZAP
// (opcodes 0x0040..0x0043).

go 1.26.4

// luxfi/keys + luxfi/kms drive the consensus-native ZAP secret surface.
// Tagged upstream:
//   luxfi/keys v1.1.0   — BBF-bound hybrid signature (secp256k1+ML-DSA-65)
//   luxfi/kms  v1.11.0  — anti-replay nonce ledger closes 5min window
require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/hanzoai/cloud v0.1.1-0.20260519183759-098489930d01
	github.com/hanzoai/zip v0.2.0
	github.com/luxfi/keys v1.1.0
	github.com/luxfi/kms v1.11.0
	github.com/luxfi/log v1.4.3
	github.com/luxfi/zap v0.7.2
	github.com/luxfi/zapdb v1.10.0
	modernc.org/sqlite v1.50.0
)

require github.com/luxfi/ids v1.2.15

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20260311194731-d5b7577c683d // indirect
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.6 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/dgraph-io/ristretto/v2 v2.4.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gofiber/fiber/v3 v3.2.0 // indirect
	github.com/gofiber/schema v1.7.1 // indirect
	github.com/gofiber/utils/v2 v2.0.4 // indirect
	github.com/google/flatbuffers v25.12.19+incompatible // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/grandcat/zeroconf v1.0.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/luxfi/accel v1.1.9 // indirect
	github.com/luxfi/address v1.0.1 // indirect
	github.com/luxfi/age v1.5.0 // indirect
	github.com/luxfi/cache v1.2.1 // indirect
	github.com/luxfi/codec v1.1.4 // indirect
	github.com/luxfi/constants v1.5.8-0.20260603055356-93c2c2ceb9ca // indirect
	github.com/luxfi/container v0.0.4 // indirect
	github.com/luxfi/crypto v1.19.17 // indirect
	github.com/luxfi/formatting v1.0.1 // indirect
	github.com/luxfi/geth v1.16.98 // indirect
	github.com/luxfi/go-bip32 v1.0.2 // indirect
	github.com/luxfi/go-bip39 v1.1.2 // indirect
	github.com/luxfi/math v1.4.1 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/mdns v0.1.1 // indirect
	github.com/luxfi/metric v1.5.7 // indirect
	github.com/luxfi/mock v0.1.1 // indirect
	github.com/luxfi/proto v1.0.0 // indirect
	github.com/luxfi/sampler v1.1.0 // indirect
	github.com/luxfi/tls v1.0.3 // indirect
	github.com/luxfi/vm v1.2.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/minio/minio-go/v7 v7.0.100 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.70.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/exp v0.0.0-20260312153236-7ab1446f8b90 // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
	gonum.org/v1/gonum v0.17.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	modernc.org/libc v1.72.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

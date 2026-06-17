#!/bin/bash

# Run this script from its directory, so that badgerpb4.proto is where it's expected to
# be.

go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
protoc --go_out=. --go_opt=paths=source_relative badgerpb4.proto

# Add grpc build tag so protobuf types are only compiled when grpc tag is set.
# The default (non-grpc) build uses native binary encoding from types_zap.go.
sed -i.bak '1s/^/\/\/go:build grpc\n\n/' badgerpb4.pb.go && rm -f badgerpb4.pb.go.bak

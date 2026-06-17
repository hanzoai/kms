#!/bin/bash
# Build script for ML-DSA C library
# Copyright (C) 2025, Lux Industries Inc.

set -e

echo "Building ML-DSA C library..."

cd c

# Build for all three security levels
echo "Building ML-DSA-44 (Dilithium2)..."
make clean
DILITHIUM_MODE=2 make
mv libmldsa.a libmldsa44.a

echo "Building ML-DSA-65 (Dilithium3)..."
make clean
DILITHIUM_MODE=3 make
mv libmldsa.a libmldsa65.a

echo "Building ML-DSA-87 (Dilithium5)..."
make clean
DILITHIUM_MODE=5 make
mv libmldsa.a libmldsa87.a

# Create combined library
echo "Creating combined library..."
ar -x libmldsa44.a
ar -x libmldsa65.a
ar -x libmldsa87.a
ar rcs libmldsa.a *.o
rm *.o

echo "ML-DSA C library built successfully!"
echo "Libraries created:"
echo "  - libmldsa.a (combined)"
echo "  - libmldsa44.a (ML-DSA-44)"
echo "  - libmldsa65.a (ML-DSA-65)"
echo "  - libmldsa87.a (ML-DSA-87)"
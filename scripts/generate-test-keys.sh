#!/bin/bash
# Generate test validator keys for development and testing
#
# Usage: ./scripts/generate-test-keys.sh [count] [output_dir] [password]
#
# This script generates BLS12-381 validator keypairs and saves them as
# EIP-2335 JSON keystores.

set -e

COUNT=${1:-1}
OUTPUT_DIR=${2:-./keys}
PASSWORD=${3:-testpassword}

echo "Generating $COUNT test validator key(s) in $OUTPUT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run the key generation using cargo
cargo run --release --bin generate-test-keys -- --count "$COUNT" --output "$OUTPUT_DIR" --password "$PASSWORD"

echo "Done! Keys saved to $OUTPUT_DIR"
echo ""
echo "To use these keys:"
echo "  export NKLAVE_KEYSTORE_PASSWORD=$PASSWORD"
echo "  cargo run --release"

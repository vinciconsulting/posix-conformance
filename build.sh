#!/bin/bash
# Build the PSE51/52 conformance test binary
#
# Outputs:
#   target/x86_64-unknown-linux-gnu/release/posix-conformance - Static (for µKernel)
#   target/release/posix-conformance - Dynamic (for Docker/dev testing)
#
set -euo pipefail
cd "$(dirname "$0")"

# Default to static build for µKernel
TARGET="${1:-static}"

case "$TARGET" in
    static)
        # Static no_std build for µKernel POSIX domain loading
        # Uses gnu target with -nostartfiles -static linker flags from .cargo/config.toml
        cargo build --release --target x86_64-unknown-linux-gnu
        BINARY="target/x86_64-unknown-linux-gnu/release/posix-conformance"
        strip "$BINARY"
        echo ""
        echo "Built (static): $BINARY"
        ls -la "$BINARY"
        file "$BINARY"
        ;;
    dynamic|dev)
        # Dynamic build for local testing/Docker (same flags, same output)
        cargo build --release
        BINARY="target/release/posix-conformance"
        echo ""
        echo "Built (dynamic): $BINARY"
        ls -la "$BINARY"
        ;;
    *)
        echo "Usage: $0 [static|dynamic]"
        echo "  static  - For µKernel POSIX domain (default)"
        echo "  dynamic - For Docker/local testing"
        exit 1
        ;;
esac

#!/usr/bin/env bash
#
# Build Suricata with AddressSanitizer (ASAN)
#
# This script builds Suricata instrumented with AddressSanitizer to detect:
#   - Heap/stack/global buffer overflows
#   - Use-after-free
#   - Double-free
#   - Memory leaks (disabled for fuzzing)
#
# Output: $BUILD_DIR/suricata-asan/
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_step() { echo -e "${CYAN}▶${NC} $1"; }

# Verify environment
if [ -z "${SURICATA_FUZZ_ROOT:-}" ]; then
    log_error "Not in Nix development environment"
    echo "Run: nix develop"
    exit 1
fi

if [ ! -d "$SURICATA_SRC" ]; then
    log_error "Suricata source not found at $SURICATA_SRC"
    echo "Clone first: git clone https://github.com/OISF/suricata.git $SURICATA_SRC"
    exit 1
fi

log_step "Building Suricata with AddressSanitizer"
echo ""

# Build directory
BUILD_ASAN="$BUILD_DIR/suricata-asan"
mkdir -p "$BUILD_ASAN"

cd "$SURICATA_SRC"

# Clean previous build
log_info "Cleaning previous build..."
rm -rf build-asan
mkdir -p build-asan
cd build-asan

# ASAN flags
ASAN_CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
ASAN_LDFLAGS="-fsanitize=address"

log_info "Configuring with ASAN instrumentation..."
log_info "  CFLAGS: $ASAN_CFLAGS"

# Configure Suricata
CC="$CC" \
CFLAGS="$ASAN_CFLAGS" \
LDFLAGS="$ASAN_LDFLAGS" \
../configure \
    --prefix="$BUILD_ASAN" \
    --enable-debug \
    --enable-unittests \
    --disable-shared \
    --enable-rust \
    --enable-lua \
    --enable-geoip \
    --enable-hiredis

log_info "Building Suricata (this may take 5-10 minutes)..."
make -j$(nproc) 2>&1 | grep -E "(error|warning:)" || true

log_info "Installing to $BUILD_ASAN..."
make install

# Verify build
if [ -f "$BUILD_ASAN/bin/suricata" ]; then
    log_success "Suricata-ASAN built successfully"

    # Test binary
    VERSION=$("$BUILD_ASAN/bin/suricata" --build-info | head -1)
    log_info "Version: $VERSION"

    # Verify ASAN is linked
    if ldd "$BUILD_ASAN/bin/suricata" | grep -q "libasan"; then
        log_success "ASAN runtime linked correctly"
    else
        log_error "Warning: ASAN runtime not found in binary"
    fi

    echo ""
    log_success "Build complete: $BUILD_ASAN/bin/suricata"
else
    log_error "Build failed - binary not found"
    exit 1
fi

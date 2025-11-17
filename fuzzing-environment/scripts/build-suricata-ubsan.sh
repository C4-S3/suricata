#!/usr/bin/env bash
#
# Build Suricata with UndefinedBehaviorSanitizer (UBSAN)
#
# This script builds Suricata instrumented with UBSan to detect:
#   - Integer overflows/underflows
#   - Null pointer dereferences
#   - Misaligned memory access
#   - Signed integer overflow
#   - Division by zero
#
# Output: $BUILD_DIR/suricata-ubsan/
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
if [ -z "${FUZZING_ROOT:-}" ]; then
    log_error "Not in Nix development environment"
    echo "Run: nix develop"
    exit 1
fi

# Backward compatibility
SURICATA_FUZZ_ROOT="${FUZZING_ROOT}"

if [ ! -d "$SURICATA_SRC" ]; then
    log_error "Suricata source not found at $SURICATA_SRC"
    exit 1
fi

log_step "Building Suricata with UndefinedBehaviorSanitizer"
echo ""

# Build directory
BUILD_UBSAN="$BUILD_DIR/suricata-ubsan"
mkdir -p "$BUILD_UBSAN"

cd "$SURICATA_SRC"

# Bootstrap if needed
if [ ! -f configure ]; then
    log_info "Bootstrapping Suricata build system..."
    ./autogen.sh
    log_success "Bootstrap complete"
fi

# Clean previous build
log_info "Cleaning previous build..."
rm -rf build-ubsan
mkdir -p build-ubsan
cd build-ubsan

# UBSAN flags - comprehensive UB detection
UBSAN_CFLAGS="-fsanitize=undefined,integer,nullability -fno-omit-frame-pointer -g -O1"
UBSAN_LDFLAGS="-fsanitize=undefined,integer,nullability"

log_info "Configuring with UBSAN instrumentation..."
log_info "  CFLAGS: $UBSAN_CFLAGS"

# Configure Suricata
CC="$CC" \
CFLAGS="$UBSAN_CFLAGS" \
LDFLAGS="$UBSAN_LDFLAGS" \
../configure \
    --prefix="$BUILD_UBSAN" \
    --enable-debug \
    --enable-unittests \
    --disable-shared

log_info "Building Suricata (this may take 5-10 minutes)..."
make -j$(nproc) 2>&1 | grep -E "(error|warning:)" || true

log_info "Installing to $BUILD_UBSAN..."
make install

# Verify build
if [ -f "$BUILD_UBSAN/bin/suricata" ]; then
    log_success "Suricata-UBSAN built successfully"

    VERSION=$("$BUILD_UBSAN/bin/suricata" --build-info | head -1)
    log_info "Version: $VERSION"

    # Verify UBSAN is linked
    if ldd "$BUILD_UBSAN/bin/suricata" | grep -q "libubsan"; then
        log_success "UBSAN runtime linked correctly"
    else
        log_error "Warning: UBSAN runtime not found in binary"
    fi

    echo ""
    log_success "Build complete: $BUILD_UBSAN/bin/suricata"
else
    log_error "Build failed - binary not found"
    exit 1
fi

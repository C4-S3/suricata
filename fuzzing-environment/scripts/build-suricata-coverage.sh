#!/usr/bin/env bash
#
# Build Suricata with Code Coverage Instrumentation
#
# This script builds Suricata with gcov/lcov coverage tracking to measure:
#   - Line coverage
#   - Branch coverage
#   - Function coverage
#
# Used for analyzing fuzzer corpus effectiveness
#
# Output: $BUILD_DIR/suricata-coverage/
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
    log_error "Not in Nix development environment"
    echo "Run: nix develop"
    exit 1
fi

if [ ! -d "$SURICATA_SRC" ]; then
    log_error "Suricata source not found at $SURICATA_SRC"
    exit 1
fi

log_step "Building Suricata with Code Coverage"
echo ""

# Build directory
BUILD_COV="$BUILD_DIR/suricata-coverage"
mkdir -p "$BUILD_COV"

cd "$SURICATA_SRC"

# Clean previous build
log_info "Cleaning previous build..."
rm -rf build-coverage
mkdir -p build-coverage
cd build-coverage

# Coverage flags
COV_CFLAGS="-fprofile-arcs -ftest-coverage -g -O0"
COV_LDFLAGS="--coverage"

log_info "Configuring with coverage instrumentation..."
log_info "  CFLAGS: $COV_CFLAGS"

# Configure Suricata
CC="$CC" \
CFLAGS="$COV_CFLAGS" \
LDFLAGS="$COV_LDFLAGS" \
../configure \
    --prefix="$BUILD_COV" \
    --enable-debug \
    --enable-unittests \
    --disable-shared \
    --enable-rust \
    --enable-lua \
    --enable-geoip \
    --enable-hiredis

log_info "Building Suricata (this may take 5-10 minutes)..."
make -j$(nproc) 2>&1 | grep -E "(error|warning:)" || true

log_info "Installing to $BUILD_COV..."
make install

# Verify build
if [ -f "$BUILD_COV/bin/suricata" ]; then
    log_success "Suricata-Coverage built successfully"

    VERSION=$("$BUILD_COV/bin/suricata" --build-info | head -1)
    log_info "Version: $VERSION"

    # Check for .gcno files (coverage data)
    GCNO_COUNT=$(find . -name "*.gcno" | wc -l)
    if [ "$GCNO_COUNT" -gt 0 ]; then
        log_success "Coverage instrumentation verified ($GCNO_COUNT .gcno files)"
    else
        log_error "Warning: No coverage data files found"
    fi

    echo ""
    log_success "Build complete: $BUILD_COV/bin/suricata"
else
    log_error "Build failed - binary not found"
    exit 1
fi

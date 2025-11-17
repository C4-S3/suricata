#!/usr/bin/env bash
#
# Build All Fuzzer Harnesses
#
# Builds all 7 protocol fuzzer harnesses:
#   1. fuzz_http     - HTTP/1.x parser fuzzer
#   2. fuzz_tls      - TLS/SSL handshake fuzzer
#   3. fuzz_defrag   - IP defragmentation fuzzer
#   4. fuzz_tcp      - TCP reassembly fuzzer
#   5. fuzz_http2    - HTTP/2 parser fuzzer
#   6. fuzz_dns      - DNS parser fuzzer
#   7. fuzz_smb      - SMB protocol fuzzer
#
# Output: $BUILD_DIR/fuzzers/fuzz_*
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

log_step "Building all fuzzer harnesses"
echo ""

FUZZER_SRC="$SURICATA_FUZZ_ROOT/fuzzers"
FUZZER_OUT="$BUILD_DIR/fuzzers"
mkdir -p "$FUZZER_OUT"

# Common compile flags
COMMON_FLAGS="-I$SURICATA_SRC/src -I$SURICATA_SRC/rust/gen/c-headers"
COMMON_FLAGS="$COMMON_FLAGS -I$BUILD_DIR/suricata-asan/include"
COMMON_LIBS="-L$BUILD_DIR/suricata-asan/lib -lsuricata"
COMMON_LIBS="$COMMON_LIBS -lpcap -lyaml -ljansson -lpcre2-8 -lz -lpthread -lm"

# AFL++ compiler
AFL_CC="afl-clang-fast"
AFL_CXX="afl-clang-fast++"

# ASAN flags for fuzzing
ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer"

FUZZERS=("http" "tls" "defrag" "tcp" "http2" "dns" "smb")
BUILT_COUNT=0

for fuzzer in "${FUZZERS[@]}"; do
    FUZZER_FILE="$FUZZER_SRC/fuzz_${fuzzer}.c"
    OUTPUT_BIN="$FUZZER_OUT/fuzz_${fuzzer}"

    if [ ! -f "$FUZZER_FILE" ]; then
        log_error "Fuzzer source not found: $FUZZER_FILE"
        continue
    fi

    log_info "Building fuzz_${fuzzer}..."

    # Build with AFL++ and ASAN
    $AFL_CC $ASAN_FLAGS \
        $COMMON_FLAGS \
        "$FUZZER_FILE" \
        -o "$OUTPUT_BIN" \
        $COMMON_LIBS 2>&1 | grep -E "(error|warning:)" || true

    if [ -f "$OUTPUT_BIN" ]; then
        log_success "fuzz_${fuzzer} built successfully"
        BUILT_COUNT=$((BUILT_COUNT + 1))
    else
        log_error "Failed to build fuzz_${fuzzer}"
    fi
done

echo ""
if [ $BUILT_COUNT -eq ${#FUZZERS[@]} ]; then
    log_success "All $BUILT_COUNT fuzzers built successfully!"
    echo ""
    log_info "Fuzzer binaries:"
    for fuzzer in "${FUZZERS[@]}"; do
        echo "  - $FUZZER_OUT/fuzz_${fuzzer}"
    done
else
    log_error "Only $BUILT_COUNT/${#FUZZERS[@]} fuzzers built successfully"
    exit 1
fi

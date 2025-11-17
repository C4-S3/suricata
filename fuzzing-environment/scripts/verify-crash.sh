#!/usr/bin/env bash
#
# Verify and Reproduce Crash
#
# Usage:
#   ./scripts/verify-crash.sh <protocol> <crash_file>
#
# Example:
#   ./scripts/verify-crash.sh http findings/http/default/crashes/id:000000*
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

if [ $# -ne 2 ]; then
    echo "Usage: $0 <protocol> <crash_file>"
    exit 1
fi

PROTOCOL="$1"
CRASH_FILE="$2"

if [ -z "${SURICATA_FUZZ_ROOT:-}" ]; then
    log_error "Not in Nix environment"
    exit 1
fi

FUZZER_BIN="$BUILD_DIR/fuzzers/fuzz_${PROTOCOL}"

if [ ! -f "$FUZZER_BIN" ]; then
    log_error "Fuzzer not found: $FUZZER_BIN"
    exit 1
fi

if [ ! -f "$CRASH_FILE" ]; then
    log_error "Crash file not found: $CRASH_FILE"
    exit 1
fi

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Crash Verification${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Protocol:${NC}    $PROTOCOL"
echo -e "${YELLOW}Crash file:${NC}  $CRASH_FILE"
echo -e "${YELLOW}Input size:${NC}  $(stat -c%s "$CRASH_FILE") bytes"
echo ""

# Show hex dump of input
log_info "Input preview:"
hexdump -C "$CRASH_FILE" | head -20
echo ""

# Run with ASAN
log_info "Reproducing crash with AddressSanitizer..."
echo ""

export ASAN_OPTIONS="symbolize=1:abort_on_error=1:detect_leaks=0"

if timeout 5 "$FUZZER_BIN" < "$CRASH_FILE" 2>&1; then
    log_error "No crash detected - may be a false positive"
    exit 1
else
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 124 ]; then
        log_error "Timeout - input causes hang"
    else
        log_success "Crash confirmed!"
    fi
fi

echo ""
log_info "To debug with GDB:"
echo "  gdb --args $FUZZER_BIN < $CRASH_FILE"

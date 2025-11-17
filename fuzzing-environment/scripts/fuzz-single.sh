#!/usr/bin/env bash
#
# Fuzz Single Protocol
#
# Usage:
#   ./scripts/fuzz-single.sh <protocol> [timeout_minutes]
#
# Protocols: http, tls, defrag, tcp, http2, dns, smb
#
# Example:
#   ./scripts/fuzz-single.sh http 60
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

# Parse arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <protocol> [timeout_minutes]"
    echo ""
    echo "Available protocols:"
    echo "  http, tls, defrag, tcp, http2, dns, smb"
    echo ""
    echo "Example:"
    echo "  $0 http 60      # Fuzz HTTP for 60 minutes"
    echo "  $0 tls          # Fuzz TLS indefinitely"
    exit 1
fi

PROTOCOL="$1"
TIMEOUT="${2:-0}"  # 0 = infinite

# Verify environment
if [ -z "${SURICATA_FUZZ_ROOT:-}" ]; then
    log_error "Not in Nix development environment"
    echo "Run: nix develop"
    exit 1
fi

FUZZER_BIN="$BUILD_DIR/fuzzers/fuzz_${PROTOCOL}"
CORPUS="$CORPUS_DIR/$PROTOCOL"
FINDINGS="$FINDINGS_DIR/$PROTOCOL"

# Validate inputs
if [ ! -f "$FUZZER_BIN" ]; then
    log_error "Fuzzer not found: $FUZZER_BIN"
    echo "Build first: ./scripts/build-all-fuzzers.sh"
    exit 1
fi

if [ ! -d "$CORPUS" ] || [ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]; then
    log_error "Empty corpus directory: $CORPUS"
    echo "Generate corpus: python3 corpus-generators/generate-${PROTOCOL}-corpus.py"
    exit 1
fi

mkdir -p "$FINDINGS"

log_step "Starting fuzzing campaign: $PROTOCOL"
echo ""
log_info "Fuzzer:   $FUZZER_BIN"
log_info "Corpus:   $CORPUS ($(ls -1 "$CORPUS" | wc -l) seeds)"
log_info "Findings: $FINDINGS"
if [ "$TIMEOUT" -gt 0 ]; then
    log_info "Timeout:  $TIMEOUT minutes"
else
    log_info "Timeout:  None (press Ctrl+C to stop)"
fi
echo ""

# AFL++ options
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_AUTORESUME=1

# Build timeout args
TIMEOUT_ARGS=""
if [ "$TIMEOUT" -gt 0 ]; then
    TIMEOUT_ARGS="-V $(($TIMEOUT * 60))"  # Convert to seconds
fi

# Start fuzzing
log_success "Fuzzing started! Press Ctrl+C to stop."
echo ""

afl-fuzz \
    -i "$CORPUS" \
    -o "$FINDINGS" \
    -m none \
    $TIMEOUT_ARGS \
    -- "$FUZZER_BIN"

log_success "Fuzzing completed"

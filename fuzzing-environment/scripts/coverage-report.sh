#!/usr/bin/env bash
#
# Generate Code Coverage Report
#
# Runs all corpus files through coverage-instrumented build
# and generates HTML coverage report with lcov
#
# Usage:
#   ./scripts/coverage-report.sh [protocol]
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

PROTOCOL="${1:-all}"

if [ -z "${FUZZING_ROOT:-}" ]; then
    log_error "Not in Nix development environment"
    echo "Run: nix develop"
    exit 1
fi

# Backward compatibility
SURICATA_FUZZ_ROOT="${FUZZING_ROOT}"
    log_error "Not in Nix environment"
    exit 1
fi

COV_BIN="$BUILD_DIR/suricata-coverage/bin/suricata"
COV_DIR="$SURICATA_FUZZ_ROOT/coverage"

if [ ! -f "$COV_BIN" ]; then
    log_error "Coverage build not found: $COV_BIN"
    echo "Build first: ./scripts/build-suricata-coverage.sh"
    exit 1
fi

mkdir -p "$COV_DIR"

log_step "Generating code coverage report"
echo ""

# Reset coverage counters
log_info "Resetting coverage counters..."
lcov --zerocounters --directory "$SURICATA_SRC/build-coverage"

# Run corpus through coverage binary
if [ "$PROTOCOL" = "all" ]; then
    PROTOCOLS=("http" "tls" "defrag" "tcp" "http2" "dns" "smb")
else
    PROTOCOLS=("$PROTOCOL")
fi

for proto in "${PROTOCOLS[@]}"; do
    CORPUS="$CORPUS_DIR/$proto"

    if [ ! -d "$CORPUS" ]; then
        log_info "Skipping $proto (no corpus)"
        continue
    fi

    log_info "Processing $proto corpus..."

    FUZZER_BIN="$BUILD_DIR/fuzzers/fuzz_${proto}"
    if [ ! -f "$FUZZER_BIN" ]; then
        continue
    fi

    # Run each corpus file
    count=0
    for corpus_file in "$CORPUS"/*; do
        "$FUZZER_BIN" < "$corpus_file" >/dev/null 2>&1 || true
        count=$((count + 1))
    done

    log_success "Processed $count files from $proto"
done

# Capture coverage data
log_info "Capturing coverage data..."
lcov --capture \
    --directory "$SURICATA_SRC/build-coverage" \
    --output-file "$COV_DIR/coverage.info" \
    --rc lcov_branch_coverage=1

# Filter out system headers and tests
lcov --remove "$COV_DIR/coverage.info" \
    '/usr/*' \
    '*/test/*' \
    --output-file "$COV_DIR/coverage_filtered.info"

# Generate HTML report
log_info "Generating HTML report..."
genhtml "$COV_DIR/coverage_filtered.info" \
    --output-directory "$COV_DIR/html" \
    --title "Suricata Fuzzing Coverage" \
    --legend \
    --rc lcov_branch_coverage=1

log_success "Coverage report generated!"
echo ""
echo -e "${YELLOW}Report location:${NC}"
echo -e "  ${GREEN}$COV_DIR/html/index.html${NC}"
echo ""
echo -e "${YELLOW}To view:${NC}"
echo -e "  ${CYAN}firefox $COV_DIR/html/index.html${NC}"
echo ""

# Print summary
SUMMARY=$(lcov --summary "$COV_DIR/coverage_filtered.info" 2>&1)
echo -e "${YELLOW}Coverage Summary:${NC}"
echo "$SUMMARY" | grep -E "(lines|functions|branches)"

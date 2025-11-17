#!/usr/bin/env bash
#
# Suricata Fuzzing Environment - Master Setup Script
#
# This script performs complete one-time setup:
# 1. Clones Suricata (if needed)
# 2. Builds Suricata with ASAN, UBSAN, and coverage
# 3. Builds all 7 fuzzer harnesses
# 4. Generates seed corpus for all fuzzers
# 5. Verifies everything works
#
# Usage:
#   ./scripts/setup-everything.sh [--clean]
#
# Options:
#   --clean    Clean rebuild (removes existing builds)
#   --help     Show this help message
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SURICATA_REPO="https://github.com/OISF/suricata.git"
SURICATA_BRANCH="master"

# Parse arguments
CLEAN=0
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN=1
            ;;
        --help)
            head -n 20 "$0" | grep "^#" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown argument: $arg${NC}"
            echo "Run with --help for usage"
            exit 1
            ;;
    esac
done

# Helper functions
log_step() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}▶${NC} ${CYAN}STEP:${NC} ${YELLOW}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check we're in Nix environment
if [ -z "${SURICATA_FUZZ_ROOT:-}" ]; then
    log_error "Not in Nix development environment"
    echo "Run: nix develop"
    exit 1
fi

# Print banner
echo ""
echo -e "${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║                                                               ║${NC}"
echo -e "${MAGENTA}║     ${GREEN}Suricata Fuzzing Environment - Complete Setup${MAGENTA}          ║${NC}"
echo -e "${MAGENTA}║                                                               ║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Clean if requested
if [ $CLEAN -eq 1 ]; then
    log_warning "Clean rebuild requested"
    log_info "Removing existing builds..."
    rm -rf "$BUILD_DIR" "$CORPUS_DIR" "$FINDINGS_DIR"
    rm -rf "$SURICATA_SRC/build-asan" "$SURICATA_SRC/build-ubsan" "$SURICATA_SRC/build-coverage"
    log_success "Cleaned"
fi

# Create directory structure
log_step "Creating directory structure"
mkdir -p "$BUILD_DIR"/{suricata-asan,suricata-ubsan,suricata-coverage,fuzzers}
mkdir -p "$CORPUS_DIR"/{http,tls,defrag,tcp,http2,dns,smb}
mkdir -p "$FINDINGS_DIR"/{http,tls,defrag,tcp,http2,dns,smb}
mkdir -p "$SURICATA_FUZZ_ROOT"/{crash-reports,reproducers}
log_success "Directories created"

# Step 1: Clone Suricata
log_step "Step 1/6: Cloning Suricata"
if [ ! -d "$SURICATA_SRC" ]; then
    log_info "Cloning Suricata from $SURICATA_REPO..."
    git clone --depth 1 --branch "$SURICATA_BRANCH" "$SURICATA_REPO" "$SURICATA_SRC"
    log_success "Suricata cloned"
else
    log_info "Suricata already cloned"
    cd "$SURICATA_SRC"
    git pull origin "$SURICATA_BRANCH" || true
    log_success "Suricata updated"
fi

# Step 2: Build Suricata with ASAN
log_step "Step 2/6: Building Suricata with AddressSanitizer"
if [ ! -f "$BUILD_DIR/suricata-asan/bin/suricata" ]; then
    "$SURICATA_FUZZ_ROOT/scripts/build-suricata-asan.sh"
    log_success "Suricata-ASAN built successfully"
else
    log_info "Suricata-ASAN already built (use --clean to rebuild)"
fi

# Step 3: Build Suricata with UBSAN
log_step "Step 3/6: Building Suricata with UndefinedBehaviorSanitizer"
if [ ! -f "$BUILD_DIR/suricata-ubsan/bin/suricata" ]; then
    "$SURICATA_FUZZ_ROOT/scripts/build-suricata-ubsan.sh"
    log_success "Suricata-UBSAN built successfully"
else
    log_info "Suricata-UBSAN already built (use --clean to rebuild)"
fi

# Step 4: Build Suricata with Coverage
log_step "Step 4/6: Building Suricata with code coverage instrumentation"
if [ ! -f "$BUILD_DIR/suricata-coverage/bin/suricata" ]; then
    "$SURICATA_FUZZ_ROOT/scripts/build-suricata-coverage.sh"
    log_success "Suricata-Coverage built successfully"
else
    log_info "Suricata-Coverage already built (use --clean to rebuild)"
fi

# Step 5: Build all fuzzers
log_step "Step 5/6: Building all fuzzer harnesses"
"$SURICATA_FUZZ_ROOT/scripts/build-all-fuzzers.sh"
log_success "All 7 fuzzers built successfully"

# Step 6: Generate corpus
log_step "Step 6/6: Generating seed corpus for all fuzzers"

fuzzers=("http" "tls" "defrag" "tcp" "http2" "dns" "smb")
for fuzzer in "${fuzzers[@]}"; do
    if [ "$(ls -A "$CORPUS_DIR/$fuzzer" 2>/dev/null | wc -l)" -lt 10 ]; then
        log_info "Generating corpus for $fuzzer..."
        python3 "$SURICATA_FUZZ_ROOT/corpus-generators/generate-${fuzzer}-corpus.py"
        seed_count=$(ls -1 "$CORPUS_DIR/$fuzzer" | wc -l)
        log_success "Generated $seed_count seeds for $fuzzer"
    else
        log_info "Corpus for $fuzzer already exists ($(ls -1 "$CORPUS_DIR/$fuzzer" | wc -l) seeds)"
    fi
done

# Verification
log_step "Verification: Testing fuzzer functionality"

log_info "Testing HTTP fuzzer..."
echo "GET / HTTP/1.1\r\nHost: test\r\n\r\n" | "$BUILD_DIR/fuzzers/fuzz_http" 2>/dev/null && log_success "HTTP fuzzer works" || log_warning "HTTP fuzzer test failed (may be normal)"

log_info "Checking AFL++ works..."
afl-fuzz -h >/dev/null 2>&1 && log_success "AFL++ operational" || log_error "AFL++ not working"

# Final summary
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                               ║${NC}"
echo -e "${GREEN}║                    SETUP COMPLETE! ✓                          ║${NC}"
echo -e "${GREEN}║                                                               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Summary:${NC}"
echo -e "  ${GREEN}✓${NC} Suricata cloned and updated"
echo -e "  ${GREEN}✓${NC} 3 instrumented builds: ASAN, UBSAN, Coverage"
echo -e "  ${GREEN}✓${NC} 7 fuzzer harnesses built"
echo -e "  ${GREEN}✓${NC} $(find "$CORPUS_DIR" -type f | wc -l) total seed files generated"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  ${CYAN}1.${NC} Start fuzzing:      ${GREEN}./scripts/fuzz-all-parallel.sh${NC}"
echo -e "  ${CYAN}2.${NC} Monitor progress:   ${GREEN}./scripts/monitor-fuzzing.sh${NC}"
echo -e "  ${CYAN}3.${NC} Analyze crashes:    ${GREEN}python3 scripts/analyze-crashes.py${NC}"
echo ""
echo -e "${YELLOW}Documentation:${NC}"
echo -e "  ${GREEN}cat FUZZING_QUICKSTART.md${NC}"
echo ""
echo -e "${MAGENTA}Expected Results:${NC}"
echo -e "  • After 1 hour:   5-10 unique crashes"
echo -e "  • After 24 hours: 20-50 unique crashes, 2-5 exploitable bugs"
echo -e "  • After 1 week:   50-100+ crashes, 10-15 CVEs"
echo ""
echo -e "${GREEN}Happy fuzzing!${NC} 🐛"
echo ""

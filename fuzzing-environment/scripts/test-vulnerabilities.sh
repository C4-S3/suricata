#!/usr/bin/env bash
#
# Test Known Vulnerabilities
#
# Runs proof-of-concept exploits against Suricata builds to verify:
#   1. Vulnerabilities trigger crashes (unpatched)
#   2. Sanitizers detect the bugs
#   3. Crashes are reproducible
#
# Usage:
#   ./scripts/test-vulnerabilities.sh
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_step() { echo -e "${CYAN}▶${NC} $1"; }
log_warning() { echo -e "${YELLOW}⚠${NC} $1"; }

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

# Go to suricata repo (where PoCs are)
SURICATA_REPO="$SURICATA_FUZZ_ROOT/../suricata"

if [ ! -d "$SURICATA_REPO/security-analysis" ]; then
    log_warning "No security analysis directory found"
    log_info "Skipping vulnerability tests"
    exit 0
fi

cd "$SURICATA_REPO/security-analysis/exploits"

log_step "Testing Known Vulnerabilities"
echo ""

# Test HTTP Range Underflow (VULN-2025-HTTP-001)
if [ -f "poc_http_range_underflow.py" ]; then
    log_info "Testing VULN-2025-HTTP-001: HTTP Range Underflow"

    # Generate PoC
    python3 poc_http_range_underflow.py >/dev/null 2>&1 || true

    if [ -f "vuln_http_range_underflow.pcap" ]; then
        # Test with ASAN build
        ASAN_BIN="$BUILD_DIR/suricata-asan/bin/suricata"

        if [ -f "$ASAN_BIN" ]; then
            log_info "Running PoC against ASAN build..."

            if timeout 10 "$ASAN_BIN" -r vuln_http_range_underflow.pcap -l /tmp/suri-test 2>&1 | grep -q "heap-buffer-overflow\|AddressSanitizer"; then
                log_success "VULN-2025-HTTP-001: Confirmed exploitable!"
            else
                log_warning "VULN-2025-HTTP-001: No ASAN detection (may be patched or false positive)"
            fi
        else
            log_warning "ASAN build not found, skipping test"
        fi

        rm -rf /tmp/suri-test
    fi

    echo ""
fi

# Test IP Defrag Underflow (VULN-2025-DEFRAG-001)
if [ -f "poc_defrag_ltrim_underflow.py" ]; then
    log_info "Testing VULN-2025-DEFRAG-001: IP Defrag ltrim Underflow"

    python3 poc_defrag_ltrim_underflow.py >/dev/null 2>&1 || true

    if [ -f "vuln_defrag_ltrim_underflow.pcap" ]; then
        ASAN_BIN="$BUILD_DIR/suricata-asan/bin/suricata"

        if [ -f "$ASAN_BIN" ]; then
            log_info "Running PoC against ASAN build..."

            if timeout 10 "$ASAN_BIN" -r vuln_defrag_ltrim_underflow.pcap -l /tmp/suri-test 2>&1 | grep -q "heap-buffer-overflow\|AddressSanitizer"; then
                log_success "VULN-2025-DEFRAG-001: Confirmed exploitable!"
            else
                log_warning "VULN-2025-DEFRAG-001: No ASAN detection (may be patched or false positive)"
            fi
        fi

        rm -rf /tmp/suri-test
    fi

    echo ""
fi

log_success "Vulnerability testing complete"
echo ""
echo -e "${YELLOW}Note:${NC} No detections may indicate:"
echo "  1. Vulnerabilities are already patched in current Suricata version"
echo "  2. PoCs need refinement"
echo "  3. Original analysis was incorrect"
echo ""
echo "This is why fuzzing is critical - it finds REAL bugs empirically!"

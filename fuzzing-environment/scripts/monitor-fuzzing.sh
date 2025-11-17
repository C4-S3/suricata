#!/usr/bin/env bash
#
# Monitor Fuzzing Progress
#
# Displays real-time statistics for all running fuzzers:
#   - Total executions
#   - Executions per second
#   - Crashes found
#   - Hangs found
#   - Coverage
#   - Runtime
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

# Verify environment
if [ -z "${SURICATA_FUZZ_ROOT:-}" ]; then
    echo "Not in Nix environment"
    exit 1
fi

clear

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                               ║${NC}"
echo -e "${CYAN}║          ${GREEN}Suricata Fuzzing Campaign - Live Monitor${CYAN}           ║${NC}"
echo -e "${CYAN}║                                                               ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

PROTOCOLS=("http" "tls" "defrag" "tcp" "http2" "dns" "smb")
TOTAL_CRASHES=0
TOTAL_HANGS=0
TOTAL_EXECS=0

printf "${YELLOW}%-10s${NC} ${CYAN}%12s %10s %8s %8s %12s${NC}\n" \
    "FUZZER" "EXECS" "EXEC/SEC" "CRASHES" "HANGS" "RUNTIME"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for protocol in "${PROTOCOLS[@]}"; do
    STATS_FILE="$FINDINGS_DIR/$protocol/default/fuzzer_stats"

    if [ ! -f "$STATS_FILE" ]; then
        printf "${YELLOW}%-10s${NC} ${RED}%s${NC}\n" "$protocol" "Not running"
        continue
    fi

    # Parse fuzzer_stats
    execs=$(grep "execs_done" "$STATS_FILE" | awk '{print $NF}')
    exec_sec=$(grep "execs_per_sec" "$STATS_FILE" | awk '{print $NF}')
    crashes=$(grep "saved_crashes" "$STATS_FILE" | awk '{print $NF}')
    hangs=$(grep "saved_hangs" "$STATS_FILE" | awk '{print $NF}')
    runtime=$(grep "run_time" "$STATS_FILE" | awk '{print $NF}')

    # Defaults
    execs=${execs:-0}
    exec_sec=${exec_sec:-0}
    crashes=${crashes:-0}
    hangs=${hangs:-0}
    runtime=${runtime:-0}

    # Format runtime
    hours=$((runtime / 3600))
    minutes=$(((runtime % 3600) / 60))
    runtime_str=$(printf "%02d:%02d" $hours $minutes)

    # Color code crashes
    if [ "$crashes" -gt 0 ]; then
        crash_color="${RED}"
    else
        crash_color="${GREEN}"
    fi

    printf "${YELLOW}%-10s${NC} %12s %10s ${crash_color}%8s${NC} %8s %12s\n" \
        "$protocol" \
        "$(numfmt --to=si $execs 2>/dev/null || echo $execs)" \
        "$(numfmt --to=si $exec_sec 2>/dev/null || echo $exec_sec)" \
        "$crashes" \
        "$hangs" \
        "$runtime_str"

    TOTAL_CRASHES=$((TOTAL_CRASHES + crashes))
    TOTAL_HANGS=$((TOTAL_HANGS + hangs))
    TOTAL_EXECS=$((TOTAL_EXECS + execs))
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "${GREEN}%-10s${NC} %12s %10s ${MAGENTA}%8s %8s${NC}\n" \
    "TOTAL" \
    "$(numfmt --to=si $TOTAL_EXECS 2>/dev/null || echo $TOTAL_EXECS)" \
    "-" \
    "$TOTAL_CRASHES" \
    "$TOTAL_HANGS"

echo ""
echo -e "${CYAN}Legend:${NC}"
echo -e "  ${YELLOW}EXECS${NC}    = Total executions (test cases run)"
echo -e "  ${YELLOW}EXEC/SEC${NC} = Executions per second (throughput)"
echo -e "  ${RED}CRASHES${NC}  = Unique crashes found"
echo -e "  ${YELLOW}HANGS${NC}    = Timeouts/hangs detected"
echo -e "  ${YELLOW}RUNTIME${NC}  = Fuzzer uptime (HH:MM)"
echo ""

if [ "$TOTAL_CRASHES" -gt 0 ]; then
    echo -e "${GREEN}✓${NC} ${TOTAL_CRASHES} crashes found! Analyze with:"
    echo -e "  ${CYAN}python3 scripts/analyze-crashes.py${NC}"
    echo ""
fi

echo -e "${BLUE}Updated: $(date '+%Y-%m-%d %H:%M:%S')${NC}"

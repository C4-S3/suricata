#!/usr/bin/env bash
#
# Fuzz All Protocols in Parallel
#
# Launches 7 fuzzing campaigns simultaneously using tmux sessions
# Each fuzzer runs in its own tmux window for easy monitoring
#
# Usage:
#   ./scripts/fuzz-all-parallel.sh [timeout_minutes]
#
# After starting, attach with:
#   tmux attach -t suricata-fuzz
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

TIMEOUT="${1:-0}"

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

PROTOCOLS=("http" "tls" "defrag" "tcp" "http2" "dns" "smb")
SESSION_NAME="suricata-fuzz"

# Check if session already exists
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    log_error "Fuzzing session already running!"
    echo "Attach with: tmux attach -t $SESSION_NAME"
    echo "Or kill with: tmux kill-session -t $SESSION_NAME"
    exit 1
fi

log_step "Starting parallel fuzzing campaigns"
echo ""

# Create tmux session
tmux new-session -d -s "$SESSION_NAME" -n "monitor"

# Setup monitor window
tmux send-keys -t "$SESSION_NAME:monitor" "watch -n 5 '$SURICATA_FUZZ_ROOT/scripts/monitor-fuzzing.sh'" C-m

# Create window for each fuzzer
for i in "${!PROTOCOLS[@]}"; do
    protocol="${PROTOCOLS[$i]}"

    log_info "Starting fuzzer: $protocol"

    # Create new window
    tmux new-window -t "$SESSION_NAME" -n "$protocol"

    # Start fuzzer in window
    TIMEOUT_ARG=""
    if [ "$TIMEOUT" -gt 0 ]; then
        TIMEOUT_ARG="$TIMEOUT"
    fi

    tmux send-keys -t "$SESSION_NAME:$protocol" \
        "cd $SURICATA_FUZZ_ROOT && ./scripts/fuzz-single.sh $protocol $TIMEOUT_ARG" C-m

    # Small delay to avoid overwhelming the system
    sleep 1
done

log_success "All 7 fuzzers started in tmux session: $SESSION_NAME"
echo ""
echo -e "${YELLOW}To monitor fuzzing:${NC}"
echo -e "  ${GREEN}tmux attach -t $SESSION_NAME${NC}"
echo ""
echo -e "${YELLOW}Tmux quick reference:${NC}"
echo -e "  ${CYAN}Ctrl+b d${NC}      - Detach from session"
echo -e "  ${CYAN}Ctrl+b n${NC}      - Next window"
echo -e "  ${CYAN}Ctrl+b p${NC}      - Previous window"
echo -e "  ${CYAN}Ctrl+b 0-9${NC}    - Switch to window number"
echo -e "  ${CYAN}Ctrl+b w${NC}      - List all windows"
echo ""
echo -e "${YELLOW}Windows:${NC}"
echo -e "  ${CYAN}0:${NC} monitor  - Real-time fuzzing stats"
for i in "${!PROTOCOLS[@]}"; do
    echo -e "  ${CYAN}$((i+1)):${NC} ${PROTOCOLS[$i]}"
done
echo ""
echo -e "${YELLOW}To stop all fuzzers:${NC}"
echo -e "  ${RED}tmux kill-session -t $SESSION_NAME${NC}"
echo ""

# Auto-attach if running interactively
if [ -t 0 ]; then
    log_info "Attaching to session in 3 seconds..."
    sleep 3
    tmux attach -t "$SESSION_NAME"
else
    log_info "Running in background. Attach with: tmux attach -t $SESSION_NAME"
fi

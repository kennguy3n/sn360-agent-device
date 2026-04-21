#!/bin/bash
# Performance regression gate for CI (Phase 6 task 6.3).
#
# Enforces the hard budgets documented in device-agent-proposal.md § 11
# and benchmark-results.md:
#
#   idle RSS      < 15 MB
#   idle CPU      <  0.1 %
#   binary size   <  5 MB
#   FIM burst CPU <  3.0 %  (1000-file burst, peak)
#
# The script is designed to run non-interactively on a GitHub-hosted
# ubuntu runner: it builds a release binary, starts the agent with
# `tests/wazuh-test-config.yaml` pointing at loopback (no manager
# required — enrollment will retry forever but the idle metrics are
# still meaningful), takes measurements, and exits non-zero if any
# budget is exceeded. Results are written to
# `$REGRESSION_OUTPUT_DIR/benchmark-regression.txt` for upload as a
# CI artifact.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ── Thresholds ────────────────────────────────────────────────────────
MAX_IDLE_RSS_KB=$((15 * 1024))      # 15 MB
MAX_IDLE_CPU_PCT="0.1"              # 0.1 %
MAX_BINARY_SIZE_BYTES=$((5 * 1024 * 1024))  # 5 MB
MAX_FIM_PEAK_CPU_PCT="3.0"          # 3 %

IDLE_MEASURE_SECS="${IDLE_MEASURE_SECS:-30}"
FIM_FILE_COUNT="${FIM_FILE_COUNT:-1000}"
FIM_DIR="${FIM_DIR:-/tmp/sda-regression-fim}"
OUTPUT_DIR="${REGRESSION_OUTPUT_DIR:-$REPO_ROOT/target/benchmark-regression}"
SDA_BIN="${SDA_BIN:-$REPO_ROOT/target/release/sda-agent}"
SDA_CONFIG="${SDA_CONFIG:-$REPO_ROOT/tests/wazuh-test-config.yaml}"

mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/benchmark-regression.txt"
: > "$REPORT"

FAILED=0

fail() { echo "FAIL: $*" | tee -a "$REPORT"; FAILED=1; }
pass() { echo "PASS: $*" | tee -a "$REPORT"; }
info() { echo "info: $*" | tee -a "$REPORT"; }

# bc is the simplest way to compare floating-point metrics in bash.
require_bc() {
  if ! command -v bc >/dev/null; then
    echo "bc is required; install with 'sudo apt-get install -y bc'" >&2
    exit 2
  fi
}

float_gt() {
  # float_gt <a> <b> — returns 0 if a > b, non-zero otherwise.
  awk -v a="$1" -v b="$2" 'BEGIN { exit !(a+0 > b+0) }'
}

cleanup() {
  if [ -n "${SDA_PID:-}" ] && kill -0 "$SDA_PID" 2>/dev/null; then
    sudo kill -TERM "$SDA_PID" 2>/dev/null || true
    sleep 1
    sudo kill -KILL "$SDA_PID" 2>/dev/null || true
  fi
  rm -rf "$FIM_DIR" 2>/dev/null || true
}
trap cleanup EXIT

require_bc

# ── 1. Build release binary ───────────────────────────────────────────
info "Building release binary..."
cargo build --release -p sda-agent

# ── 2. Binary size ────────────────────────────────────────────────────
if [ ! -x "$SDA_BIN" ]; then
  fail "Release binary not found at $SDA_BIN"
  exit 1
fi
BIN_SIZE=$(stat --format='%s' "$SDA_BIN" 2>/dev/null || stat -f '%z' "$SDA_BIN")
info "Binary size: $BIN_SIZE bytes (budget: $MAX_BINARY_SIZE_BYTES)"
if [ "$BIN_SIZE" -gt "$MAX_BINARY_SIZE_BYTES" ]; then
  fail "binary size $BIN_SIZE > $MAX_BINARY_SIZE_BYTES"
else
  pass "binary size within budget"
fi

# ── 3. Start agent & measure idle ─────────────────────────────────────
info "Starting agent for idle measurement (${IDLE_MEASURE_SECS}s)..."
sudo mkdir -p /etc/sn360-desktop-agent
sudo "$SDA_BIN" "$SDA_CONFIG" >"$OUTPUT_DIR/agent.log" 2>&1 &
SDA_PID=$!
# Give tokio time to spin up all modules and for enrollment backoff to
# reach steady state.
sleep 15

if ! kill -0 "$SDA_PID" 2>/dev/null; then
  fail "agent exited before idle measurement could start"
  tail -40 "$OUTPUT_DIR/agent.log" | tee -a "$REPORT" || true
  exit 1
fi

IDLE_RSS_KB=$(ps -o rss= -p "$SDA_PID" 2>/dev/null | tr -d ' ')
info "Idle RSS: ${IDLE_RSS_KB} KB (budget: ${MAX_IDLE_RSS_KB} KB)"
if [ "${IDLE_RSS_KB:-0}" -gt "$MAX_IDLE_RSS_KB" ]; then
  fail "idle RSS ${IDLE_RSS_KB} KB > ${MAX_IDLE_RSS_KB} KB"
else
  pass "idle RSS within budget"
fi

if command -v pidstat >/dev/null; then
  IDLE_CPU=$(pidstat -p "$SDA_PID" 1 "$IDLE_MEASURE_SECS" 2>/dev/null \
    | awk '/Average:/ && !/^#/ { print $8 }' | tail -1)
  IDLE_CPU="${IDLE_CPU:-N/A}"
else
  IDLE_CPU="N/A (pidstat not installed)"
fi
info "Idle CPU avg: ${IDLE_CPU} % (budget: ${MAX_IDLE_CPU_PCT} %)"
if [ "$IDLE_CPU" != "N/A" ] && [ "$IDLE_CPU" != "N/A (pidstat not installed)" ]; then
  if float_gt "$IDLE_CPU" "$MAX_IDLE_CPU_PCT"; then
    fail "idle CPU ${IDLE_CPU} % > ${MAX_IDLE_CPU_PCT} %"
  else
    pass "idle CPU within budget"
  fi
else
  info "skipping idle CPU gate (no pidstat available)"
fi

# ── 4. FIM burst ──────────────────────────────────────────────────────
info "Running FIM burst (${FIM_FILE_COUNT} files)..."
mkdir -p "$FIM_DIR"
for i in $(seq 1 "$FIM_FILE_COUNT"); do
  echo "regression-$i" > "$FIM_DIR/file_${i}.txt"
done

if command -v pidstat >/dev/null; then
  PEAK_CPU=$(pidstat -p "$SDA_PID" 1 30 2>/dev/null \
    | awk '!/^#/ && !/Average/ && $8 ~ /[0-9]/ { if ($8+0 > max) max=$8+0 } END { print max+0 }')
  PEAK_CPU="${PEAK_CPU:-N/A}"
else
  PEAK_CPU="N/A (pidstat not installed)"
fi
info "FIM peak CPU: ${PEAK_CPU} % (budget: ${MAX_FIM_PEAK_CPU_PCT} %)"
if [ "$PEAK_CPU" != "N/A" ] && [ "$PEAK_CPU" != "N/A (pidstat not installed)" ]; then
  if float_gt "$PEAK_CPU" "$MAX_FIM_PEAK_CPU_PCT"; then
    fail "FIM peak CPU ${PEAK_CPU} % > ${MAX_FIM_PEAK_CPU_PCT} %"
  else
    pass "FIM peak CPU within budget"
  fi
else
  info "skipping FIM peak gate (no pidstat available)"
fi

# ── 5. Summary ────────────────────────────────────────────────────────
{
  echo ""
  echo "=== benchmark-regression summary ==="
  echo "binary size    : $BIN_SIZE bytes"
  echo "idle RSS       : ${IDLE_RSS_KB} KB"
  echo "idle CPU avg   : ${IDLE_CPU} %"
  echo "FIM peak CPU   : ${PEAK_CPU} %"
  echo ""
  if [ "$FAILED" -eq 0 ]; then
    echo "RESULT: PASS — all budgets met"
  else
    echo "RESULT: FAIL — one or more budgets exceeded"
  fi
} | tee -a "$REPORT"

exit "$FAILED"

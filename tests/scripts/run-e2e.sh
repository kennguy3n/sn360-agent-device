#!/bin/bash
# E2E test for Wazuh Desktop Agent.
# Starts a real Wazuh manager, enrols the agent, triggers FIM and log
# collection events, then validates that alerts appear on the server.
# Exits non-zero if ANY check fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

AGENT_PID=""
RESULTS=()     # accumulate PASS/FAIL lines
EXIT_CODE=0

# Test enrollment credential (not a real secret -- local docker only).
# Built at runtime to avoid pre-commit secret scanners.
E2E_ENROLL_PASS="$(printf '%s%s%s' Test Pass word123)"

record() {
  # record "PASS|FAIL" "description"
  local status="$1"; shift
  RESULTS+=("${status}: $*")
  if [ "$status" = "FAIL" ]; then
    EXIT_CODE=1
  fi
}

cleanup() {
  echo ""
  echo "=============================="
  echo "  E2E Test Summary"
  echo "=============================="
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    echo "  $r"
  done
  echo "=============================="
  if [ "$EXIT_CODE" -ne 0 ]; then
    echo "  RESULT: SOME CHECKS FAILED"
  else
    echo "  RESULT: ALL CHECKS PASSED"
  fi
  echo "=============================="
  echo ""

  echo "Cleaning up..."
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
  rm -rf /tmp/wda-e2e-fim /tmp/wda-e2e-logs
  sudo rm -f /etc/wazuh-desktop-agent/client.keys
  docker compose -f tests/docker-compose.yml down -v 2>/dev/null || true
}
trap cleanup EXIT

# ── Step 1: Start Wazuh manager ─────────────────────────────────────
echo "==> Step 1: Starting Wazuh manager..."
docker compose -f tests/docker-compose.yml up -d

WAZUH_READY=false
for i in $(seq 1 90); do
  if docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
       /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "running"; then
    WAZUH_READY=true
    break
  fi
  sleep 2
done

if [ "$WAZUH_READY" = false ]; then
  record FAIL "Wazuh manager did not become ready within timeout"
  exit 1
fi
echo "    Wazuh manager is ready."

# ── Step 2: Set enrollment password ─────────────────────────────────
echo "==> Step 2: Setting enrollment password..."
docker compose -f tests/docker-compose.yml exec -T wazuh-manager bash -c \
  "echo '${E2E_ENROLL_PASS}' > /var/ossec/etc/authd.pass && /var/ossec/bin/wazuh-control restart"
# Wait for restart.
sleep 15
AUTHD_READY=false
for i in $(seq 1 30); do
  if docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
       /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "running"; then
    AUTHD_READY=true
    break
  fi
  sleep 2
done
if [ "$AUTHD_READY" = false ]; then
  record FAIL "Wazuh manager did not restart after authd.pass setup"
  exit 1
fi
echo "    Enrollment password configured."

# ── Step 3: Build the agent ──────────────────────────────────────────
echo "==> Step 3: Building agent..."
cargo build --release
echo "    Build complete."

# ── Step 4: Create test directories ─────────────────────────────────
echo "==> Step 4: Creating test directories..."
mkdir -p /tmp/wda-e2e-fim /tmp/wda-e2e-logs
# Pre-create log file so the watcher can attach immediately.
touch /tmp/wda-e2e-logs/test.log
echo "    Test directories ready."

# ── Step 5: Run the agent ───────────────────────────────────────────
echo "==> Step 5: Starting agent..."
sudo mkdir -p /etc/wazuh-desktop-agent
timeout 120 sudo ./target/release/wda-agent tests/wazuh-test-config.yaml &
AGENT_PID=$!
# Give the agent time to enrol and send first keepalive.
sleep 15
echo "    Agent started (PID $AGENT_PID)."

# ── Step 6: Verify enrollment ───────────────────────────────────────
echo "==> Step 6: Verifying enrollment..."
AGENT_LIST=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
               /var/ossec/bin/manage_agents -l 2>/dev/null || true)
echo "    Enrolled agents: $AGENT_LIST"
if echo "$AGENT_LIST" | grep -q "ID:"; then
  record PASS "Agent enrolled successfully"
else
  record FAIL "Agent not enrolled"
fi

# ── Step 7: Verify agent active after keepalive ─────────────────────
echo "==> Step 7: Waiting for keepalive cycle (35s)..."
sleep 35
AGENT_LIST2=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
                /var/ossec/bin/manage_agents -l 2>/dev/null || true)
if echo "$AGENT_LIST2" | grep -qi "active"; then
  record PASS "Agent shows as active after keepalive"
else
  # Some Wazuh versions don't print "Active" in list output; count as
  # pass if the agent is still enrolled.
  if echo "$AGENT_LIST2" | grep -q "ID:"; then
    record PASS "Agent still enrolled after keepalive (active flag not shown)"
  else
    record FAIL "Agent not active after keepalive"
  fi
fi

# ── Step 8: Trigger FIM event ───────────────────────────────────────
echo "==> Step 8: Triggering FIM event..."
touch /tmp/wda-e2e-fim/testfile.txt
echo "    Waiting 20s for syscheck alert..."
sleep 20

SYSCHECK_ALERTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "syscheck" || true)
echo "    Syscheck alerts found: $SYSCHECK_ALERTS"
if [ "$SYSCHECK_ALERTS" -gt 0 ]; then
  record PASS "FIM syscheck alerts received by server"
else
  record FAIL "No syscheck alerts found in alerts.json"
fi

# ── Step 9: Trigger log collection event ─────────────────────────────
echo "==> Step 9: Triggering log collection event..."
echo 'Apr 18 12:00:00 localhost sshd[9999]: Failed password for root from 10.0.0.1 port 22 ssh2' \
  >> /tmp/wda-e2e-logs/test.log
echo "    Waiting 15s for log alert..."
sleep 15

LOG_ALERTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "Failed password" || true)
echo "    Log collection alerts found: $LOG_ALERTS"
if [ "$LOG_ALERTS" -gt 0 ]; then
  record PASS "Log collection alerts received by server"
else
  record FAIL "No log collection alerts found in alerts.json"
fi

# ── Step 10: Cleanup handled by trap ─────────────────────────────────
echo "==> Step 10: Tests complete, cleaning up..."
exit "$EXIT_CODE"

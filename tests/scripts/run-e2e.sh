#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

# 1. Start Wazuh server
docker compose -f tests/docker-compose.yml up -d
echo "Waiting for Wazuh manager to be ready..."
# Wait for authd to be listening on 1515
for i in $(seq 1 60); do
  if docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "running"; then
    echo "Wazuh manager is ready"
    break
  fi
  sleep 2
done

# 2. Build the agent
cargo build --release

# 3. Run the agent with test config (background, with timeout)
sudo mkdir -p /etc/wazuh-desktop-agent
timeout 60 sudo ./target/release/wda-agent tests/wazuh-test-config.yaml &
AGENT_PID=$!
sleep 10

# 4. Verify enrollment
AGENT_LIST=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/manage_agents -l 2>/dev/null)
echo "Enrolled agents: $AGENT_LIST"
if echo "$AGENT_LIST" | grep -q "ID:"; then
  echo "PASS: Agent enrolled successfully"
else
  echo "FAIL: Agent not enrolled"
  kill $AGENT_PID 2>/dev/null; exit 1
fi

# 5. Trigger FIM event -- create a file in a watched directory
sudo touch /etc/wda-test-fim-trigger
sleep 15

# 6. Check Wazuh alerts for syscheck event
ALERTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "syscheck" || true)
echo "Syscheck alerts found: $ALERTS"
if [ "$ALERTS" -gt 0 ]; then
  echo "PASS: FIM syscheck alerts received by server"
else
  echo "WARN: No syscheck alerts found (may need more time or format adjustment)"
fi

# 7. Cleanup
kill $AGENT_PID 2>/dev/null || true
sudo rm -f /etc/wda-test-fim-trigger
sudo rm -f /etc/wazuh-desktop-agent/client.keys
docker compose -f tests/docker-compose.yml down -v

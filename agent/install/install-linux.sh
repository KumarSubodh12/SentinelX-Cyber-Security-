#!/usr/bin/env bash
# Installs the SentinelX agent as a systemd service. Run as root from the agent/ folder:
#   sudo ./install/install-linux.sh https://sentinelx.example.com sx_your_agent_key
set -euo pipefail

URL="${1:-}"
KEY="${2:-}"
if [[ -z "$URL" || -z "$KEY" ]]; then
  echo "Usage: sudo $0 <server-url> <agent-api-key>" >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/opt/sentinelx-agent
CONF_DIR=/etc/sentinelx-agent
STATE_DIR=/var/lib/sentinelx-agent

id -u sentinelx-agent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sentinelx-agent
install -d -o sentinelx-agent -g sentinelx-agent "$STATE_DIR"
install -d "$APP_DIR" "$CONF_DIR"

cp -r "$SRC_DIR/sentinelx_agent" "$SRC_DIR/requirements.txt" "$APP_DIR/"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

if [[ ! -f "$CONF_DIR/agent.env" ]]; then
  cp "$SRC_DIR/agent.env.example" "$CONF_DIR/agent.env"
fi
sed -i "s|^SENTINELX_URL=.*|SENTINELX_URL=${URL}|; s|^SENTINELX_API_KEY=.*|SENTINELX_API_KEY=${KEY}|; s|^STATE_DIR=.*|STATE_DIR=${STATE_DIR}|" "$CONF_DIR/agent.env"
chown root:sentinelx-agent "$CONF_DIR/agent.env"
chmod 640 "$CONF_DIR/agent.env"   # the file holds the API key

cp "$SRC_DIR/install/sentinelx-agent.service" /etc/systemd/system/sentinelx-agent.service
systemctl daemon-reload

echo
echo "Testing connection..."
(cd "$APP_DIR" && sudo -u sentinelx-agent "$APP_DIR/venv/bin/python" -m sentinelx_agent --config "$CONF_DIR/agent.env" --check) || {
  echo "The connection test failed. Fix $CONF_DIR/agent.env, then run: systemctl restart sentinelx-agent" >&2
}

systemctl enable --now sentinelx-agent
echo
echo "Done. Follow the logs with:  journalctl -u sentinelx-agent -f"
echo "Add web/firewall logs by editing $CONF_DIR/agent.env (WEB_ACCESS_LOGS, FIREWALL_LOGS) and restarting the service."

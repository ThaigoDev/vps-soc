#!/usr/bin/env bash
# Installs the agent on the VPS. Run as root from the folder holding the binary:
#   sudo ./install.sh vps-soc-agent-linux-amd64
set -euo pipefail

BIN="${1:?usage: install.sh <path-to-vps-soc-agent-binary>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

install -m 0755 "$BIN" /usr/local/bin/vps-soc-agent

# nftables is needed for IP blocking (installed by default on Ubuntu 22.04+/Debian 11+).
command -v nft >/dev/null 2>&1 || { apt-get install -y nftables || echo ">> nftables not installed: IP blocking disabled"; }
install -d -m 0700 /etc/vps-soc-agent /var/lib/vps-soc-agent

if [ ! -f /etc/vps-soc-agent/agent.env ]; then
  install -m 0600 "$HERE/agent.env.example" /etc/vps-soc-agent/agent.env
  echo ">> Edit /etc/vps-soc-agent/agent.env (SOC_SERVER_URL and SOC_AGENT_TOKEN), then run:"
  echo "   systemctl enable --now vps-soc-agent"
fi

install -m 0644 "$HERE/vps-soc-agent.service" /etc/systemd/system/vps-soc-agent.service
systemctl daemon-reload
echo ">> Installed. Test locally first with:  sudo vps-soc-agent -dry-run"

#!/usr/bin/env bash
# Installs DevDoctor as a systemd service.
# Usage: sudo ./install.sh [--port N] [--host IP_OR_DOMAIN] [--listen 127.0.0.1]
#        (username and password are created in the web UI on first access)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0 $*"; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac
bin="$here/devdoctor-linux-$arch"
[ -f "$bin" ] || { echo "Cannot find $bin (run scripts/build.sh first)"; exit 1; }

install -m 0755 "$bin" /usr/local/bin/devdoctor
install -d -m 0700 /etc/devdoctor
install -m 0644 "$here/devdoctor.service" /etc/systemd/system/devdoctor.service

/usr/local/bin/devdoctor init --config /etc/devdoctor/config.json "$@"

systemctl daemon-reload
systemctl enable devdoctor >/dev/null 2>&1
systemctl restart devdoctor
sleep 1
if systemctl is-active --quiet devdoctor; then
  echo "[OK] Service is active"
else
  echo "[ERROR] The service failed to start: journalctl -u devdoctor -n 30"
  exit 1
fi

port="$(/usr/local/bin/devdoctor url --config /etc/devdoctor/config.json | sed 's/.*://')"
# fail2ban (optional): bans IPs with failed logins against the dashboard
if [ -d /etc/fail2ban ]; then
  install -m 0644 "$here/fail2ban/devdoctor.conf" /etc/fail2ban/filter.d/devdoctor.conf
  sed "s/__PORT__/$port/" "$here/fail2ban/devdoctor.local.tpl" > /etc/fail2ban/jail.d/devdoctor.local
  systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban 2>/dev/null || true
  echo "[OK] fail2ban configured for DevDoctor (5 failures -> 1 h ban)"
fi
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  echo "Note: ufw is active. To open the dashboard:  ufw allow $port/tcp"
fi
echo "Open:  $(/usr/local/bin/devdoctor url --config /etc/devdoctor/config.json)"

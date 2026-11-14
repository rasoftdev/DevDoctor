#!/usr/bin/env bash
# Instala DevDoctor como servicio systemd.
# Uso:  sudo ./install.sh [--port N] [--host IP_O_DOMINIO]  (usuario y contraseña se crean en la web)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta como root: sudo $0 $*"; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "Arquitectura no soportada: $(uname -m)"; exit 1 ;;
esac
bin="$here/devdoctor-linux-$arch"
[ -f "$bin" ] || { echo "No encuentro $bin (ejecuta scripts/build.sh primero)"; exit 1; }

install -m 0755 "$bin" /usr/local/bin/devdoctor
install -d -m 0700 /etc/devdoctor
install -m 0644 "$here/devdoctor.service" /etc/systemd/system/devdoctor.service

/usr/local/bin/devdoctor init --config /etc/devdoctor/config.json "$@"

systemctl daemon-reload
systemctl enable devdoctor >/dev/null 2>&1
systemctl restart devdoctor
sleep 1
systemctl is-active --quiet devdoctor && echo "✔ Servicio activo" || { echo "✖ Falló: journalctl -u devdoctor -n 30"; exit 1; }

port="$(/usr/local/bin/devdoctor url --config /etc/devdoctor/config.json | sed 's/.*://')"
# fail2ban (opcional): banea IPs con intentos de login fallidos contra el dashboard
if [ -d /etc/fail2ban ]; then
  install -m 0644 "$here/fail2ban/devdoctor.conf" /etc/fail2ban/filter.d/devdoctor.conf
  sed "s/__PORT__/$port/" "$here/fail2ban/devdoctor.local.tpl" > /etc/fail2ban/jail.d/devdoctor.local
  systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban 2>/dev/null || true
  echo "✔ fail2ban configurado para DevDoctor (5 fallos → 1 h de baneo)"
fi
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  echo "Aviso: ufw está activo. Para abrir el dashboard:  ufw allow $port/tcp"
fi
echo "Abre:  $(/usr/local/bin/devdoctor url --config /etc/devdoctor/config.json)"

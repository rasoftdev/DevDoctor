#!/usr/bin/env bash
# DevDoctor — instalador remoto: descarga el repo, compila, instala y borra todo lo temporal.
#
#   curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash -s -- --port 8443 --user admin
#   curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash -s -- uninstall
#
# Variables opcionales: DEVDOCTOR_REPO (URL git), DEVDOCTOR_REF (rama/tag, por defecto main).
set -euo pipefail

REPO="${DEVDOCTOR_REPO:-https://github.com/rasoftdev/DevDoctor.git}"
REF="${DEVDOCTOR_REF:-main}"
GO_VERSION="1.24.4"

say() { printf '\033[1;36m▶\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m✖\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root (anteponer sudo al bash):  curl -fsSL … | sudo bash"
[ "$(uname -s)" = "Linux" ] || die "DevDoctor sólo funciona en Linux."
command -v systemctl >/dev/null || die "Se requiere systemd."

if [ "${1:-}" = "uninstall" ]; then
  say "Desinstalando DevDoctor…"
  systemctl disable --now devdoctor 2>/dev/null || true
  rm -f /etc/systemd/system/devdoctor.service /usr/local/bin/devdoctor
  rm -rf /etc/devdoctor
  rm -f /etc/fail2ban/filter.d/devdoctor.conf /etc/fail2ban/jail.d/devdoctor.local
  systemctl reload fail2ban 2>/dev/null || true
  systemctl daemon-reload
  say "Listo. DevDoctor fue eliminado."
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "Arquitectura no soportada: $(uname -m)" ;;
esac

command -v git  >/dev/null || die "Falta git (apt install git / dnf install git)."
command -v curl >/dev/null || die "Falta curl."

# Todo lo temporal vive aquí y se borra siempre al salir (éxito o error).
WORK="$(mktemp -d /tmp/devdoctor-build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

say "Descargando el repositorio ($REF)…"
git clone --quiet --depth 1 --branch "$REF" "$REPO" "$WORK/repo"

# Go: usa el del sistema si es suficientemente nuevo; si no, uno temporal dentro de $WORK.
need_go=1
if command -v go >/dev/null; then
  have="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
  [ "$(printf '%s\n1.24\n' "$have" | sort -V | head -1)" = "1.24" ] && need_go=0
fi
if [ "$need_go" -eq 1 ]; then
  say "Descargando Go $GO_VERSION temporal (se eliminará al terminar)…"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" | tar -C "$WORK" -xz
  export PATH="$WORK/go/bin:$PATH"
fi
export GOCACHE="$WORK/gocache" GOPATH="$WORK/gopath" GOFLAGS="-mod=mod" CGO_ENABLED=0

say "Compilando…"
( cd "$WORK/repo" && go build -trimpath -ldflags "-s -w" -o "deploy/devdoctor-linux-$ARCH" ./cmd/devdoctor )

if [ "${DEVDOCTOR_BUILD_ONLY:-}" = "1" ]; then
  say "Compilación OK (modo prueba; no se instala)."
  "$WORK/repo/deploy/devdoctor-linux-$ARCH" version
  exit 0
fi

say "Instalando…"
bash "$WORK/repo/deploy/install.sh" "$@"

say "Limpiando archivos temporales…"
# (el trap borra $WORK al salir)

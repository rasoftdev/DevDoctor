#!/usr/bin/env bash
# DevDoctor remote installer: downloads the repo, builds, installs and removes all temporary files.
#
#   curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash -s -- --port 8443 --host 203.0.113.10
#   curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash -s -- uninstall
#
# Once installed you can also use:  sudo devdoctor update   |   sudo devdoctor uninstall
# Optional variables: DEVDOCTOR_REPO (git URL), DEVDOCTOR_REF (branch/tag, default: main).
set -euo pipefail

REPO="${DEVDOCTOR_REPO:-https://github.com/rasoftdev/DevDoctor.git}"
REF="${DEVDOCTOR_REF:-main}"
GO_VERSION="1.24.4"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (put sudo before bash):  curl -fsSL ... | sudo bash"
[ "$(uname -s)" = "Linux" ] || die "DevDoctor only runs on Linux."
command -v systemctl >/dev/null || die "systemd is required."

if [ "${1:-}" = "uninstall" ]; then
  say "Uninstalling DevDoctor..."
  systemctl disable --now devdoctor 2>/dev/null || true
  rm -f /etc/systemd/system/devdoctor.service /usr/local/bin/devdoctor
  rm -rf /etc/devdoctor
  rm -f /etc/fail2ban/filter.d/devdoctor.conf /etc/fail2ban/jail.d/devdoctor.local
  systemctl reload fail2ban 2>/dev/null || true
  systemctl daemon-reload
  say "Done. DevDoctor has been removed."
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "Unsupported architecture: $(uname -m)" ;;
esac

command -v git  >/dev/null || die "git is missing (apt install git / dnf install git)."
command -v curl >/dev/null || die "curl is missing."

# Everything temporary lives here and is always deleted on exit (success or failure).
WORK="$(mktemp -d /tmp/devdoctor-build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

say "Downloading the repository ($REF)..."
git clone --quiet --depth 1 --branch "$REF" "$REPO" "$WORK/repo"

# Go: use the system one if recent enough; otherwise a temporary copy inside $WORK.
need_go=1
if command -v go >/dev/null; then
  have="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
  [ "$(printf '%s\n1.24\n' "$have" | sort -V | head -1)" = "1.24" ] && need_go=0
fi
if [ "$need_go" -eq 1 ]; then
  say "Downloading a temporary Go $GO_VERSION (it will be removed when finished)..."
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" | tar -C "$WORK" -xz
  export PATH="$WORK/go/bin:$PATH"
fi
export GOCACHE="$WORK/gocache" GOPATH="$WORK/gopath" GOFLAGS="-mod=mod" CGO_ENABLED=0

say "Building..."
( cd "$WORK/repo" && go build -trimpath -ldflags "-s -w" -o "deploy/devdoctor-linux-$ARCH" ./cmd/devdoctor )

if [ "${DEVDOCTOR_BUILD_ONLY:-}" = "1" ]; then
  say "Build OK (test mode; nothing is installed)."
  "$WORK/repo/deploy/devdoctor-linux-$ARCH" version
  exit 0
fi

say "Installing..."
bash "$WORK/repo/deploy/install.sh" "$@"

say "Cleaning up temporary files..."
# (the trap removes $WORK on exit)

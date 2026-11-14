#!/usr/bin/env bash
# Builds static Linux binaries (amd64 and arm64) into ./dist
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "dist/devdoctor-linux-$arch" ./cmd/devdoctor
  echo "dist/devdoctor-linux-$arch"
done
cp -r deploy/install.sh deploy/devdoctor.service deploy/fail2ban dist/

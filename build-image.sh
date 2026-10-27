#!/bin/sh
set -eu
cd "$(dirname "$0")"
./kotlin build -m server-linux -v release
mkdir -p dist
cp build/tasks/_server-linux_linkLinuxArm64Release/server-linux.kexe dist/telegram-mcp
printf '%s\n' 'Linux ARM64 binary ready. Build the Docker image on an ARM64 host with: docker build -t telegram-mcp:local .'

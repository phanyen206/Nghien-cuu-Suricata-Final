#!/usr/bin/env bash
# Chay tren Victim tai thu muc tam rong, tranh chia se thu muc home.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p http-lab
printf 'KB11 normal HTTP test\n' > http-lab/index.html
cd http-lab
sudo python3 -m http.server 80 --bind 192.168.100.20

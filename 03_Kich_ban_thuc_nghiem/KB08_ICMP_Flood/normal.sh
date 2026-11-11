#!/usr/bin/env bash
# Chay tren Attacker, tao 5 Echo Request binh thuong.
set -euo pipefail
ping -c 5 -i 1 -I 192.168.100.10 192.168.100.20

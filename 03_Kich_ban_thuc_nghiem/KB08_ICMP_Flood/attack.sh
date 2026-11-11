#!/usr/bin/env bash
# Chay tren Attacker trong lab Host-only VMnet1.
# Tao dung mau ICMP 100 goi da dung trong bao cao; KHONG su dung flood vo han.
set -euo pipefail
ping -c 100 -i 0.01 -I 192.168.100.10 192.168.100.20

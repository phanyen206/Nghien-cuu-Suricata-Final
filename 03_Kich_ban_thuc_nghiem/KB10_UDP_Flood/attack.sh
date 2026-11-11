#!/usr/bin/env bash
# May Attacker - su dung duy nhat tren VMnet1 cua nhom
set -euo pipefail
ip -4 addr show dev ens37 | grep -q '192.168.100.10/24' || { echo 'Khong thay IP Attacker 192.168.100.10 tren ens37' >&2; exit 1; }
sudo hping3 --udp -c 100 -i u10000 -p 9999 192.168.100.20

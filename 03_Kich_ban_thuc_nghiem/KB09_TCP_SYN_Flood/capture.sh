#!/usr/bin/env bash
# Chay tren Victim. Dung Ctrl+C khi Attacker da gui xong.
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-}" in
  syn) file=sample_group.pcap;;
  normal) file=normal_group.pcap;;
  *) echo "Cach dung: ./capture.sh syn | normal" >&2; exit 1;;
esac
if [[ -e "$file" ]]; then echo "File $file da ton tai. Doi ten/sao luu truoc, khong ghi de." >&2; exit 1; fi
sudo tcpdump -i ens37 -nn -w "$file" 'tcp and host 192.168.100.10 and host 192.168.100.20 and port 80'

#!/usr/bin/env bash
# Chay tren Victim: ./capture.sh sample_group.pcap (hoac normal_group.pcap)
# Bat Ctrl+C sau khi script tren Attacker hoan tat.
set -euo pipefail
filename="${1:-}"
if [[ "$filename" != "sample_group.pcap" && "$filename" != "normal_group.pcap" ]]; then
  echo 'Dung: ./capture.sh sample_group.pcap|normal_group.pcap' >&2
  exit 2
fi
if [[ -e "$filename" ]]; then
  echo "File $filename da ton tai. Khong ghi de du lieu cu." >&2
  exit 1
fi
sudo tcpdump -i ens37 -nn -w "$filename" 'icmp and src host 192.168.100.10 and dst host 192.168.100.20'

#!/usr/bin/env bash
# May Victim: bash capture.sh attack|normal
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-}" in
  attack) filename=sample_group.pcap;;
  normal) filename=normal_group_new.pcap;;
  *) echo 'Dung: bash capture.sh attack|normal' >&2; exit 2;;
esac
if [[ -e "$filename" ]]; then echo "File $filename da ton tai; doi ten/sao luu truoc khi ghi" >&2; exit 1; fi
echo "Dang bat UDP tu 192.168.100.10 den 192.168.100.20:9999; Ctrl+C sau khi gui xong"
sudo tcpdump -i ens37 -nn -w "$filename" 'udp and src host 192.168.100.10 and dst host 192.168.100.20 and dst port 9999'

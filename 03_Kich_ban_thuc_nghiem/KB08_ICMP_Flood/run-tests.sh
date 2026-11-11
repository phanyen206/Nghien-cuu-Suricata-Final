#!/usr/bin/env bash
# Chay tren Victim sau khi co sample_group.pcap va normal_group.pcap.
# Luu log moi, khong cong don eve.json cua cac lan truoc.
set -euo pipefail
cd "$(dirname "$0")"
for f in sample_group.pcap normal_group.pcap custom-rule.rules; do
  [[ -f "$f" ]] || { echo "Thieu file: $f" >&2; exit 1; }
done
command -v jq >/dev/null || { echo 'Can cai jq' >&2; exit 1; }
BASE="results_$(date +%Y%m%d_%H%M%S)_$$"
mkdir "$BASE"
run_case() {
  local name="$1" pcap="$2" custom="$3"
  mkdir "$BASE/$name"
  if [[ "$custom" == yes ]]; then
    sudo suricata -r "$pcap" -c /etc/suricata/suricata.yaml -s custom-rule.rules -l "$BASE/$name"
    jq -s '[.[] | select(.event_type=="alert" and .alert.signature_id==1000006)] | length' "$BASE/$name/eve.json"
  else
    sudo suricata -r "$pcap" -c /etc/suricata/suricata.yaml -l "$BASE/$name"
    jq -s '[.[] | select(.event_type=="alert")] | length' "$BASE/$name/eve.json"
  fi
}
echo 'Run 1 - doi chung, sample:'; run_case run1 sample_group.pcap no
echo 'Run 2 - luat rieng, sample:'; run_case run2 sample_group.pcap yes
echo 'Run 3 - doi chung, normal:'; run_case run3 normal_group.pcap no
echo 'Run 4 - luat rieng, normal:'; run_case run4 normal_group.pcap yes
echo "Log: $BASE"

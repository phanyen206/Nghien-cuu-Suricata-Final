#!/usr/bin/env bash
# Chay tren Victim voi sample_group.pcap va normal_group.pcap da thu thap.
set -euo pipefail
cd "$(dirname "$0")"
for f in sample_group.pcap normal_group.pcap custom-rule.rules; do
  [[ -f "$f" ]] || { echo "Thieu $f" >&2; exit 1; }
done
command -v jq >/dev/null || { echo 'Can cai jq' >&2; exit 1; }
# Moi lan tao thu muc ket qua moi, tranh cong don eve.json.
BASE="group_results_$(date +%Y%m%d_%H%M%S)_$$"
mkdir -p "$BASE"
run_case() {
  local name="$1" pcap="$2" custom="$3"
  mkdir -p "$BASE/$name"
  if [[ "$custom" == yes ]]; then
    sudo suricata -r "$pcap" -c /etc/suricata/suricata.yaml -s custom-rule.rules -l "$BASE/$name"
  else
    sudo suricata -r "$pcap" -c /etc/suricata/suricata.yaml -l "$BASE/$name"
  fi
  local total sid
  total=$(jq -s '[.[] | select(.event_type=="alert")] | length' "$BASE/$name/eve.json")
  sid=$(jq -s '[.[] | select(.event_type=="alert" and .alert.signature_id==1000010)] | length' "$BASE/$name/eve.json")
  echo "$name: tong=$total, SID1000010=$sid"
}
run_case run1 sample_group.pcap no
run_case run2 sample_group.pcap yes
run_case run3 normal_group.pcap no
run_case run4 normal_group.pcap yes
echo "Logs: $BASE"

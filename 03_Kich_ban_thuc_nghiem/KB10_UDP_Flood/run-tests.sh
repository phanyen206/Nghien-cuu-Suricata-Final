#!/usr/bin/env bash
# May Victim: bash run-tests.sh -- chay bon phep thu, log moi tung lan
set -euo pipefail
cd "$(dirname "$0")"
for program in suricata jq; do command -v "$program" >/dev/null || { echo "Thieu: $program" >&2; exit 1; }; done
for file in sample_group.pcap normal_group_new.pcap custom-rule.rules; do [[ -f "$file" ]] || { echo "Thieu $file" >&2; exit 1; }; done
sudo suricata -T -c /etc/suricata/suricata.yaml -s custom-rule.rules >/dev/null
base="results_$(date +%Y%m%d_%H%M%S)_$$"; mkdir -p "$base"
run() {
 local label="$1" pcap="$2" mode="$3"; mkdir -p "$base/$label"
 if [[ "$mode" == custom ]]; then
  sudo suricata -r "$pcap" -c /etc/suricata/suricata.yaml -s custom-rule.rules -l "$base/$label"
 else
  sudo suricata -r "$pcap" -c /etc/suricata/suricata.yaml -l "$base/$label"
 fi
 local log="$base/$label/eve.json"
 printf '%s: tong alert = ' "$label"
 jq -s '[.[] | select(.event_type=="alert")] | length' "$log"
 printf '%s: alert SID 1000015 = ' "$label"
 jq -s '[.[] | select(.event_type=="alert" and .alert.signature_id==1000015)] | length' "$log"
}
run run1_group sample_group.pcap baseline
run run2_group sample_group.pcap custom
run run3_group normal_group_new.pcap baseline
run run4_group normal_group_new.pcap custom
echo "Logs: $base"

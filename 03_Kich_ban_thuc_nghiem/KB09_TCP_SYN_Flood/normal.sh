#!/usr/bin/env bash
# Chay tren Attacker sau khi Victim bat HTTP server TCP 80.
set -euo pipefail
if ! command -v curl >/dev/null 2>&1; then echo "Thieu curl" >&2; exit 1; fi
curl --interface 192.168.100.10 --max-time 15 -sS -o /dev/null -w 'HTTP %{http_code}\n' http://192.168.100.20/

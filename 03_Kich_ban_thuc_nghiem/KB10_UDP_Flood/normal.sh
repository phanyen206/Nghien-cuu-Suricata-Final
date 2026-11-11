#!/usr/bin/env bash
# May Attacker - dung Python thay hping3 de gui 5 goi UDP cach 1 giay
set -euo pipefail
python3 - <<'PYCODE'
import socket, time
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(('192.168.100.10', 0))
    for i in range(5):
        sock.sendto(b'UDP normal test', ('192.168.100.20', 9999))
        print(f'Da gui goi UDP {i+1}/5', flush=True)
        time.sleep(1)
PYCODE

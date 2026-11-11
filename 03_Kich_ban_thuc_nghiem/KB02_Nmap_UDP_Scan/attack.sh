#!/bin/bash
# 02-nmap-udp-scan — SUA IP cho dung lab that truoc khi chay. Day la lenh mau.
VICTIM="192.168.100.20"
sudo nmap -sU --top-ports 100 "$VICTIM"

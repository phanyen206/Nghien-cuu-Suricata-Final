#!/bin/bash
# 01-nmap-syn-scan — SUA IP cho dung lab that truoc khi chay. Day la lenh mau.
VICTIM="192.168.100.20"
sudo nmap -sS -p 1-1000 "$VICTIM"

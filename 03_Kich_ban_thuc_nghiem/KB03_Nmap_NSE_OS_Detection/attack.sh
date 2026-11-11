#!/bin/bash
# 05-nmap-nse-os-detect — SUA IP cho dung lab that truoc khi chay. Day la lenh mau.
VICTIM="192.168.100.20"
sudo nmap -O -sV --script http-title "$VICTIM"

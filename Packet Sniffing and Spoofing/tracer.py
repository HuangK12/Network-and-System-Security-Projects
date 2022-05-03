# Kevin Huang
# CSS 537
# sniffspoof.c
# 01/24/2022

#!/usr/bin/env python3
from scapy.all import *

for i in range(1, 15):
  a = IP()
  a.dst = '8.8.8.8'
  a.ttl = i
  b = ICMP()
  send (a/b)

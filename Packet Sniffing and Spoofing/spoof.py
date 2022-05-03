# Kevin Huang
# CSS 537
# sniffspoof.c
# 01/24/2022

#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.dst = '10.9.0.5'
a.src = '10.9.0.6'
b = ICMP()
p = a/b
send(p)
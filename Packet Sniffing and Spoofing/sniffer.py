# Kevin Huang
# CSS 537
# sniffspoof.c
# 01/24/2022

#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
  pkt.show()
  
pkt = sniff(iface='br-8349f2980054', filter='dst net 128.230.0.0/16', prn=print_pkt)

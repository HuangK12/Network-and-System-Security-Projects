# Kevin Huang
# CSS 537
# sniffspoof.c
# 01/24/2022

#!/usr/bin/env python3
from scapy.all import *

def spoof_pkt(pkt):
  a = IP()
  a.dst = pkt[IP].src
  a.src = pkt[IP].dst
  a.ihl = pkt[IP].ihl
  b = ICMP()
  b.type = 0
  b.id = pkt[ICMP].id
  b.seq = pkt[ICMP].seq
  c = pkt[Raw].load
  p = a/b/c
  send(p, verbose = 0)
  
pkt = sniff(iface='br-8349f2980054', filter='icmp', prn=spoof_pkt)

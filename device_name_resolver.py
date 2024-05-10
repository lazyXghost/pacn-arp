from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR


pkt = IP(dst="224.0.0.251") / UDP(dport=5353) / \
        DNS(rd=1, qd=DNSQR(qname="172.16.5.58", qtype="PTR", qclass="IN"))

response = sr1(pkt, verbose=True, timeout=2)

print(response[DNS].an.rdata.decode()[:-1]) 
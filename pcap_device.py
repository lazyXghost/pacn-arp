from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether

# Define a function to extract device details from packet headers
def extract_device_details(packet):
    print(packet)

# Sniff packets and call the function for each packet
sniff(prn=extract_device_details, count=30)

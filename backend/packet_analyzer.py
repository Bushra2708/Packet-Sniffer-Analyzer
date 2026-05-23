from scapy.all import IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, ARP

from utils.geoip_tracker import get_ip_location
from utils.threat_detector import detect_threat


def analyze_packet(packet):

    packet_data = {
        "source_ip": "N/A",
        "destination_ip": "N/A",
        "protocol": "OTHER",
        "source_port": "N/A",
        "destination_port": "N/A",
        "packet_length": len(packet),
        "location": {},
        "alerts": []
    }

    # ==========================
    # ARP PACKETS
    # ==========================

    if packet.haslayer(ARP):

        packet_data["protocol"] = "ARP"

        packet_data["source_ip"] = packet[ARP].psrc

        packet_data["destination_ip"] = packet[ARP].pdst

    # ==========================
    # IP PACKETS
    # ==========================

    elif packet.haslayer(IP) or packet.haslayer(IPv6):

        packet_data["source_ip"] = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src

        packet_data["destination_ip"] = packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst

        # GEO LOCATION
        if not packet_data["destination_ip"].startswith("192.168") and not packet_data["destination_ip"].startswith("fe80"):

            packet_data["location"] = get_ip_location(
                packet_data["destination_ip"]
            )

        # ======================
        # TCP
        # ======================

        if packet.haslayer(TCP):

            packet_data["protocol"] = "TCP"

            packet_data["source_port"] = packet[TCP].sport

            packet_data["destination_port"] = packet[TCP].dport

        # ======================
        # UDP
        # ======================

        elif packet.haslayer(UDP):

            packet_data["protocol"] = "UDP"

            packet_data["source_port"] = packet[UDP].sport

            packet_data["destination_port"] = packet[UDP].dport

        # ======================
        # ICMP
        # ======================

        elif packet.haslayer(ICMP) or any("ICMPv6" in layer.__name__ for layer in packet.layers()):

            packet_data["protocol"] = "ICMP"

    # ==========================
    # THREAT DETECTION
    # ==========================

    packet_data["alerts"] = detect_threat(packet_data)

    return packet_data
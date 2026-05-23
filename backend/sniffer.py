from scapy.all import sniff

from packet_analyzer import analyze_packet
from logger import log_packet

# Global control flag for sniffing state
is_sniffing_active = True

def set_sniffing_active(active):
    global is_sniffing_active
    is_sniffing_active = active
    print(f"Packet Sniffing state set to: {is_sniffing_active}")

def process_packet(packet, socketio):

    if not is_sniffing_active:
        return

    try:

        packet_data = analyze_packet(packet)

        print(packet_data)

        log_packet(packet_data)

        socketio.emit(
            "new_packet",
            packet_data
        )

    except Exception as e:

        print("Error:", e)


def start_sniffing(socketio):

    print("Starting Packet Sniffer...")

    sniff(
        prn=lambda packet:
            process_packet(packet, socketio),

        store=False
    )
SUSPICIOUS_PORTS = [
    4444,
    5555,
    6666,
    1337,
    31337
]


def detect_threat(packet_data):

    alerts = []

    # Suspicious Ports
    if packet_data["destination_port"] in SUSPICIOUS_PORTS:

        alerts.append(
            f"Suspicious Port Access: "
            f"{packet_data['destination_port']}"
        )

    # Large Packets
    if packet_data["packet_length"] > 2000:

        alerts.append(
            "Large Packet Detected"
        )

    return alerts
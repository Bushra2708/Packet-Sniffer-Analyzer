import csv
import os

LOG_FILE = "logs/packet_logs.csv"

# ==========================
# CREATE CSV FILE
# ==========================

def initialize_log():

    os.makedirs("logs", exist_ok=True)

    if not os.path.exists(LOG_FILE):

        with open(LOG_FILE, "w", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([
                "Source IP",
                "Destination IP",
                "Protocol",
                "Source Port",
                "Destination Port",
                "Packet Length"
            ])

# ==========================
# SAVE PACKET
# ==========================

def log_packet(packet):

    with open(LOG_FILE, "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            packet["source_ip"],
            packet["destination_ip"],
            packet["protocol"],
            packet["source_port"],
            packet["destination_port"],
            packet["packet_length"]
        ])
import os
import random
import time
from scapy.all import sniff

from packet_analyzer import analyze_packet
from logger import log_packet
from utils.threat_detector import detect_threat

# Global control flag for sniffing state
is_sniffing_active = True
use_simulation = False

# Mock locations for simulation to avoid hitting external GeoIP APIs and getting rate-limited
MOCK_LOCATIONS = [
    {"country": "United States", "city": "Mountain View", "isp": "Google LLC"},
    {"country": "Australia", "city": "Sydney", "isp": "Cloudflare, Inc."},
    {"country": "United States", "city": "San Francisco", "isp": "Twitter, Inc."},
    {"country": "Japan", "city": "Tokyo", "isp": "Amazon Technologies"},
    {"country": "Ireland", "city": "Dublin", "isp": "Microsoft Corporation"},
    {"country": "United States", "city": "Chicago", "isp": "GitHub, Inc."},
    {"country": "Germany", "city": "Frankfurt", "isp": "Google Cloud"},
    {"country": "United Kingdom", "city": "London", "isp": "British Telecom"}
]

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
        print("Error processing packet:", e)

def generate_mock_packet():
    protocols = ["TCP", "UDP", "ICMP", "ARP"]
    proto = random.choices(protocols, weights=[60, 25, 10, 5], k=1)[0]
    
    external_ips = [
        "8.8.8.8", "1.1.1.1", "142.250.190.46", "104.244.42.1", 
        "13.224.233.111", "20.112.52.29", "185.199.108.153", "34.117.237.239"
    ]
    internal_ips = [
        "192.168.1.1", "192.168.1.15", "192.168.1.35", "192.168.1.100", "10.0.0.5"
    ]
    
    direction = random.choice(["inbound", "outbound", "internal"])
    if direction == "inbound":
        src = random.choice(external_ips)
        dst = random.choice(internal_ips)
    elif direction == "outbound":
        src = random.choice(internal_ips)
        dst = random.choice(external_ips)
    else:
        src = random.choice(internal_ips)
        dst = random.choice(internal_ips)
        
    src_port = None
    dst_port = None
    packet_length = random.randint(40, 1500)
    
    if proto in ["TCP", "UDP"]:
        common_ports = [80, 443, 22, 53, 8080, 21, 23, 25]
        # Occasionally generate suspicious port
        if random.random() < 0.15:
            dst_port = random.choice([4444, 1337, 5555, 6666, 31337])
        else:
            dst_port = random.choice(common_ports)
        src_port = random.randint(49152, 65535)
        
        if proto == "TCP":
            packet_length = random.randint(54, 1460)
        else:
            packet_length = random.randint(28, 512)
            
        # Large packet simulation occasionally
        if random.random() < 0.05:
            packet_length = random.randint(2001, 3000)
    elif proto == "ICMP":
        packet_length = random.choice([32, 64, 128])
    elif proto == "ARP":
        packet_length = 60
        src = f"192.168.1.{random.randint(2, 254)}"
        dst = f"192.168.1.{random.randint(2, 254)}"
        
    location = {}
    if proto != "ARP" and not dst.startswith("192.168") and not dst.startswith("10."):
        # Use local mock locations to avoid hitting external IP-API during simulation
        location = random.choice(MOCK_LOCATIONS)
        
    packet_data = {
        "source_ip": src,
        "destination_ip": dst,
        "protocol": proto,
        "source_port": src_port,
        "destination_port": dst_port,
        "packet_length": packet_length,
        "location": location,
        "alerts": []
    }
    
    packet_data["alerts"] = detect_threat(packet_data)
    return packet_data

def run_simulation(socketio):
    print("Fallback simulation started. Generating mock packet stream...")
    while True:
        if is_sniffing_active:
            try:
                packet_data = generate_mock_packet()
                log_packet(packet_data)
                socketio.emit("new_packet", packet_data)
            except Exception as e:
                print("Error in simulation packet generation:", e)
        time.sleep(random.uniform(0.5, 1.5))

def start_sniffing(socketio):
    global use_simulation
    
    # Check environment variables
    if os.environ.get("SIMULATE_TRAFFIC", "").lower() == "true" or os.environ.get("RENDER", ""):
        print("Simulation mode forced or Render detected. Starting simulator directly.")
        use_simulation = True
        run_simulation(socketio)
        return

    print("Starting Packet Sniffer...")
    try:
        # Try live sniffing test
        sniff(count=1, timeout=0.3)
        print("Live capture initialized successfully.")
        sniff(
            prn=lambda packet: process_packet(packet, socketio),
            store=False
        )
    except Exception as e:
        print(f"Failed to start live sniffing ({e}). Falling back to simulation mode.")
        use_simulation = True
        run_simulation(socketio)
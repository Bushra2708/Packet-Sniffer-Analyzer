# NetScope – Real-Time Packet Sniffer & Network Traffic Analyzer

```md id="q8m2vk"
# 🌐 NetScope – Real-Time Packet Sniffer & Network Traffic Analyzer

NetScope is a modern real-time packet sniffer and cybersecurity dashboard built using Python, Flask, Scapy, and Socket.IO. It captures, analyzes, and visualizes network traffic with live monitoring, protocol analysis, GeoIP tracking, threat detection, and interactive charts.

The project supports:

✅ Real Packet Sniffing (Local Machine)  
✅ Cloud Simulation Mode (Render Deployment)  
✅ Real-Time Dashboard Updates  
✅ Live Packet Analysis  
✅ Threat Detection Alerts  
✅ GeoIP Tracking  
✅ CSV Logging  
✅ Cybersecurity Visualization  

---

# Live Link
https://packet-sniffer-analyzer.onrender.com/

# 🚀 Features

## 🔍 Real-Time Packet Sniffing
- Captures live network packets using Scapy
- Supports:
  - TCP
  - UDP
  - ICMP
  - ARP

## 📊 Live Dashboard
- Real-time packet counters
- Interactive traffic charts
- Dynamic packet table
- Alert notification system

## 🌍 GeoIP Tracking
- Detects:
  - Country
  - City
  - ISP
- Uses IP geolocation APIs locally
- Uses mock locations in cloud simulation mode

## 🛡️ Threat Detection
Detects:
- Suspicious ports
- Large packet payloads
- Potential malicious traffic indicators

## 📁 CSV Packet Logging
Automatically stores packet data into:
```

```md id="t3p7qx"
logs/packet_logs.csv
```

```md id="x7m4pl"

## ☁️ Cloud Simulation Mode
Since cloud providers restrict raw packet sniffing, NetScope automatically switches to simulation mode during deployment.

Simulation mode:
- Generates realistic network packets
- Simulates TCP/UDP/ICMP/ARP traffic
- Produces live dashboard activity
- Prevents deployment failures

---

# 🧠 Technologies Used

| Technology          | Purpose                 |
|---------------------|-------------------------|
| Python              | Backend Logic           |
| Flask               | Web Framework           |
| Flask-SocketIO      | Real-Time Communication |
| Scapy               | Packet Sniffing         |
| Chart.js            | Live Graphs             |
| HTML/CSS/JavaScript | Frontend UI             |
| Requests            | GeoIP API               |
| CSV                 | Packet Logging          |

---

# 📂 Project Structure

```

```md id="m5v9zk"
Packet-Sniffer-Analyzer/
│
├── backend/
│   │
│   ├── app.py
│   ├── sniffer.py
│   ├── packet_analyzer.py
│   ├── logger.py
│   ├── requirements.txt
│   │
│   ├── logs/
│   │   └── packet_logs.csv
│   │
│   └── utils/
│       ├── __init__.py
│       ├── geoip_tracker.py
│       └── threat_detector.py
│
├── frontend/
│   │
│   ├── templates/
│   │   └── index.html
│   │
│   └── static/
│       │
│       ├── css/
│       │   └── style.css
│       │
│       └── js/
│           └── script.js
│
├── Procfile
├── runtime.txt
├── .gitignore
└── README.md
```

````md id="p4n8ql"

---

# ⚙️ Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/Packet-Sniffer-Analyzer.git
````

## 2️⃣ Navigate Into Project

```bash
cd Packet-Sniffer-Analyzer
```

## 3️⃣ Create Virtual Environment

### Windows

```bash
python -m venv venv
```

## 4️⃣ Activate Virtual Environment

### Windows

```bash
venv\Scripts\activate
```

## 5️⃣ Install Dependencies

```bash
pip install -r backend/requirements.txt
```

---

# ▶️ Running the Project

## Start Backend Server

```bash
cd backend
python app.py
```

Open browser:

````


```md id="v1x7pk"
http://127.0.0.1:5000
````

````md id="z6m2qw"

---

# 🧪 Testing Traffic

## Generate ICMP Traffic

```bash
ping google.com
````

## Generate DNS Traffic

```bash
nslookup github.com
```

## Generate HTTPS Traffic

Open websites like:

* YouTube
* GitHub
* Google

---

# ☁️ Render Deployment

## Environment Variables

Add:

````


```md id="f8p3vm"
SIMULATE_TRAFFIC=true
````

````md id="n2q7zk"

## Build Command

```bash
pip install -r backend/requirements.txt
````

## Start Command

```bash
python backend/app.py
```

---

# 🔄 Application Modes

| Mode            | Description                                      |
| --------------- | ------------------------------------------------ |
| Live Sniffing   | Captures real packets locally                    |
| Simulation Mode | Generates realistic traffic for cloud deployment |

```
```

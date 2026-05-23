// ==========================================
// NETSCOPE DASHBOARD ORCHESTRATION
// ==========================================

const socket = io();

// Stats counters
let totalPackets = 0;
let tcpCount = 0;
let udpCount = 0;
let icmpCount = 0;
let arpCount = 0;
let isSniffingActive = true;

// Active tracking list for searching
let allPackets = [];

// ==========================================
// SOCKET STATE LISTENERS
// ==========================================
socket.on("connect", () => {
    const statusBadge = document.getElementById("connectionStatus");
    const connectionText = document.getElementById("connectionText");
    statusBadge.classList.add("connected");
    connectionText.innerText = isSniffingActive ? "Sniffing Live" : "Sniffer Paused";
});

socket.on("disconnect", () => {
    const statusBadge = document.getElementById("connectionStatus");
    const connectionText = document.getElementById("connectionText");
    statusBadge.classList.remove("connected");
    connectionText.innerText = "Offline";
});

socket.on("status_change", (data) => {
    isSniffingActive = data.active;
    const toggleBtn = document.getElementById("toggleBtn");
    const connectionText = document.getElementById("connectionText");
    
    if (isSniffingActive) {
        toggleBtn.innerText = "⏸ Pause Sniffer";
        toggleBtn.classList.remove("paused");
        connectionText.innerText = "Sniffing Live";
    } else {
        toggleBtn.innerText = "▶ Resume Sniffer";
        toggleBtn.classList.add("paused");
        connectionText.innerText = "Sniffer Paused";
    }
});

// ==========================================
// CHART CONFIGURATION (MULTI-SERIES GLOW)
// ==========================================
const ctx = document.getElementById('trafficChart').getContext('2d');

// CSS variable color fetch helpers
const getStyleColor = (variableName) => getComputedStyle(document.documentElement).getPropertyValue(variableName).trim();

const trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'TCP',
                data: [],
                borderColor: '#00f0ff',
                backgroundColor: 'rgba(0, 240, 255, 0.05)',
                borderWidth: 2.5,
                tension: 0.4,
                pointRadius: 2,
                pointHoverRadius: 5,
                fill: true
            },
            {
                label: 'UDP',
                data: [],
                borderColor: '#bd00ff',
                backgroundColor: 'rgba(189, 0, 255, 0.05)',
                borderWidth: 2.5,
                tension: 0.4,
                pointRadius: 2,
                pointHoverRadius: 5,
                fill: true
            },
            {
                label: 'ICMP',
                data: [],
                borderColor: '#00ff66',
                backgroundColor: 'rgba(0, 255, 102, 0.05)',
                borderWidth: 2.5,
                tension: 0.4,
                pointRadius: 2,
                pointHoverRadius: 5,
                fill: true
            },
            {
                label: 'ARP',
                data: [],
                borderColor: '#ffaa00',
                backgroundColor: 'rgba(255, 170, 0, 0.05)',
                borderWidth: 2.5,
                tension: 0.4,
                pointRadius: 2,
                pointHoverRadius: 5,
                fill: true
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    boxWidth: 12,
                    font: { family: 'Outfit', size: 12, weight: 600 },
                    color: '#94a3b8',
                    padding: 15
                }
            },
            tooltip: {
                backgroundColor: '#0c1025',
                borderColor: 'rgba(255, 255, 255, 0.1)',
                borderWidth: 1,
                titleFont: { family: 'Outfit', weight: 700 },
                bodyFont: { family: 'Space Mono' },
                padding: 12,
                cornerRadius: 8
            }
        },
        scales: {
            x: {
                grid: { color: 'rgba(255, 255, 255, 0.02)' },
                ticks: { color: '#64748b', font: { family: 'Space Mono', size: 10 } }
            },
            y: {
                grid: { color: 'rgba(255, 255, 255, 0.02)' },
                ticks: { color: '#64748b', font: { family: 'Space Mono', size: 10 } },
                suggestedMin: 0
            }
        }
    }
});

// Update Live Graph
function updateChart() {
    if (!isSniffingActive) return;

    const currentTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    trafficChart.data.labels.push(currentTime);
    
    // Plot current totals for each protocol series
    trafficChart.data.datasets[0].data.push(tcpCount);
    trafficChart.data.datasets[1].data.push(udpCount);
    trafficChart.data.datasets[2].data.push(icmpCount);
    trafficChart.data.datasets[3].data.push(arpCount);

    // Maintain 15 points
    if (trafficChart.data.labels.length > 15) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets.forEach(dataset => dataset.data.shift());
    }

    trafficChart.update('none'); // Update without full animations for buttery performance
}

setInterval(updateChart, 2000);

// ==========================================
// UI VALUE FLASH HELPER
// ==========================================
function animateUpdate(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.classList.remove('updated-value');
    void el.offsetWidth; // trigger layout reflow
    el.classList.add('updated-value');
}

// ==========================================
// INCOMING TELEMETRY HANDLER
// ==========================================
socket.on("new_packet", function(packet) {
    if (!isSniffingActive) return;

    // Cache packet for dynamic searches
    allPackets.unshift(packet);
    if (allPackets.length > 150) {
        allPackets.pop();
    }

    // Increment absolute total
    totalPackets++;
    document.getElementById("totalPackets").innerText = totalPackets;
    animateUpdate("totalPackets");

    // Route counts based on protocol type
    const proto = packet.protocol ? packet.protocol.toUpperCase() : "OTHER";
    
    if (proto === "TCP") {
        tcpCount++;
        document.getElementById("tcpCount").innerText = tcpCount;
        animateUpdate("tcpCount");
    } else if (proto === "UDP") {
        udpCount++;
        document.getElementById("udpCount").innerText = udpCount;
        animateUpdate("udpCount");
    } else if (proto === "ICMP") {
        icmpCount++;
        document.getElementById("icmpCount").innerText = icmpCount;
        animateUpdate("icmpCount");
    } else if (proto === "ARP") {
        arpCount++;
        document.getElementById("arpCount").innerText = arpCount;
        animateUpdate("arpCount");
    }

    // Append to UI packet log table
    appendPacketToTable(packet);

    // Analyze threat profiles
    processThreatLog(packet);
});

// ==========================================
// APPEND PACKET ROW TO TABLE
// ==========================================
function appendPacketToTable(packet) {
    const tableBody = document.getElementById("packetTableBody");
    const newRow = tableBody.insertRow(0);
    newRow.className = "new-row";
    
    // Assign packet details to click drawer
    newRow.onclick = () => openPacketDetails(packet);

    const badgeClass = packet.protocol ? packet.protocol.toLowerCase() : "other";

    newRow.innerHTML = `
        <td>
            <span class="protocol-badge ${badgeClass}">
                ${packet.protocol}
            </span>
        </td>
        <td>${packet.source_ip}</td>
        <td>${packet.destination_ip}</td>
        <td>${packet.source_port !== null ? packet.source_port : '-'}</td>
        <td>${packet.destination_port !== null ? packet.destination_port : '-'}</td>
        <td class="${packet.alerts && packet.alerts.length > 0 ? 'threat-text' : ''}">${packet.packet_length}</td>
    `;

    // Cap displayed table rows at 100
    if (tableBody.rows.length > 100) {
        tableBody.deleteRow(100);
    }
}

// ==========================================
// INTRUSION/THREAT LOG PROCESSOR
// ==========================================
function processThreatLog(packet) {
    if (!packet.alerts || packet.alerts.length === 0) return;

    const alertContainer = document.getElementById("alertContainer");
    const emptyAlerts = document.getElementById("emptyAlerts");
    
    if (emptyAlerts) {
        emptyAlerts.style.display = "none";
    }

    packet.alerts.forEach(alertMsg => {
        const alertItem = document.createElement("div");
        alertItem.className = "alert-item";
        
        const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

        alertItem.innerHTML = `
            <div class="alert-title">⚠ Intrusion Signal</div>
            <div class="alert-desc">${alertMsg} (${packet.protocol} from ${packet.source_ip} to port ${packet.destination_port})</div>
            <div class="alert-time">${timestamp}</div>
        `;

        alertContainer.prepend(alertItem);

        // Keep maximum of 15 alert notifications displayed
        if (alertContainer.children.length > 15) {
            alertContainer.lastElementChild.remove();
        }
    });
}

// ==========================================
// SEARCH / MULTI-FIELD FILTER
// ==========================================
function filterTable() {
    const input = document.getElementById("searchInput").value.toLowerCase();
    const tableBody = document.getElementById("packetTableBody");
    
    // Clear display
    tableBody.innerHTML = "";
    
    // Filter from caches
    const filtered = allPackets.filter(packet => {
        const protocol = (packet.protocol || "").toLowerCase();
        const src = (packet.source_ip || "").toLowerCase();
        const dst = (packet.destination_ip || "").toLowerCase();
        const srcPort = String(packet.source_port || "").toLowerCase();
        const dstPort = String(packet.destination_port || "").toLowerCase();
        const len = String(packet.packet_length || "").toLowerCase();

        return protocol.includes(input) || 
               src.includes(input) || 
               dst.includes(input) || 
               srcPort.includes(input) || 
               dstPort.includes(input) || 
               len.includes(input);
    });

    // Populate filtered rows
    filtered.forEach(packet => {
        appendPacketToTable(packet);
    });
}

document.getElementById("searchInput").addEventListener("input", filterTable);

// ==========================================
// PAUSE / RESUME CONTROL
// ==========================================
function toggleSniffing() {
    socket.emit("toggle_sniffing", { active: !isSniffingActive });
}

// ==========================================
// CLEAR METRICS AND STREAM TABLE
// ==========================================
function clearTable() {
    // Clear Table UI
    document.getElementById("packetTableBody").innerHTML = "";
    allPackets = [];

    // Reset counters
    totalPackets = 0;
    tcpCount = 0;
    udpCount = 0;
    icmpCount = 0;
    arpCount = 0;

    // Refresh UI labels
    document.getElementById("totalPackets").innerText = "0";
    document.getElementById("tcpCount").innerText = "0";
    document.getElementById("udpCount").innerText = "0";
    document.getElementById("icmpCount").innerText = "0";
    document.getElementById("arpCount").innerText = "0";

    // Clear Alert Panel
    const alertContainer = document.getElementById("alertContainer");
    alertContainer.innerHTML = `
        <div class="empty-alerts" id="emptyAlerts">
            🔒 No security anomalies detected.
        </div>
    `;

    // Reset Graph dataset
    trafficChart.data.labels = [];
    trafficChart.data.datasets.forEach(dataset => dataset.data = []);
    trafficChart.update();
}

// ==========================================
// EXPORT PACKETS TO LOG CSV
// ==========================================
function exportCSV() {
    window.location.href = "/download_logs";
}

// ==========================================
// PACKET DETAILS DRAWER SLIDER
// ==========================================
function openPacketDetails(packet) {
    const drawer = document.getElementById("packetDrawer");
    const overlay = document.getElementById("overlay");

    // Map base elements
    document.getElementById("detailProtocol").innerText = packet.protocol || "-";
    document.getElementById("detailLength").innerText = (packet.packet_length || "0") + " Bytes";
    document.getElementById("detailSrcIP").innerText = packet.source_ip || "-";
    document.getElementById("detailDstIP").innerText = packet.destination_ip || "-";
    
    // Map Ports
    document.getElementById("detailSrcPort").innerText = packet.source_port !== null ? packet.source_port : "-";
    document.getElementById("detailDstPort").innerText = packet.destination_port !== null ? packet.destination_port : "-";

    // Geolocation details
    const loc = packet.location || {};
    document.getElementById("detailCountry").innerText = loc.country || "Unknown Location / Private IP";
    document.getElementById("detailCity").innerText = loc.city || "Unknown City";
    document.getElementById("detailISP").innerText = loc.isp || "Local Link / Private ISP";

    // Intrusive Alert details
    const banner = document.getElementById("threatStatusBanner");
    if (packet.alerts && packet.alerts.length > 0) {
        banner.className = "threat-banner alerted";
        banner.innerHTML = `<strong>⚠ Intrusion Risk Detected:</strong><br>${packet.alerts.join('<br>')}`;
    } else {
        banner.className = "threat-banner clean";
        banner.innerHTML = `🛡️ Clean Packet: No intrusion signatures matched.`;
    }

    // Toggle Drawer Open State classes
    drawer.classList.add("open");
    overlay.classList.add("open");
}

function closeDrawer() {
    const drawer = document.getElementById("packetDrawer");
    const overlay = document.getElementById("overlay");
    
    drawer.classList.remove("open");
    overlay.classList.remove("open");
}
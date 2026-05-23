from flask import Flask, render_template, send_file
from flask_socketio import SocketIO

from logger import initialize_log
import sniffer
from sniffer import start_sniffing

import threading

# ==========================
# FLASK APP
# ==========================

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

# ==========================
# SOCKETIO
# ==========================

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

# ==========================
# LOGGER
# ==========================

initialize_log()

# ==========================
# HOME ROUTE
# ==========================

@app.route("/")
def home():

    return render_template("index.html")

@app.route("/download_logs")
def download_logs():
    return send_file("logs/packet_logs.csv", as_attachment=True)

# ==========================
# SOCKETIO EVENTS
# ==========================

@socketio.on("connect")
def handle_connect():
    socketio.emit("status_change", {"active": sniffer.is_sniffing_active})

@socketio.on("toggle_sniffing")
def handle_toggle(data):
    active = data.get("active", True)
    sniffer.set_sniffing_active(active)
    socketio.emit("status_change", {"active": active})
    return {"status": "success", "active": active}

# ==========================
# PACKET SNIFFER
# ==========================

def run_sniffer():

    start_sniffing(socketio)

# ==========================
# MAIN
# ==========================

if __name__ == "__main__":

    sniff_thread = threading.Thread(
        target=run_sniffer
    )

    sniff_thread.daemon = True

    sniff_thread.start()

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True
    )
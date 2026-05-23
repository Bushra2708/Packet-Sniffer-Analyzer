import os

# Perform monkey patching if running on Render or if eventlet is available
async_mode = "threading"
if os.environ.get("RENDER") or os.environ.get("USE_EVENTLET"):
    try:
        import eventlet
        eventlet.monkey_patch()
        async_mode = "eventlet"
        print("Production environment (Render/Eventlet) detected. Using Eventlet async mode.")
    except ImportError:
        print("Eventlet not installed. Falling back to default async mode.")

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
    async_mode=async_mode
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

    port = int(os.environ.get("PORT", 5000))
    debug_mode = not os.environ.get("RENDER")

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=debug_mode,
        allow_unsafe_werkzeug=True
    )
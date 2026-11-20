"""
VPN Manager - web backend (Flask).

Shows the page where each host accepts/rejects its tunnels.
On every click it:
    1. saves the new state in STATE_FILE (tunnels.txt), and
    2. calls the ONOS REST API (onos_rest.py) to install / remove the rules.

File format (one line per entry):
    H1 tunnel1 accept
    H2 tunnel1 reject
    ...

Run:
    pip install -r requirements.txt
    python3 app.py
    -> open http://localhost:5000
"""
import os
import shutil
import threading

from flask import Flask, jsonify, render_template, request

import onos_rest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INIT_FILE = os.path.join(BASE_DIR, "tunnels_init.txt")
STATE_FILE = os.environ.get("TUNNELS_FILE", "/tmp/tunnels.txt")

# Which host is at each end of each tunnel
TUNNELS = {
    "tunnel1": ("H1", "H2"),
    "tunnel2": ("H1", "H3"),
}
VALID_ENTRIES = {(h, t) for t, ends in TUNNELS.items() for h in ends}

app = Flask(__name__)
lock = threading.Lock()


def read_state():
    """Returns {("H1", "tunnel1"): "accept", ...}. Missing entry = reject."""
    state = {entry: "reject" for entry in VALID_ENTRIES}
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            for line in f:
                parts = line.split()
                if len(parts) == 3 and (parts[0], parts[1]) in VALID_ENTRIES:
                    state[(parts[0], parts[1])] = parts[2].lower()
    return state


def write_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        for host, tunnel in sorted(state):
            f.write("{} {} {}\n".format(host, tunnel, state[(host, tunnel)]))
    os.replace(tmp, STATE_FILE)


def state_as_json(state, onos_error=None):
    hosts = {}
    for (host, tunnel), action in state.items():
        hosts.setdefault(host, {})[tunnel] = action

    tunnels = {}
    for tunnel, (a, b) in TUNNELS.items():
        a_ok = state[(a, tunnel)] == "accept"
        b_ok = state[(b, tunnel)] == "accept"
        status = "up" if a_ok and b_ok else "half" if a_ok or b_ok else "down"
        tunnels[tunnel] = {"ends": [a, b], "status": status,
                           "forward": a_ok, "backward": b_ok}
    return {"hosts": hosts, "tunnels": tunnels, "onos_error": onos_error}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/tunnels", methods=["GET"])
def get_tunnels():
    with lock:
        return jsonify(state_as_json(read_state()))


@app.route("/api/tunnels", methods=["POST"])
def set_tunnel():
    data = request.get_json(silent=True) or {}
    host, tunnel, action = data.get("host"), data.get("tunnel"), data.get("action")

    if (host, tunnel) not in VALID_ENTRIES or action not in ("accept", "reject"):
        return jsonify({"error": "invalid host/tunnel/action"}), 400

    with lock:
        state = read_state()
        state[(host, tunnel)] = action
        write_state(state)
        print("[web] {} {} -> {}".format(host, tunnel, action))
        error = None
        try:
            onos_rest.apply((host, tunnel), action)
        except onos_rest.OnosError as e:
            error = str(e)
            print("[web] ONOS ERROR:", error)
        return jsonify(state_as_json(state, error))


@app.route("/api/reset", methods=["POST"])
def reset():
    with lock:
        shutil.copy(INIT_FILE, STATE_FILE)
        state = read_state()
        error = None
        try:
            onos_rest.sync(state)
        except onos_rest.OnosError as e:
            error = str(e)
        return jsonify(state_as_json(state, error))


if __name__ == "__main__":
    # Every run starts with all tunnels closed (also in ONOS)
    shutil.copy(INIT_FILE, STATE_FILE)
    try:
        onos_rest.sync(read_state())
    except onos_rest.OnosError as e:
        print("[web] WARNING, ONOS not reachable yet:", e)
    print("[web] State file: {} (all tunnels rejected)".format(STATE_FILE))
    app.run(host="0.0.0.0", port=5000)

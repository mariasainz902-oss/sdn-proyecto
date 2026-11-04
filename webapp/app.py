"""
VPN Manager - web backend (Flask).

Shows the page where each host accepts/rejects its tunnels and writes the
result to STATE_FILE. The ONOS app (VpnManager.java) reads that same file
every 2 seconds and installs/removes the OpenFlow rules.

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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INIT_FILE = os.path.join(BASE_DIR, "tunnels_init.txt")

# Must be the same path as STATE_FILE in VpnManager.java
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
    """Writes to a temp file and renames it, so ONOS never reads a half-written file."""
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        for host, tunnel in sorted(state):
            f.write(f"{host} {tunnel} {state[(host, tunnel)]}\n")
    os.replace(tmp, STATE_FILE)


def state_as_json(state):
    hosts = {}
    for (host, tunnel), action in state.items():
        hosts.setdefault(host, {})[tunnel] = action

    tunnels = {}
    for tunnel, (a, b) in TUNNELS.items():
        a_ok = state[(a, tunnel)] == "accept"
        b_ok = state[(b, tunnel)] == "accept"
        if a_ok and b_ok:
            status = "up"
        elif a_ok or b_ok:
            status = "half"
        else:
            status = "down"
        tunnels[tunnel] = {
            "ends": [a, b],
            "status": status,
            "forward": a_ok,   # a -> b has rules
            "backward": b_ok,  # b -> a has rules
        }
    return {"hosts": hosts, "tunnels": tunnels}


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
    host = data.get("host")
    tunnel = data.get("tunnel")
    action = data.get("action")

    if (host, tunnel) not in VALID_ENTRIES or action not in ("accept", "reject"):
        return jsonify({"error": "invalid host/tunnel/action"}), 400

    with lock:
        state = read_state()
        state[(host, tunnel)] = action
        write_state(state)
        print(f"[web] {host} {tunnel} -> {action}")
        return jsonify(state_as_json(state))


@app.route("/api/reset", methods=["POST"])
def reset():
    with lock:
        shutil.copy(INIT_FILE, STATE_FILE)
        return jsonify(state_as_json(read_state()))


if __name__ == "__main__":
    # Every run starts with all tunnels closed
    shutil.copy(INIT_FILE, STATE_FILE)
    print(f"[web] State file: {STATE_FILE} (all tunnels rejected)")
    app.run(host="0.0.0.0", port=5000)

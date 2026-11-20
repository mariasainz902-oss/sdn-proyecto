"""
Installs / removes the VPN paths in ONOS using the REST API.

It does the same as clicking "Try it out" in the ONOS Swagger page
(http://localhost:8181/onos/v1/docs), but from Python.

Each "direction" of a tunnel (e.g. H1 -> H2 through tunnel 1) is a list of
hops. For every hop we install 2 flow rules on that switch:
    - IPv4: in_port + src IP + dst IP  -> output port
    - ARP:  in_port + src IP + dst IP  -> output port   (needed for ping)

Can be used from the web app (app.py) or alone from the terminal:
    python3 onos_rest.py status
    python3 onos_rest.py accept H1 tunnel1
    python3 onos_rest.py reject H1 tunnel1
    python3 onos_rest.py accept all
    python3 onos_rest.py reject all
"""
import base64
import json
import sys
import urllib.error
import urllib.request

# ---- ONOS connection (same user/password you use in Firefox) -------------
ONOS_URL = "http://127.0.0.1:8181/onos/v1"
ONOS_USER = "onos"
ONOS_PASS = "rocks"
APP_ID = "appNoaMaria"

PRIORITY = 40000
USE_ARP_RULES = False   # if ONOS rejects the ARP rules, set False and use net.staticArp() in Mininet

# ---- Topology (from the Mininet script) -----------------------------------
# Ports are assigned in the order of addLink:
#   S1: 1->H1  2->S3  3->S4
#   S2: 1->H2  2->S3  3->S4
#   S3: 1->H3  2->S1  3->S2
#   S4: 1->S1  2->S2
H1, H2, H3 = "10.0.0.1", "10.0.0.2", "10.0.0.3"
S1 = "of:0000000000000001"
S2 = "of:0000000000000002"
S3 = "of:0000000000000003"
S4 = "of:0000000000000004"

# (host, tunnel) -> (src IP, dst IP, [(switch, in_port, out_port), ...])
# The key is the same as a line of tunnels.txt: "H1 tunnel1 accept"
DIRECTIONS = {
    # Tunnel 1 (green): H1 - S1 - S4 - S2 - H2
    ("H1", "tunnel1"): (H1, H2, [(S1, 1, 3), (S4, 1, 2), (S2, 3, 1)]),
    ("H2", "tunnel1"): (H2, H1, [(S2, 1, 3), (S4, 2, 1), (S1, 3, 1)]),
    # Tunnel 2 (red): H1 - S1 - S3 - H3
    ("H1", "tunnel2"): (H1, H3, [(S1, 1, 2), (S3, 2, 1)]),
    ("H3", "tunnel2"): (H3, H1, [(S3, 1, 2), (S1, 2, 1)]),
}


class OnosError(Exception):
    pass


# ---- HTTP helper ------------------------------------------------------------

# ONOS is local: never go through a proxy
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def onos(method, path, body=None):
    """Sends one request to the ONOS REST API and returns the JSON answer (or None)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(ONOS_URL + path, data=data, method=method)
    token = base64.b64encode((ONOS_USER + ":" + ONOS_PASS).encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    if data is not None:
        # Only when sending a body; ONOS answers 415 if a GET/DELETE carries it
        req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with _opener.open(req, timeout=5) as r:
            text = r.read().decode()
            return json.loads(text) if text.strip() else None
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise OnosError("{} {} -> HTTP {}: {}".format(method, path, e.code, detail))
    except urllib.error.URLError as e:
        raise OnosError("Cannot reach ONOS at {}: {}".format(ONOS_URL, e.reason))


# ---- Flow rules -------------------------------------------------------------

def build_flow(device, in_port, out_port, src, dst, arp=False):
    """Same JSON you write in the Swagger 'stream' box, with IP match added."""
    if arp:
        criteria = [
            {"type": "IN_PORT", "port": in_port},
            {"type": "ETH_TYPE", "ethType": "0x0806"},
            {"type": "ARP_SPA", "ip": src},
            {"type": "ARP_TPA", "ip": dst},
        ]
    else:
        criteria = [
            {"type": "IN_PORT", "port": in_port},
            {"type": "ETH_TYPE", "ethType": "0x0800"},
            {"type": "IPV4_SRC", "ip": src + "/32"},
            {"type": "IPV4_DST", "ip": dst + "/32"},
        ]
    return {
        "priority": PRIORITY,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": device,
        "selector": {"criteria": criteria},
        "treatment": {"instructions": [{"type": "OUTPUT", "port": str(out_port)}]},
    }


def install(key):
    """Opens one direction: POST one rule per switch of the path (IPv4 + ARP)."""
    src, dst, hops = DIRECTIONS[key]
    for device, in_port, out_port in hops:
        onos("POST", "/flows/{}?appId={}".format(device, APP_ID),
             build_flow(device, in_port, out_port, src, dst))
        if USE_ARP_RULES:
            onos("POST", "/flows/{}?appId={}".format(device, APP_ID),
                 build_flow(device, in_port, out_port, src, dst, arp=True))
    print("[onos] {} {} ACCEPT: {} -> {} via {}".format(
        key[0], key[1], src, dst, " - ".join(h[0][-1] for h in hops)))


def _is_our_rule(flow, src, dst):
    """True if this flow (as returned by GET /flows) is one of ours for src -> dst."""
    if flow.get("priority") != PRIORITY:
        return False
    found_src = found_dst = None
    for c in flow.get("selector", {}).get("criteria", []):
        if c.get("type") in ("IPV4_SRC", "ARP_SPA"):
            found_src = c.get("ip", "").split("/")[0]
        if c.get("type") in ("IPV4_DST", "ARP_TPA"):
            found_dst = c.get("ip", "").split("/")[0]
    return found_src == src and found_dst == dst


def remove(key):
    """Closes one direction: finds our rules on each switch of the path and DELETEs them."""
    src, dst, hops = DIRECTIONS[key]
    removed = 0
    for device, _, _ in hops:
        flows = (onos("GET", "/flows/" + device) or {}).get("flows", [])
        for f in flows:
            if _is_our_rule(f, src, dst):
                onos("DELETE", "/flows/{}/{}".format(device, f["id"]))
                removed += 1
    print("[onos] {} {} REJECT: {} rules removed".format(key[0], key[1], removed))


def apply(key, action):
    if action == "accept":
        install(key)
    else:
        remove(key)


def sync(state):
    """state = {("H1", "tunnel1"): "accept", ...}. Puts ONOS in that state."""
    for key in DIRECTIONS:
        apply(key, state.get(key, "reject"))


def status():
    devices = (onos("GET", "/devices") or {}).get("devices", [])
    print("Switches in ONOS: {}".format(len(devices)))
    for d in devices:
        print("  {}  available={}".format(d["id"], d.get("available")))
    for key, (src, dst, hops) in DIRECTIONS.items():
        count = 0
        for device, _, _ in hops:
            flows = (onos("GET", "/flows/" + device) or {}).get("flows", [])
            count += sum(1 for f in flows if _is_our_rule(f, src, dst))
        print("  {} {:8} {} -> {}: {} rules installed".format(key[0], key[1], src, dst, count))


# ---- Command line ---------------------------------------------------------

if __name__ == "__main__":
    args = sys.argv[1:]
    try:
        if args == ["status"]:
            status()
        elif len(args) == 2 and args[0] in ("accept", "reject") and args[1] == "all":
            for k in DIRECTIONS:
                apply(k, args[0])
        elif len(args) == 3 and args[0] in ("accept", "reject") and (args[1], args[2]) in DIRECTIONS:
            apply((args[1], args[2]), args[0])
        else:
            print(__doc__)
            sys.exit(1)
    except OnosError as e:
        print("ERROR:", e)
        sys.exit(1)
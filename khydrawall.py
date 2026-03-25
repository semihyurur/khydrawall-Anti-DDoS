#!/usr/bin/env python3
# Author: semihyurur (khydra)
"""
╔══════════════════════════════════════════════════════════════════════╗
║          khydrawall Architecture                      ║
║  Layer 1 : XDP/eBPF      — driver-level, ~100 ns                    ║
║  Layer 2 : iptables mangle — pre-routing scrub                       ║
║  Layer 3 : ipset hash:ip  — O(1) million-IP blacklist                ║
║  Layer 4 : Application chains — flood guards                         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import argparse
import ipaddress
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional
from datetime import datetime
import threading

# ─── Paths ────────────────────────────────────────────────────────────────────

BASE_DIR       = Path("/etc/khydrawall")
WHITELIST_FILE = BASE_DIR / "whitelist.conf"
BLACKLIST_FILE = BASE_DIR / "blacklist.conf"
WEBHOOK_FILE   = BASE_DIR / "webhook.conf"
XDP_OBJ        = BASE_DIR / "xdp_filter.o"
XDP_SRC        = Path(__file__).parent / "xdp_filter.c"
STATE_FILE     = BASE_DIR / "state.json"
LOG_FILE       = BASE_DIR / "khydrawall.log"

# ─── Webhook Defaults ────────────────────────────────────────────────────────

WEBHOOK_DEFAULTS = {
    "url": "",
    "type": "discord",           # discord, slack, generic
    "enabled": False,
    "alert_threshold_pps": 1000, # Alert when drops/s exceed this
    "alert_cooldown": 60,        # Seconds between alerts (anti-spam)
    "notify_blacklist": True,    # Alert on IP blacklist
    "notify_start_stop": True,   # Alert on service start/stop
    "notify_attacks": True,      # Alert on detected attacks
    "server_name": "VPS",        # Identifier in alerts
}

# ─── Colours ──────────────────────────────────────────────────────────────────

R  = "\033[91m";  G  = "\033[92m";  Y  = "\033[93m"
B  = "\033[94m";  C  = "\033[96m";  W  = "\033[97m"
DIM = "\033[2m";  BOLD = "\033[1m"; NC = "\033[0m"

def banner():
    print(f"""{B}{BOLD}
 ╔══════════════════════════════════════════════════════════════╗
 ║  ░█████╗░███╗░░██╗████████╗██╗██████╗░██████╗░░█████╗░░██████╗  ║
 ║     khydrawall  ·  v2.0                      ║
 ╚══════════════════════════════════════════════════════════════╝{NC}
""")

def log(level: str, msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    colour = {
        "INFO":  G, "WARN": Y, "ERROR": R, "DEBUG": DIM
    }.get(level, W)
    print(f"  {colour}[{level}]{NC} {msg}")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{ts}] [{level}] {msg}\n")
    except Exception:
        pass

# ─── Helpers ──────────────────────────────────────────────────────────────────

def run(cmd: str, check=True, capture=False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, shell=True, check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True
    )

def require_root():
    if os.geteuid() != 0:
        print(f"{R}[ERROR]{NC} Must be run as root (sudo).")
        sys.exit(1)

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False

def get_ssh_client_ip() -> Optional[str]:
    """Return the IP of the current SSH session (if any)."""
    ssh_conn = os.environ.get("SSH_CONNECTION", "")
    if ssh_conn:
        parts = ssh_conn.split()
        if parts:
            return parts[0]
    # Fallback: inspect /proc/net/tcp for established ssh sessions
    try:
        result = run("ss -tnp | grep sshd | awk '{print $5}' | head -1",
                     capture=True, check=False)
        ip_port = result.stdout.strip()
        if ip_port and ":" in ip_port:
            return ip_port.rsplit(":", 1)[0].strip("[]")
    except Exception:
        pass
    return None

def get_default_interface() -> str:
    result = run("ip route | grep default | awk '{print $5}' | head -1",
                 capture=True, check=False)
    iface = result.stdout.strip()
    return iface if iface else "eth0"

def load_whitelist() -> list[str]:
    if not WHITELIST_FILE.exists():
        return []
    return [
        line.strip() for line in WHITELIST_FILE.read_text().splitlines()
        if line.strip() and not line.startswith("#") and validate_ip(line.strip())
    ]

def load_blacklist() -> list[str]:
    if not BLACKLIST_FILE.exists():
        return []
    return [
        line.strip() for line in BLACKLIST_FILE.read_text().splitlines()
        if line.strip() and not line.startswith("#") and validate_ip(line.strip())
    ]

def save_state(state: dict):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"running": False, "interface": "", "xdp_mode": ""}

# ─── Webhook System ──────────────────────────────────────────────────────────

_last_alert_time = 0
_alert_lock = threading.Lock()

def load_webhook_config() -> dict:
    """Load webhook configuration from file."""
    config = WEBHOOK_DEFAULTS.copy()
    if WEBHOOK_FILE.exists():
        try:
            saved = json.loads(WEBHOOK_FILE.read_text())
            config.update(saved)
        except Exception:
            pass
    return config

def save_webhook_config(config: dict):
    """Save webhook configuration to file."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    WEBHOOK_FILE.write_text(json.dumps(config, indent=2))

def send_webhook_alert(
    title: str,
    description: str,
    color: str = "red",
    fields: list = None,
    force: bool = False
):
    """
    Send alert to configured webhook (Discord/Slack/Generic).
    
    Args:
        title: Alert title
        description: Alert message
        color: red, orange, green, blue
        fields: List of {"name": "...", "value": "..."} dicts
        force: Bypass cooldown (for test alerts)
    """
    global _last_alert_time
    
    config = load_webhook_config()
    
    if not config.get("enabled") or not config.get("url"):
        return False
    
    # Cooldown check (anti-spam)
    with _alert_lock:
        now = time.time()
        cooldown = config.get("alert_cooldown", 60)
        if not force and (now - _last_alert_time) < cooldown:
            return False
        _last_alert_time = now
    
    url = config["url"]
    webhook_type = config.get("type", "discord")
    server_name = config.get("server_name", "VPS")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Color mapping
    colors = {
        "red": 0xFF4444,
        "orange": 0xFFA500,
        "green": 0x44FF44,
        "blue": 0x4444FF,
    }
    color_int = colors.get(color, colors["red"])
    
    try:
        if webhook_type == "discord":
            payload = _build_discord_payload(
                title, description, color_int, fields, server_name, timestamp
            )
        elif webhook_type == "slack":
            payload = _build_slack_payload(
                title, description, color, fields, server_name, timestamp
            )
        else:  # generic
            payload = _build_generic_payload(
                title, description, color, fields, server_name, timestamp
            )
        
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "AntiDDoS/2.0"}
        )
        
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 204)
            
    except Exception as e:
        log("WARN", f"Webhook failed: {e}")
        return False

def _build_discord_payload(title, desc, color, fields, server, ts):
    embed = {
        "title": f"🛡️ {title}",
        "description": desc,
        "color": color,
        "footer": {"text": f"{server} • {ts}"},
        "fields": []
    }
    if fields:
        for f in fields:
            embed["fields"].append({
                "name": f.get("name", ""),
                "value": f.get("value", ""),
                "inline": f.get("inline", True)
            })
    return {"embeds": [embed]}

def _build_slack_payload(title, desc, color, fields, server, ts):
    color_map = {"red": "danger", "orange": "warning", "green": "good", "blue": "#4444FF"}
    attachment = {
        "fallback": f"{title}: {desc}",
        "color": color_map.get(color, color),
        "title": f"🛡️ {title}",
        "text": desc,
        "footer": f"{server} • {ts}",
        "fields": []
    }
    if fields:
        for f in fields:
            attachment["fields"].append({
                "title": f.get("name", ""),
                "value": f.get("value", ""),
                "short": f.get("inline", True)
            })
    return {"attachments": [attachment]}

def _build_generic_payload(title, desc, color, fields, server, ts):
    return {
        "event": "khydrawall_alert",
        "title": title,
        "description": desc,
        "severity": color,
        "server": server,
        "timestamp": ts,
        "fields": fields or []
    }

def alert_attack_detected(pps: float, drop_type: str, details: str = ""):
    """Send alert for detected attack."""
    config = load_webhook_config()
    if not config.get("notify_attacks", True):
        return
    
    send_webhook_alert(
        title="⚠️ Attack Detected!",
        description=f"High packet drop rate detected: **{pps:,.0f} drops/sec**",
        color="red",
        fields=[
            {"name": "Type", "value": drop_type, "inline": True},
            {"name": "Rate", "value": f"{pps:,.0f}/s", "inline": True},
            {"name": "Details", "value": details or "Automatic mitigation active", "inline": False},
        ]
    )

def alert_ip_blocked(ip: str, reason: str = "Manual"):
    """Send alert when IP is blacklisted."""
    config = load_webhook_config()
    if not config.get("notify_blacklist", True):
        return
    
    send_webhook_alert(
        title="🚫 IP Blocked",
        description=f"IP address added to blacklist",
        color="orange",
        fields=[
            {"name": "IP Address", "value": f"`{ip}`", "inline": True},
            {"name": "Reason", "value": reason, "inline": True},
        ]
    )

def alert_service_status(status: str, details: str = ""):
    """Send alert on service start/stop."""
    config = load_webhook_config()
    if not config.get("notify_start_stop", True):
        return
    
    is_start = status.lower() == "started"
    send_webhook_alert(
        title="✅ Protection Started" if is_start else "⛔ Protection Stopped",
        description=f"khydrawall protection has been {status.lower()}",
        color="green" if is_start else "red",
        fields=[
            {"name": "Status", "value": status, "inline": True},
            {"name": "Details", "value": (details or "All layers active") if is_start else (details or "Server unprotected"), "inline": True},
        ]
    )

# ─── Dependency Checks ────────────────────────────────────────────────────────

REQUIRED_TOOLS = {
    "iptables":  "iptables",
    "ipset":     "ipset",
    "ip":        "iproute2",
    "bpftool":   "linux-tools-common linux-tools-$(uname -r)",
    "clang":     "clang",
    "llc":       "llvm",
}

def check_dependencies() -> bool:
    missing = []
    for tool, pkg in REQUIRED_TOOLS.items():
        if not shutil.which(tool):
            missing.append((tool, pkg))
    if missing:
        log("ERROR", "Missing dependencies:")
        for tool, pkg in missing:
            print(f"    {R}✗{NC}  {tool}  →  sudo apt install {pkg}")
        return False
    log("INFO", "All dependencies satisfied.")
    return True

# ─── Layer 1: XDP/eBPF ───────────────────────────────────────────────────────

def compile_xdp() -> bool:
    """Compile xdp_filter.c → xdp_filter.o"""
    src = XDP_SRC
    if not src.exists():
        log("WARN", "xdp_filter.c not found — XDP layer disabled.")
        return False

    BASE_DIR.mkdir(parents=True, exist_ok=True)

    # Detect kernel include path
    uname = run("uname -r", capture=True, check=False).stdout.strip()
    kernel_inc = f"/usr/src/linux-headers-{uname}/include"
    if not Path(kernel_inc).exists():
        kernel_inc = "/usr/include"

    cmd = (
        f"clang -O2 -target bpf "
        f"-I{kernel_inc} "
        f"-I/usr/include/x86_64-linux-gnu "
        f"-c {src} -o {XDP_OBJ}"
    )
    log("INFO", f"Compiling XDP program: {cmd}")
    result = run(cmd, check=False, capture=True)
    if result.returncode != 0:
        log("WARN", f"XDP compile failed: {result.stderr.strip()}")
        log("WARN", "Continuing without XDP layer.")
        return False
    log("INFO", f"XDP object compiled → {XDP_OBJ}")
    return True

def attach_xdp(iface: str) -> str:
    """Try native XDP, fall back to xdpgeneric. Returns mode string."""
    if not XDP_OBJ.exists():
        return ""

    # Detach any existing XDP program first
    run(f"ip link set dev {iface} xdp off", check=False)

    # Try native (fastest)
    r = run(f"ip link set dev {iface} xdp obj {XDP_OBJ} sec xdp",
            check=False, capture=True)
    if r.returncode == 0:
        log("INFO", f"XDP attached in {G}NATIVE{NC} mode on {iface}")
        return "native"

    # Fall back to generic
    r = run(f"ip link set dev {iface} xdpgeneric obj {XDP_OBJ} sec xdp",
            check=False, capture=True)
    if r.returncode == 0:
        log("INFO", f"XDP attached in {Y}GENERIC{NC} mode on {iface}")
        return "generic"

    log("WARN", f"XDP attach failed: {r.stderr.strip()}")
    return ""

def detach_xdp(iface: str):
    run(f"ip link set dev {iface} xdp off", check=False)
    run(f"ip link set dev {iface} xdpgeneric off", check=False)
    log("INFO", f"XDP detached from {iface}")

def xdp_populate_whitelist(ips: list[str]):
    """Push whitelist IPs into the BPF map via bpftool."""
    if not shutil.which("bpftool"):
        return
    for ip in ips:
        try:
            packed = int(ipaddress.IPv4Address(ip))
            # bpftool expects hex key in little-endian for network byte order
            hex_key = format(socket.htonl(packed), "08x")
            run(f"bpftool map update name ip_whitelist key hex {' '.join(hex_key[i:i+2] for i in range(0,8,2))} value hex 01 any",
                check=False, capture=True)
        except Exception:
            pass

def xdp_populate_blacklist(ips: list[str]):
    if not shutil.which("bpftool"):
        return
    for ip in ips:
        try:
            packed = int(ipaddress.IPv4Address(ip))
            hex_key = format(socket.htonl(packed), "08x")
            run(f"bpftool map update name ip_blacklist key hex {' '.join(hex_key[i:i+2] for i in range(0,8,2))} value hex 01 any",
                check=False, capture=True)
        except Exception:
            pass

# ─── Layer 2: iptables mangle ─────────────────────────────────────────────────

def setup_mangle(whitelist: list[str]):
    log("INFO", "Setting up Layer 2 — iptables mangle (pre-routing scrub)…")

    cmds = [
        # Flush existing mangle PREROUTING rules we own
        "iptables -t mangle -F PREROUTING 2>/dev/null || true",

        # ── Whitelist bypass ─────────────────────────────────────────────────
        *[f"iptables -t mangle -A PREROUTING -s {ip} -j ACCEPT" for ip in whitelist],

        # ── Bogus TCP flags ──────────────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN     -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG     -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE        -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL         -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP",

        # ── Bogus SYN packets ────────────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -p tcp ! --syn -m state --state NEW -j DROP",
        "iptables -t mangle -A PREROUTING -p tcp -m state --state INVALID     -j DROP",

        # ── MSS spoofing / tiny SYN ──────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -p tcp --syn -m length --length 0:40 -j DROP",

        # ── IP fragment attacks ──────────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -f -j DROP",

        # ── Private / spoofed source IPs on public interfaces ───────────────
        # (soft: LOG before DROP to avoid breaking LAN setups)
        "iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP",
        "iptables -t mangle -A PREROUTING -s 192.0.2.0/24   -j DROP",
        "iptables -t mangle -A PREROUTING -s 198.51.100.0/24 -j DROP",
        "iptables -t mangle -A PREROUTING -s 203.0.113.0/24  -j DROP",
        "iptables -t mangle -A PREROUTING -s 240.0.0.0/5     -j DROP",
        "iptables -t mangle -A PREROUTING -s 0.0.0.0/8       -j DROP",

        # ── Limit ICMP ───────────────────────────────────────────────────────
        "iptables -t mangle -A PREROUTING -p icmp -m hashlimit "
            "--hashlimit-upto 5/s --hashlimit-burst 10 "
            "--hashlimit-mode srcip --hashlimit-name icmp_pre -j ACCEPT",
        "iptables -t mangle -A PREROUTING -p icmp -j DROP",
    ]

    for cmd in cmds:
        run(cmd, check=False)

    log("INFO", f"  {G}✓{NC} Mangle/PREROUTING rules applied.")

def teardown_mangle():
    run("iptables -t mangle -F PREROUTING 2>/dev/null || true", check=False)
    log("INFO", "Layer 2 mangle rules removed.")

# ─── Layer 3: ipset blacklist ─────────────────────────────────────────────────

IPSET_BL = "khydrawall_blacklist"
IPSET_WL = "khydrawall_whitelist"

def setup_ipset(whitelist: list[str], blacklist: list[str]):
    log("INFO", "Setting up Layer 3 — ipset hash:ip lists…")

    # Destroy & recreate
    run(f"ipset destroy {IPSET_BL} 2>/dev/null || true", check=False)
    run(f"ipset destroy {IPSET_WL} 2>/dev/null || true", check=False)
    run(f"ipset create {IPSET_BL} hash:ip maxelem 1000000 hashsize 65536 timeout 0", check=False)
    run(f"ipset create {IPSET_WL} hash:ip maxelem 65536  hashsize 4096   timeout 0", check=False)

    # Populate whitelist set
    for ip in whitelist:
        run(f"ipset add {IPSET_WL} {ip} 2>/dev/null || true", check=False)

    # Populate blacklist set
    for ip in blacklist:
        run(f"ipset add {IPSET_BL} {ip} 2>/dev/null || true", check=False)

    # iptables rules referencing the sets
    run(f"iptables -I INPUT 1 -m set --match-set {IPSET_WL} src -j ACCEPT")
    run(f"iptables -I INPUT 2 -m set --match-set {IPSET_BL} src -j DROP")

    log("INFO", f"  {G}✓{NC} ipset lists created  "
                f"(whitelist={len(whitelist)}, blacklist={len(blacklist)} IPs).")

def teardown_ipset():
    run(f"iptables -D INPUT -m set --match-set {IPSET_WL} src -j ACCEPT 2>/dev/null || true", check=False)
    run(f"iptables -D INPUT -m set --match-set {IPSET_BL} src -j DROP   2>/dev/null || true", check=False)
    run(f"ipset destroy {IPSET_BL} 2>/dev/null || true", check=False)
    run(f"ipset destroy {IPSET_WL} 2>/dev/null || true", check=False)
    log("INFO", "Layer 3 ipset lists removed.")

# ─── Layer 4: Application Chains ─────────────────────────────────────────────

def setup_application_chains(whitelist: list[str]):
    log("INFO", "Setting up Layer 4 — application flood-guard chains…")

    def ipt(cmd):
        run(f"iptables {cmd}", check=False)

    # Flush & recreate custom chains
    for chain in ["TCP_FLOOD", "UDP_FLOOD", "ICMP_GUARD"]:
        ipt(f"-N {chain} 2>/dev/null || true")
        ipt(f"-F {chain}")

    # ── Whitelist bypass in INPUT ────────────────────────────────────────────
    for ip in whitelist:
        ipt(f"-I INPUT -s {ip} -j ACCEPT")

    # ── Allow established/related ────────────────────────────────────────────
    ipt("-I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT")
    ipt("-I INPUT 2 -i lo -j ACCEPT")

    # ── SSH — open to all, no whitelist restriction ──────────────────────────
    ipt("-A INPUT -p tcp --dport 22 -j ACCEPT")

    # ── HTTP / HTTPS / Custom web ports ──────────────────────────────────────
    for port in ["80", "443", "20080"]:
        ipt(f"-A INPUT -p tcp --dport {port} -j ACCEPT")

    # ── Custom UDP ports (BEFORE flood chains) ────────────────────────────────
    for port in ["22126", "22129", "22132", "22135", "22138", "22141", "22144", "22153"]:
        ipt(f"-A INPUT -p udp --dport {port} -j ACCEPT")

    # ── Custom UDP game/app ports ─────────────────────────────────────────────
    for port in ["22003", "22006", "22009", "22012", "22015", "22018", "22021", "22030"]:
        ipt(f"-A INPUT -p udp --dport {port} -j ACCEPT")

    # ── Custom TCP game/app ports ─────────────────────────────────────────────
    for port in ["22006", "22009", "22012", "22015", "22018", "22021", "22024", "22033"]:
        ipt(f"-A INPUT -p tcp --dport {port} -j ACCEPT")

    # ── Dispatch to sub-chains ───────────────────────────────────────────────
    ipt("-A INPUT -p tcp  -j TCP_FLOOD")
    ipt("-A INPUT -p udp  -j UDP_FLOOD")
    ipt("-A INPUT -p icmp -j ICMP_GUARD")

    # ── TCP_FLOOD chain ──────────────────────────────────────────────────────
    # SYN flood — limit new connections per source IP
    ipt("-A TCP_FLOOD -p tcp --syn "
        "-m hashlimit --hashlimit-upto 100/s --hashlimit-burst 200 "
        "--hashlimit-mode srcip --hashlimit-name syn_flood "
        "-j ACCEPT")
    ipt("-A TCP_FLOOD -p tcp --syn -j DROP")

    # ACK flood — limit ACK packets per source IP
    ipt("-A TCP_FLOOD -p tcp --tcp-flags ACK ACK "
        "-m hashlimit --hashlimit-upto 1000/s --hashlimit-burst 2000 "
        "--hashlimit-mode srcip --hashlimit-name ack_flood "
        "-j ACCEPT")
    ipt("-A TCP_FLOOD -p tcp --tcp-flags ACK ACK -j DROP")

    # RST flood — limit RST packets per source IP
    ipt("-A TCP_FLOOD -p tcp --tcp-flags RST RST "
        "-m hashlimit --hashlimit-upto 10/s --hashlimit-burst 20 "
        "--hashlimit-mode srcip --hashlimit-name rst_flood "
        "-j ACCEPT")
    ipt("-A TCP_FLOOD -p tcp --tcp-flags RST RST -j DROP")

    ipt("-A TCP_FLOOD -j ACCEPT")

    # ── UDP_FLOOD chain ──────────────────────────────────────────────────────
    # Block UDP amplification source ports (reflected traffic)
    AMPLIFICATION_PORTS = [
        19,    # Chargen
        111,   # portmap
        123,   # NTP
        137,   # NetBIOS
        161,   # SNMP
        389,   # LDAP
        1900,  # SSDP/UPnP
        3702,  # WSD
        11211, # Memcached
        27015, # Steam/Source
    ]
    for port in AMPLIFICATION_PORTS:
        ipt(f"-A UDP_FLOOD -p udp --sport {port} -j DROP")

    # DNS — limit tightly if this server is not a DNS server
    ipt("-A UDP_FLOOD -p udp --dport 53 "
        "-m hashlimit --hashlimit-upto 5/s --hashlimit-burst 10 "
        "--hashlimit-mode srcip --hashlimit-name udp_dns "
        "-j ACCEPT")
    ipt("-A UDP_FLOOD -p udp --dport 53 -j DROP")

    # General UDP — limit per source IP
    ipt("-A UDP_FLOOD -p udp "
        "-m hashlimit --hashlimit-upto 500/s --hashlimit-burst 1000 "
        "--hashlimit-mode srcip --hashlimit-name udp_generic "
        "-j ACCEPT")
    ipt("-A UDP_FLOOD -p udp -j DROP")

    # ── ICMP_GUARD chain ─────────────────────────────────────────────────────
    # Limit echo-request per source IP
    ipt("-A ICMP_GUARD -p icmp --icmp-type echo-request "
        "-m hashlimit --hashlimit-upto 2/s --hashlimit-burst 10 "
        "--hashlimit-mode srcip --hashlimit-name icmp_guard "
        "-j ACCEPT")
    ipt("-A ICMP_GUARD -p icmp --icmp-type echo-reply   -j ACCEPT")
    ipt("-A ICMP_GUARD -p icmp --icmp-type 3            -j ACCEPT")  # unreachable
    ipt("-A ICMP_GUARD -p icmp --icmp-type 11           -j ACCEPT")  # TTL exceeded
    ipt("-A ICMP_GUARD -p icmp -j DROP")

    log("INFO", f"  {G}✓{NC} TCP_FLOOD / UDP_FLOOD / ICMP_GUARD chains active.")

def teardown_application_chains():
    def ipt(cmd):
        run(f"iptables {cmd}", check=False)

    # Remove explicit INPUT rules added at startup
    ipt("-D INPUT -p tcp --dport 22    -j ACCEPT 2>/dev/null || true")
    for port in ["80", "443", "20080"]:
        ipt(f"-D INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null || true")
    for port in ["22126", "22129", "22132", "22135", "22138", "22141", "22144", "22153"]:
        ipt(f"-D INPUT -p udp --dport {port} -j ACCEPT 2>/dev/null || true")
    for port in ["22003", "22006", "22009", "22012", "22015", "22018", "22021", "22030"]:
        ipt(f"-D INPUT -p udp --dport {port} -j ACCEPT 2>/dev/null || true")
    for port in ["22006", "22009", "22012", "22015", "22018", "22021", "22024", "22033"]:
        ipt(f"-D INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null || true")

    # Remove chain jumps and destroy custom chains
    for chain in ["TCP_FLOOD", "UDP_FLOOD", "ICMP_GUARD"]:
        ipt(f"-D INPUT -p tcp  -j {chain} 2>/dev/null || true")
        ipt(f"-D INPUT -p udp  -j {chain} 2>/dev/null || true")
        ipt(f"-D INPUT -p icmp -j {chain} 2>/dev/null || true")
        ipt(f"-F {chain} 2>/dev/null || true")
        ipt(f"-X {chain} 2>/dev/null || true")

    log("INFO", "Layer 4 application chains removed.")

# ─── Kernel Hardening (sysctl) ────────────────────────────────────────────────

SYSCTL_SETTINGS = {
    "net.ipv4.tcp_syncookies":           "1",
    "net.ipv4.tcp_syn_retries":          "2",
    "net.ipv4.tcp_synack_retries":       "2",
    "net.ipv4.tcp_max_syn_backlog":      "4096",
    "net.ipv4.conf.all.rp_filter":       "1",   # reverse-path filtering
    "net.ipv4.conf.default.rp_filter":   "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects":   "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.log_martians":    "1",
    "net.ipv4.tcp_rfc1337":             "1",
    "net.ipv4.tcp_fin_timeout":         "15",
    "net.ipv4.tcp_keepalive_time":      "300",
    "net.ipv4.tcp_keepalive_probes":    "5",
    "net.ipv4.tcp_keepalive_intvl":     "15",
}

def apply_sysctl():
    log("INFO", "Applying kernel hardening (sysctl)…")
    for key, val in SYSCTL_SETTINGS.items():
        run(f"sysctl -w {key}={val}", check=False, capture=True)
    log("INFO", f"  {G}✓{NC} sysctl hardening applied.")

def restore_sysctl():
    # Restore all changed settings back to kernel defaults
    restore_map = {
        "net.ipv4.tcp_syncookies":                    "1",
        "net.ipv4.tcp_syn_retries":                   "6",
        "net.ipv4.tcp_synack_retries":                "5",
        "net.ipv4.tcp_max_syn_backlog":               "128",
        "net.ipv4.conf.all.rp_filter":                "1",
        "net.ipv4.conf.default.rp_filter":            "1",
        "net.ipv4.icmp_echo_ignore_broadcasts":       "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "net.ipv4.conf.all.accept_redirects":         "1",
        "net.ipv4.conf.all.send_redirects":           "1",
        "net.ipv4.conf.all.accept_source_route":      "0",
        "net.ipv4.conf.all.log_martians":             "0",
        "net.ipv4.tcp_rfc1337":                       "0",
        "net.ipv4.tcp_fin_timeout":                   "60",
        "net.ipv4.tcp_keepalive_time":                "7200",
        "net.ipv4.tcp_keepalive_probes":              "9",
        "net.ipv4.tcp_keepalive_intvl":               "75",
    }
    for key, val in restore_map.items():
        run(f"sysctl -w {key}={val}", check=False, capture=True)
    log("INFO", "sysctl settings restored to defaults.")

# ─── Main CLI Commands ────────────────────────────────────────────────────────

def cmd_start(args):
    require_root()
    banner()

    state = load_state()
    if state.get("running"):
        log("WARN", "khydrawall is already running. Use --stop first.")
        sys.exit(1)

    BASE_DIR.mkdir(parents=True, exist_ok=True)

    # Initialise config files if absent
    if not WHITELIST_FILE.exists():
        WHITELIST_FILE.write_text("# khydrawall Whitelist — one IP per line\n")
    if not BLACKLIST_FILE.exists():
        BLACKLIST_FILE.write_text("# khydrawall Blacklist — one IP per line\n")

    # Safety: auto-whitelist current SSH session IP
    ssh_ip = get_ssh_client_ip()
    if ssh_ip:
        whitelist_add_ip(ssh_ip, silent=True)
        log("INFO", f"Auto-whitelisted SSH session IP: {C}{ssh_ip}{NC}")
    else:
        log("WARN", "Could not detect SSH session IP — ensure your IP is in whitelist.conf.")

    iface = getattr(args, "interface", None) or get_default_interface()
    log("INFO", f"Using network interface: {C}{iface}{NC}")

    whitelist = load_whitelist()
    blacklist = load_blacklist()

    log("INFO", f"Whitelist: {len(whitelist)} IPs  |  Blacklist: {len(blacklist)} IPs")

    # ── Layer 1: XDP ──────────────────────────────────────────────────────────
    xdp_mode = ""
    if not args.no_xdp:
        compiled = compile_xdp()
        if compiled:
            xdp_mode = attach_xdp(iface)
            if xdp_mode:
                xdp_populate_whitelist(whitelist)
                xdp_populate_blacklist(blacklist)

    # ── Layer 2: mangle ───────────────────────────────────────────────────────
    apply_sysctl()
    setup_mangle(whitelist)

    # ── Layer 3: ipset ────────────────────────────────────────────────────────
    setup_ipset(whitelist, blacklist)

    # ── Layer 4: application chains ───────────────────────────────────────────
    setup_application_chains(whitelist)

    save_state({"running": True, "interface": iface, "xdp_mode": xdp_mode,
                "started": time.strftime("%Y-%m-%d %H:%M:%S")})

    print(f"\n  {G}{BOLD}khydrawall protection ACTIVE{NC}")
    print(f"  {'Layer':<10} {'Status':<12} {'Details'}")
    print(f"  {'─'*50}")
    xdp_label = f"{G}✓ {xdp_mode.upper()}{NC}" if xdp_mode else f"{Y}⚠ SKIPPED{NC}"
    print(f"  {'XDP':<10} {xdp_label:<30} driver-level packet filter")
    print(f"  {'Mangle':<10} {G}✓ ACTIVE{NC:<30} bogus-flag scrubber")
    print(f"  {'ipset':<10} {G}✓ ACTIVE{NC:<30} O(1) IP blacklist ({len(blacklist)} IPs)")
    print(f"  {'Chains':<10} {G}✓ ACTIVE{NC:<30} flood/brute-force guards")
    print()
    
    # Send webhook notification
    alert_service_status("Started", f"XDP: {xdp_mode or 'disabled'}, Interface: {iface}")

def cmd_stop(args):
    require_root()
    state = load_state()
    iface = state.get("interface") or get_default_interface()

    log("INFO", "Stopping khydrawall protection…")

    detach_xdp(iface)
    teardown_mangle()
    teardown_ipset()
    teardown_application_chains()
    restore_sysctl()

    save_state({"running": False, "interface": "", "xdp_mode": ""})
    log("INFO", f"{G}All layers deactivated. Server is unprotected.{NC}")
    
    # Send webhook notification
    alert_service_status("Stopped", "All protection layers deactivated")

def cmd_status(args):
    state = load_state()
    running = state.get("running", False)
    banner()

    status_str = f"{G}ACTIVE{NC}" if running else f"{R}INACTIVE{NC}"
    print(f"  Status   : {BOLD}{status_str}{NC}")
    if running:
        print(f"  Interface: {C}{state.get('interface')}{NC}")
        print(f"  XDP Mode : {state.get('xdp_mode') or 'disabled'}")
        print(f"  Started  : {state.get('started', 'unknown')}")
        print()

    whitelist = load_whitelist()
    blacklist  = load_blacklist()
    print(f"  Whitelist IPs : {len(whitelist)}")
    print(f"  Blacklist IPs : {len(blacklist)}")

    if whitelist:
        print(f"\n  {C}Whitelisted:{NC}")
        for ip in whitelist[:10]:
            print(f"    {G}✓{NC}  {ip}")
        if len(whitelist) > 10:
            print(f"    … and {len(whitelist)-10} more")

    if blacklist:
        print(f"\n  {R}Blacklisted:{NC}")
        for ip in blacklist[:10]:
            print(f"    {R}✗{NC}  {ip}")
        if len(blacklist) > 10:
            print(f"    … and {len(blacklist)-10} more")

    # iptables chain stats
    print(f"\n  {B}iptables DROP counters:{NC}")
    r = run("iptables -L INPUT -v -n --line-numbers 2>/dev/null",
            capture=True, check=False)
    if r.stdout:
        lines = r.stdout.strip().splitlines()
        for line in lines:
            if "DROP" in line or "Chain" in line or "pkts" in line:
                print(f"    {DIM}{line}{NC}")
    print()

def whitelist_add_ip(ip: str, silent=False):
    if not validate_ip(ip):
        if not silent:
            log("ERROR", f"Invalid IP address: {ip}")
        return False
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    WHITELIST_FILE.touch(exist_ok=True)
    existing = WHITELIST_FILE.read_text()
    if ip in existing.splitlines():
        if not silent:
            log("INFO", f"{ip} already in whitelist.")
        return True
    with open(WHITELIST_FILE, "a") as f:
        f.write(f"{ip}\n")
    if not silent:
        log("INFO", f"Added {G}{ip}{NC} to whitelist.")

    # Live update if running
    state = load_state()
    if state.get("running"):
        run(f"ipset add {IPSET_WL} {ip} 2>/dev/null || true", check=False)
        # Also remove from blacklist if present
        run(f"ipset del {IPSET_BL} {ip} 2>/dev/null || true", check=False)
        if not silent:
            log("INFO", "Live-updated running ipset.")
    return True

def cmd_whitelist_add(args):
    require_root()
    whitelist_add_ip(args.ip)

def cmd_blacklist_add(args):
    require_root()
    ip = args.ip
    if not validate_ip(ip):
        log("ERROR", f"Invalid IP address: {ip}")
        sys.exit(1)
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    BLACKLIST_FILE.touch(exist_ok=True)
    existing = BLACKLIST_FILE.read_text()
    if ip in existing.splitlines():
        log("INFO", f"{ip} already in blacklist.")
        return
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")
    log("INFO", f"Added {R}{ip}{NC} to blacklist.")

    state = load_state()
    if state.get("running"):
        run(f"ipset add {IPSET_BL} {ip} 2>/dev/null || true", check=False)
        log("INFO", "Live-updated running ipset.")
    
    # Send webhook notification
    alert_ip_blocked(ip, "Manual blacklist")

def cmd_blacklist_remove(args):
    require_root()
    ip = args.ip
    if not validate_ip(ip):
        log("ERROR", f"Invalid IP address: {ip}")
        sys.exit(1)
    if BLACKLIST_FILE.exists():
        lines = [l for l in BLACKLIST_FILE.read_text().splitlines() if l.strip() != ip]
        BLACKLIST_FILE.write_text("\n".join(lines) + "\n")
    run(f"ipset del {IPSET_BL} {ip} 2>/dev/null || true", check=False)
    log("INFO", f"Removed {ip} from blacklist.")

# ─── Live Monitor ─────────────────────────────────────────────────────────────

class Monitor:
    """Real-time stats display: PPS, bandwidth, drop counters."""

    CLEAR = "\033[2J\033[H"

    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self._prev_rx = 0
        self._prev_tx = 0
        self._prev_ts = 0.0
        self._iface   = load_state().get("interface") or get_default_interface()
        signal.signal(signal.SIGINT, self._handle_exit)
        
        # Attack detection state
        self._prev_xdp_stats = {"bl_drops": 0, "flag_drops": 0, "frag_drops": 0, "total": 0}
        self._webhook_config = load_webhook_config()

    def _handle_exit(self, *_):
        print(f"\n\n  {Y}Monitor stopped.{NC}\n")
        sys.exit(0)

    def _check_attack_threshold(self, current_xdp: dict, dt: float):
        """Check if drop rate exceeds threshold and send alert."""
        if not self._webhook_config.get("enabled"):
            return
        
        threshold = self._webhook_config.get("alert_threshold_pps", 1000)
        
        # Calculate drops per second
        bl_dps = (current_xdp["bl_drops"] - self._prev_xdp_stats["bl_drops"]) / dt
        flag_dps = (current_xdp["flag_drops"] - self._prev_xdp_stats["flag_drops"]) / dt
        frag_dps = (current_xdp["frag_drops"] - self._prev_xdp_stats["frag_drops"]) / dt
        
        total_dps = bl_dps + flag_dps + frag_dps
        
        if total_dps >= threshold:
            # Determine attack type
            if bl_dps > flag_dps and bl_dps > frag_dps:
                attack_type = "Blacklisted IP flood"
            elif flag_dps > frag_dps:
                attack_type = "TCP flag attack (NULL/XMAS/SYN+FIN)"
            else:
                attack_type = "Fragment attack"
            
            alert_attack_detected(
                pps=total_dps,
                drop_type=attack_type,
                details=f"BL: {bl_dps:.0f}/s, Flags: {flag_dps:.0f}/s, Frag: {frag_dps:.0f}/s"
            )
        
        # Update previous stats
        self._prev_xdp_stats = current_xdp.copy()

    def _read_net_stats(self) -> tuple[int, int, int, int]:
        """Returns (rx_bytes, rx_packets, tx_bytes, tx_packets)."""
        path = Path(f"/sys/class/net/{self._iface}/statistics")
        try:
            rx_b = int((path / "rx_bytes").read_text())
            rx_p = int((path / "rx_packets").read_text())
            tx_b = int((path / "tx_bytes").read_text())
            tx_p = int((path / "tx_packets").read_text())
            return rx_b, rx_p, tx_b, tx_p
        except Exception:
            return 0, 0, 0, 0

    def _get_iptables_drops(self) -> dict[str, int]:
        drops = {}
        r = run("iptables -L INPUT -v -n 2>/dev/null", capture=True, check=False)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and "DROP" in parts:
                idx = parts.index("DROP")
                try:
                    drops[" ".join(parts[idx+1:idx+4])] = int(parts[0].replace("K", "000").replace("M", "000000"))
                except (ValueError, IndexError):
                    pass
        return drops

    def _get_xdp_stats(self) -> dict[str, int]:
        """Read per-CPU counters from BPF map via bpftool."""
        stats = {"bl_drops": 0, "flag_drops": 0, "frag_drops": 0, "total": 0}
        if not shutil.which("bpftool"):
            return stats
        r = run("bpftool map dump name xdp_stats 2>/dev/null", capture=True, check=False)
        # Parse JSON output
        try:
            data = json.loads(r.stdout)
            for entry in data:
                key = entry.get("key", [0])[0]
                val = sum(entry.get("values", [0]))
                if key == 0:   stats["bl_drops"]   = val
                elif key == 1: stats["flag_drops"]  = val
                elif key == 2: stats["frag_drops"]  = val
                elif key == 3: stats["total"]       = val
        except Exception:
            pass
        return stats

    def _get_blocked_ips(self, n=10) -> list[str]:
        r = run(f"ipset list {IPSET_BL} 2>/dev/null | tail -{n}",
                capture=True, check=False)
        return [l.strip() for l in r.stdout.splitlines() if validate_ip(l.strip())]

    def _fmt_bytes(self, b: float) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f} {unit}/s"
            b /= 1024
        return f"{b:.1f} TB/s"

    def run(self):
        print(f"\n  {C}Live monitor starting — press {BOLD}Ctrl+C{NC}{C} to quit{NC}\n")
        rx_b0, rx_p0, tx_b0, tx_p0 = self._read_net_stats()
        t0 = time.time()

        while True:
            time.sleep(self.interval)
            rx_b1, rx_p1, tx_b1, tx_p1 = self._read_net_stats()
            t1 = time.time()
            dt = t1 - t0 or 1

            rx_bps = max(0, rx_b1 - rx_b0) / dt
            tx_bps = max(0, tx_b1 - tx_b0) / dt
            rx_pps = max(0, rx_p1 - rx_p0) / dt
            tx_pps = max(0, tx_p1 - tx_p0) / dt

            rx_b0, rx_p0, tx_b0, tx_p0 = rx_b1, rx_p1, tx_b1, tx_p1
            t0 = t1

            xdp   = self._get_xdp_stats()
            bl_ips = self._get_blocked_ips(8)
            
            # Check for attacks and send webhook alerts
            self._check_attack_threshold(xdp, dt)

            ts = time.strftime("%H:%M:%S")
            print(self.CLEAR, end="")
            print(f"""
{B}{BOLD} ╔══════════════════════════════════════════════════════════╗
 ║   khydrawall Live Monitor  ·  {ts}  ·  iface: {self._iface:<6}    ║
 ╚══════════════════════════════════════════════════════════╝{NC}

 {BOLD}Traffic{NC}
  ↓ Inbound  : {G}{self._fmt_bytes(rx_bps):<18}{NC}  {rx_pps:>8.0f} pps
  ↑ Outbound : {C}{self._fmt_bytes(tx_bps):<18}{NC}  {tx_pps:>8.0f} pps

 {BOLD}XDP Drop Counters{NC}
  Blacklist  drops : {R}{xdp['bl_drops']:>12,}{NC}
  Bad-flags  drops : {R}{xdp['flag_drops']:>12,}{NC}
  Fragment   drops : {R}{xdp['frag_drops']:>12,}{NC}
  Total      seen  : {DIM}{xdp['total']:>12,}{NC}

 {BOLD}Currently Blocked IPs (last {len(bl_ips)}){NC}""")

            if bl_ips:
                for ip in bl_ips:
                    print(f"  {R}✗{NC}  {ip}")
            else:
                print(f"  {DIM}(none){NC}")

            state = load_state()
            prot = f"{G}ACTIVE{NC}" if state.get("running") else f"{R}INACTIVE{NC}"
            print(f"\n  Protection: {BOLD}{prot}{NC}  |  "
                  f"XDP: {state.get('xdp_mode') or 'off'}  |  "
                  f"[Ctrl+C to quit]")

def cmd_monitor(args):
    Monitor(interval=float(getattr(args, "interval", 1.0))).run()

# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="khydrawall",
        description="4-Layer khydrawall Protection for Ubuntu VPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 khydrawall.py --start
  sudo python3 khydrawall.py --start --interface eth0
  sudo python3 khydrawall.py --stop
  sudo python3 khydrawall.py --status
  sudo python3 khydrawall.py --monitor
  sudo python3 khydrawall.py --whitelist-add 1.2.3.4
  sudo python3 khydrawall.py --blacklist-add 5.6.7.8
  sudo python3 khydrawall.py --blacklist-remove 5.6.7.8
  sudo python3 khydrawall.py --check-deps
  
  # Webhook commands
  sudo python3 khydrawall.py --webhook-set URL [--webhook-type discord|slack|generic]
  sudo python3 khydrawall.py --webhook-test
  sudo python3 khydrawall.py --webhook-status
  sudo python3 khydrawall.py --webhook-disable
"""
    )

    p.add_argument("--start",            action="store_true", help="Activate all 4 protection layers")
    p.add_argument("--stop",             action="store_true", help="Deactivate all layers")
    p.add_argument("--status",           action="store_true", help="Show current protection status")
    p.add_argument("--monitor",          action="store_true", help="Live traffic & drop stats")
    p.add_argument("--whitelist-add",    metavar="IP",        help="Add IP to whitelist (bypasses all layers)")
    p.add_argument("--blacklist-add",    metavar="IP",        help="Add IP to blacklist")
    p.add_argument("--blacklist-remove", metavar="IP",        help="Remove IP from blacklist")
    p.add_argument("--check-deps",       action="store_true", help="Check required dependencies")
    p.add_argument("--interface",        metavar="IFACE",     help="Network interface (default: auto-detect)")
    p.add_argument("--no-xdp",          action="store_true", help="Skip Layer 1 XDP (iptables only)")
    p.add_ar
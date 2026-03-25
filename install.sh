#!/usr/bin/env bash
# install.sh — khydrawall dependency installer & setup
# Authors: semihyurur (khydra)
# Run as root: sudo bash install.sh

set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "  ${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "  ${RED}[ERROR]${NC} $*"; }

[[ $EUID -ne 0 ]] && { error "Run as root: sudo bash install.sh"; exit 1; }

INSTALL_DIR="/opt/khydrawall"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\n${BOLD}${CYAN} khydrawall — Installer${NC}\n"

# ── 1. System update ──────────────────────────────────────────────────────────
info "Updating apt package lists…"
apt-get update -qq

# ── 2. Core tools ─────────────────────────────────────────────────────────────
info "Installing core packages…"
KERNEL=$(uname -r)
apt-get install -y -qq \
    iptables \
    ipset \
    iproute2 \
    python3 \
    python3-pip \
    clang \
    llvm \
    libelf-dev \
    linux-headers-"${KERNEL}" \
    linux-tools-"${KERNEL}" \
    linux-tools-common \
    linux-tools-generic \
    libbpf-dev \
    bpftrace \
    net-tools \
    procps \
    2>/dev/null || true

# ── 3. Verify bpftool ─────────────────────────────────────────────────────────
if ! command -v bpftool &>/dev/null; then
    warn "bpftool not found via package. Trying to build from source…"
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq linux-tools-"$(uname -r)" 2>/dev/null || \
        apt-get install -y -qq linux-tools-generic 2>/dev/null || true
    fi
fi

if command -v bpftool &>/dev/null; then
    info "bpftool: $(bpftool version 2>/dev/null | head -1)"
else
    warn "bpftool not available — XDP BPF map updates will be limited."
fi

# ── 4. Python dependencies ────────────────────────────────────────────────────
info "Python packages — none required (stdlib only)."

# ── 5. Enable required kernel modules ────────────────────────────────────────
info "Loading kernel modules…"
for mod in ip_tables ip_set ip_set_hash_ip xt_set xt_hashlimit xt_recent xt_state; do
    modprobe "$mod" 2>/dev/null || warn "Could not load module $mod (may be built-in)"
done

# ── 6. Copy files to install dir ─────────────────────────────────────────────
info "Installing to ${INSTALL_DIR}…"
mkdir -p "${INSTALL_DIR}"
cp "${SCRIPT_DIR}/khydrawall.py"   "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/xdp_filter.c"  "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/khydrawall.py"

# ── 7. Create symlink ─────────────────────────────────────────────────────────
ln -sf "${INSTALL_DIR}/khydrawall.py" /usr/local/bin/khydrawall
info "Symlink: /usr/local/bin/khydrawall → ${INSTALL_DIR}/khydrawall.py"

# ── 8. Create /etc/khydrawall config dir ───────────────────────────────────────
mkdir -p /etc/khydrawall
[[ -f /etc/khydrawall/whitelist.conf ]] || cat > /etc/khydrawall/whitelist.conf <<'EOF'
# khydrawall Whitelist — one IPv4 address per line
# IPs listed here bypass ALL four protection layers.
# Your SSH IP is auto-added when you run --start.
EOF

[[ -f /etc/khydrawall/blacklist.conf ]] || cat > /etc/khydrawall/blacklist.conf <<'EOF'
# khydrawall Blacklist — one IPv4 address per line
# IPs listed here are blocked at Layer 3 (ipset) and Layer 1 (XDP).
EOF

# ── 9. Compile XDP object ─────────────────────────────────────────────────────
info "Attempting XDP compilation…"
KERNEL_INC="/usr/src/linux-headers-${KERNEL}/include"
[[ -d "$KERNEL_INC" ]] || KERNEL_INC="/usr/include"

if clang -O2 -target bpf \
       -I"${KERNEL_INC}" \
       -I/usr/include/x86_64-linux-gnu \
       -c "${INSTALL_DIR}/xdp_filter.c" \
       -o /etc/khydrawall/xdp_filter.o 2>/dev/null; then
    info "XDP object compiled → /etc/khydrawall/xdp_filter.o"
else
    warn "XDP compilation failed. Layer 1 will be skipped until fixed."
    warn "Check: clang version, kernel headers, libbpf-dev."
fi

# ── 10. Systemd service (optional) ───────────────────────────────────────────
SERVICE_FILE="/etc/systemd/system/khydrawall.service"
cat > "$SERVICE_FILE" <<'SVCEOF'
[Unit]
Description=khydrawall
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/khydrawall --start
ExecStop=/usr/local/bin/khydrawall --stop
TimeoutStartSec=60
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
info "Systemd service installed: khydrawall.service"
info "  Enable on boot: sudo systemctl enable khydrawall"
info "  Start now:      sudo systemctl start khydrawall"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD} ✓ Installation complete!${NC}"
echo ""
echo -e "  ${CYAN}Quick start:${NC}"
echo "    sudo khydrawall --check-deps"
echo "    sudo khydrawall --start"
echo "    sudo khydrawall --status"
echo "    sudo khydrawall --monitor"
echo ""

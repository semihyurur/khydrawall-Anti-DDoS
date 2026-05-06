# khydrawall
A lightweight, production-ready DDoS mitigation tool for Linux VPS servers. Operates across four stacked protection layers from the driver level down to the application level.

## Architecture

```
Layer 1 — XDP/eBPF        ~100 ns   Driver-level packet drop (blacklist, bad flags, fragments)
Layer 2 — iptables mangle           Pre-routing bogus packet scrubber
Layer 3 — ipset hash:ip             O(1) million-IP blacklist
Layer 4 — Application chains        SYN/ACK/RST/UDP/ICMP flood guards
```

## Requirements

- Ubuntu 20.04+ (or Debian equivalent)
- Linux kernel 5.x+ (for XDP/eBPF support)
- Root access

**Dependencies** (installed automatically by `install.sh`):

```
iptables  ipset  iproute2  python3
clang  llvm  linux-headers  libbpf-dev  bpftrace
```

## Installation

```bash
sudo bash install.sh
```

This will install all dependencies, compile the XDP BPF program, create a systemd service, and set up config directories under `/etc/khydrawall/`.

## Usage

```bash
# Start all 4 protection layers
sudo khydrawall --start

# Start on a specific interface
sudo khydrawall --start --interface eth0

# Stop protection
sudo khydrawall --stop

# Show current status
sudo khydrawall --status

# Live traffic & drop monitor
sudo khydrawall --monitor

# Whitelist / Blacklist management
sudo khydrawall --whitelist-add 1.2.3.4
sudo khydrawall --blacklist-add 5.6.7.8
sudo khydrawall --blacklist-remove 5.6.7.8

# Check dependencies
sudo khydrawall --check-deps
```

## Webhook Alerts (Discord / Slack / Generic)

```bash
# Configure a Discord webhook
sudo khydrawall --webhook-set https://discord.com/api/webhooks/... --webhook-type discord

# Test the alert
sudo khydrawall --webhook-test

# View webhook config
sudo khydrawall --webhook-status

# Disable alerts
sudo khydrawall --webhook-disable
```

Alerts are sent for:
- Service start / stop
- IP blacklist additions
- High drop-rate attack detection

## Configuration Files

| File | Description |
|------|-------------|
| `/etc/khydrawall/whitelist.conf` | One IP per line — bypasses all layers |
| `/etc/khydrawall/blacklist.conf` | One IP per line — blocked at L1 and L3 |
| `/etc/khydrawall/webhook.conf`   | Webhook alert configuration (JSON) |
| `/etc/khydrawall/xdp_filter.o`  | Compiled XDP BPF object |
| `/etc/khydrawall/state.json`     | Runtime state |
| `/etc/khydrawall/khydrawall.log`   | Log file |

> **Note:** Your current SSH session IP is automatically added to the whitelist when you run `--start` to prevent lockouts.

## Systemd Service

```bash
sudo systemctl enable khydrawall   # Enable on boot
sudo systemctl start khydrawall    # Start now
sudo systemctl stop khydrawall     # Stop
sudo systemctl status khydrawall   # Check status
```

## What Each Layer Does

**Layer 1 — XDP/eBPF** (`xdp_filter.c`)  
Runs at the NIC driver level before the kernel network stack. Drops blacklisted IPs, malformed TCP flag combinations (NULL, XMAS, SYN+FIN, RST+SYN, FIN-without-ACK), and crafted IP fragments in ~100 ns.

**Layer 2 — iptables mangle**  
Pre-routing scrubber. Drops bogus TCP flags, invalid state packets, spoofed/private source IPs on public interfaces, and rate-limits ICMP.

**Layer 3 — ipset**  
Hash-based IP blacklist and whitelist supporting up to 1,000,000 entries with O(1) lookup. Live-updated without restarting protection.

**Layer 4 — Application chains**  
Custom iptables chains (`TCP_FLOOD`, `UDP_FLOOD`, `ICMP_GUARD`) with per-IP rate limiting via `hashlimit`. Blocks UDP amplification source ports (NTP, SNMP, Memcached, etc.).

## License

MIT © 2026 [semihyurur](https://github.com/semihyurur) (khydra) — see [LICENSE](LICENSE) for details.

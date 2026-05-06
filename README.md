# khydrawall

khydrawall is a lightweight 4-layer Anti-DDoS protection tool for Ubuntu VPS servers, combining XDP/eBPF packet filtering, iptables rules, ipset blacklists, kernel hardening, live traffic monitoring, and webhook notifications.

## Features

- XDP/eBPF packet filtering for early packet drops
- iptables mangle rules for malformed packet scrubbing
- ipset-based whitelist and blacklist management
- sysctl kernel hardening
- TCP, UDP, and ICMP flood guard chains
- Live traffic and drop monitoring
- Discord, Slack, and generic webhook alerts

## Requirements

- Ubuntu VPS or Debian-based server
- Root access
- Linux kernel with XDP/eBPF support
- `iptables`, `ipset`, `iproute2`, `clang`, `llvm`, `bpftool`, and kernel headers

## Installation

```bash
sudo bash install.sh
```

## Usage

```bash
sudo khydrawall --check-deps
sudo khydrawall --start
sudo khydrawall --status
sudo khydrawall --monitor
sudo khydrawall --stop
```

Whitelist and blacklist management:

```bash
sudo khydrawall --whitelist-add 1.2.3.4
sudo khydrawall --blacklist-add 5.6.7.8
sudo khydrawall --blacklist-remove 5.6.7.8
```

Webhook alerts:

```bash
sudo khydrawall --webhook-set WEBHOOK_URL --webhook-type discord
sudo khydrawall --webhook-test
sudo khydrawall --webhook-status
sudo khydrawall --webhook-disable
```

## Protection Layers

| Layer | Technology | Purpose |
| --- | --- | --- |
| Layer 1 | XDP/eBPF | Driver-level filtering for blacklisted IPs, bad TCP flags, and fragments |
| Layer 2 | iptables mangle | Pre-routing packet cleanup |
| Layer 3 | ipset | Fast whitelist and blacklist lookups |
| Layer 4 | iptables chains | TCP, UDP, and ICMP flood controls |

## License

MIT License. See [LICENSE](LICENSE) for details.

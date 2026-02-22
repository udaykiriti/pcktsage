# PacketSage

PacketSage is an intelligent network packet analyzer built in Rust.

It captures live traffic from network interfaces, parses protocol layers, applies filters, tracks traffic statistics, and raises basic IDS-style alerts. It also includes a real-time terminal dashboard, JSON output mode, and PCAP export for offline analysis.

## What This Project Does

- Captures live packets at Ethernet level
- Parses and labels:
  - Ethernet
  - IPv4
  - TCP
  - UDP
  - ARP
  - IPv6
  - IGMP
- Filters traffic by protocol, port, source IP, and destination IP
- Shows live statistics (total, TCP, UDP, top IP, top port)
- Detects suspicious patterns:
  - SYN burst threshold alerts
  - Telnet traffic alerts (deduplicated per source/port)
- Provides:
  - Interactive dashboard (`--dashboard`)
  - Newline-delimited JSON output (`--json`)
  - PCAP file export (`--pcap-out`)

## Build

```bash
cargo build
```

## Quick Start

Run with elevated privileges:

```bash
sudo ./target/debug/packetsage
```

Or grant packet capture capabilities once and run without `sudo`:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/packetsage
./target/debug/packetsage
```

## How To Use

### 1) List interfaces

```bash
sudo ./target/debug/packetsage --list-interfaces
```

### 2) Capture on a specific interface

```bash
sudo ./target/debug/packetsage --interface wlo1
```

### 3) Filter traffic

By protocol:

```bash
sudo ./target/debug/packetsage --protocol tcp
sudo ./target/debug/packetsage --protocol udp
sudo ./target/debug/packetsage --protocol arp
sudo ./target/debug/packetsage --protocol ipv6
sudo ./target/debug/packetsage --protocol igmp
```

By port:

```bash
sudo ./target/debug/packetsage --port 443
```

By source/destination IP:

```bash
sudo ./target/debug/packetsage --src 192.168.1.10
sudo ./target/debug/packetsage --dst 8.8.8.8
```

### 4) Limit capture size

```bash
sudo ./target/debug/packetsage --count 200
```

### 5) Quiet mode + periodic stats

```bash
sudo ./target/debug/packetsage --quiet --stats-interval 25
```

### 6) Tune IDS SYN threshold

```bash
sudo ./target/debug/packetsage --syn-threshold 50
```

## Dashboard Mode

Start dashboard:

```bash
sudo ./target/debug/packetsage --dashboard
```

Controls:

```text
space -> pause/resume capture
c     -> clear recent packets + alerts
q/Esc -> quit dashboard
```

Note: `--dashboard` and `--json` cannot be used together.

## JSON Output Mode

Emit newline-delimited JSON:

```bash
sudo ./target/debug/packetsage --json
```

Example workflow (show only alerts):

```bash
sudo ./target/debug/packetsage --json | jq 'select(.type=="alert")'
```

## PCAP Export

Write matched packets to a PCAP file:

```bash
sudo ./target/debug/packetsage --pcap-out capture.pcap
```

Combine filters + PCAP:

```bash
sudo ./target/debug/packetsage --protocol tcp --port 443 --pcap-out https_traffic.pcap
```

Combine JSON + PCAP:

```bash
sudo ./target/debug/packetsage --json --pcap-out capture.pcap
```

## Common Examples

Capture only ARP and save to PCAP:

```bash
sudo ./target/debug/packetsage --protocol arp --pcap-out arp_only.pcap
```

Capture TCP 443 with stats every 100 packets:

```bash
sudo ./target/debug/packetsage --protocol tcp --port 443 --stats-interval 100
```

## Troubleshooting

Permission error (`Operation not permitted`):

```bash
sudo ./target/debug/packetsage
```

Or re-apply capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/packetsage
```

`sudo cargo run` says `cargo: command not found`:

```bash
sudo ./target/debug/packetsage
```

No packets seen:

```bash
sudo ./target/debug/packetsage --list-interfaces
sudo ./target/debug/packetsage --interface <name>
```

After rebuild, capabilities may reset. Re-run `setcap`.

## Release Binary

For optimized builds:

```bash
cargo build --release
sudo ./target/release/packetsage
```

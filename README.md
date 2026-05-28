<div align="center">

# ThermoFlood

**A high performance SYN Flood Network Stress Testing Tool, built for low level protocol research and security analysis.**

![C](https://img.shields.io/badge/Language-C-blue?style=flat-square&logo=c)
![Platform](https://img.shields.io/badge/Platform-Linux-informational?style=flat-square&logo=linux)
![Security](https://img.shields.io/badge/Category-Network%20Security-red?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0.0-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

*Operates at Layer 2 with full Ethernet frame construction, IP spoofing, MAC spoofing, and multi-threaded packet delivery.*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Whats New in v2](#-whats-new-in-v200)
- [How It Works](#-how-it-works)
- [Technical Deep Dive](#-technical-deep-dive)
- [Compilation](#-compilation)
- [Usage](#-usage)
- [Issues & Limitations](#-issues--limitations)
- [Disclaimer](#-disclaimer)

---



## 🔍 Overview

**ThermoFlood** is a network security research tool written in C that demonstrates the mechanics of a **TCP SYN Flood**. Version 2.0.0 is a complete architectural upgrade moving from kernel-assisted `IPPROTO_RAW` sockets to fully manual **Layer 2 (`AF_PACKET`) socket programming**, giving the tool complete control over the entire packet from the Ethernet header down.

Named after the Battle of Thermopylae, where a small force held back a massive one, this tool is designed to test the resilience of network infrastructure against resource exhaustion attacks.

### What is a SYN Flood?

In a normal TCP connection, a Three Way Handshake occurs. An attacker sends multiple SYN packets but never responds to the server's SYN-ACK, leaving the server with "half-open" connections that eventually exhaust its resources.

| Phase | Packet Type | Action |
|-------|-------------|--------|
| 1 | **SYN** | Client requests connection (ThermoFlood sends this) |
| 2 | **SYN-ACK** | Server acknowledges and waits |
| 3 | **ACK** | Client completes handshake (never sent intentionally ignored) |

---



https://github.com/user-attachments/assets/facf92be-e65a-4db5-a224-f5a0be508157



## 🆕 What's New in v2.0.0

Version 2 is a significant rewrite over v1. Here is a summary of every major change:

| Feature | v1.0.0 | v2.0.0 |
|---|---|---|
| Socket Layer | Layer 3 (`IPPROTO_RAW`) | **Layer 2 (`AF_PACKET`)** |
| Ethernet Header | Kernel-managed | **Manually constructed** |
| MAC Spoofing | ✗ | **✓ Full source MAC spoofing** |
| Sequence Numbers | Static | **Randomized** |
| Source Port | Fixed | **Randomized (1024–65535)** |
| TTL | Fixed | **Randomized (64–127)** |
| IP ID | Fixed | **Randomized** |
| Window Size | Fixed | **Randomized (1024–65535)** |
| TOS Field | Fixed | **Randomized** |
| Interface Selection | Not supported | **✓ `-i` flag** |
| Input Method | Interactive prompts | **CLI argument flags** |

---

## ⚙️ How It Works

### Layer 2 Architecture

v2.0.0 moves to `AF_PACKET` + `SOCK_RAW` sockets, which operate directly at the **Data Link Layer (Layer 2)**. This means ThermoFlood now constructs the complete network frame from scratch:

```
[ Ethernet Header ] → [ IP Header ] → [ TCP Header ] → [ Payload ]
```

This is a lower level of control than v1, which only managed IP and TCP headers. The kernel is completely bypassed for all header construction.

### Randomization Engine

Every packet sent in v2 uses `getrandom()` (a cryptographically secure syscall) to randomize the following fields per-packet:

- **Sequence Number** — full 32-bit random value
- **Source Port** — range 1024–65535
- **IP Identification** — full 16-bit random value
- **TTL** — range 64–127
- **Window Size** — range 1024–65535
- **TOS (Type of Service)** — lower bits randomized

This makes each packet appear to originate from a different TCP session, significantly increasing the difficulty of simple rule-based filtering.

---

## 💻 Technical Deep Dive

### Packet Structure

The tool manually builds three headers back-to-back in a single buffer:

```
packet[]
├── struct ethhdr     (14 bytes)  ← NEW in v2
├── struct iphdr      (20 bytes)
├── struct tcphdr     (20 bytes)
└── data payload      (variable)
```

### Ethernet Header

```c
struct ethhdr *eth = (struct ethhdr*)packet;
memcpy(&(eth->h_source), ether_aton(source_mac_address), 6);
memcpy(&(eth->h_dest),   ether_aton(dest_mac_address),   6);
eth->h_proto = htons(ETH_P_IP);
```

By setting `h_source` to an arbitrary MAC address, the tool achieves **Layer 2 identity spoofing**, making packets appear to originate from a different physical device on the network.

### The Pseudo Header (TCP Checksum)

The TCP checksum calculation requires a pseudo header that borrows fields from the IP layer. This ensures the packet is technically valid and accepted by the target network stack:

```c
typedef struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t  placeholder;
    u_int16_t protocol;
    u_int16_t tcp_length;
} pseudo_header;
```

### Multi-threading Model

Each thread creates its own `AF_PACKET` raw socket and independently loops `sendto()`. The total packet count (`-c`) is divided evenly across all threads, maximising packets per second (PPS) on multi-core machines.

```c
thread_args_blueprint.packet_count_per_thread = packet_count / threads_count;
```

The default thread count is 10. The maximum is automatically capped at `sysconf(_SC_NPROCESSORS_ONLN) * 4` for your specific machine.

---

## 🚀 Compilation

**Prerequisites:**

- GCC compiler
- Linux environment (AF_PACKET requires Linux-specific headers)
- Root / sudo privileges (required for `SOCK_RAW`)

```bash
# Compile with the pthread library linked
gcc ThermoFlood.c -o ThermoFlood -lpthread
```

---

## 🛠 Usage

Since the tool creates raw Layer 2 sockets and accesses the network interface directly, it must be run with `sudo`.

```bash
sudo ./ThermoFlood -di <dest_ip> -dm <dest_mac> -dp <dest_port> \
                   -si <src_ip>  -sm <src_mac>  -i  <interface> \
                   -c  <packet_count>
```

### Arguments

| Flag | Required | Description | Example |
|------|----------|-------------|---------|
| `-di` | ✓ | Destination IP address | `-di 192.168.1.10` |
| `-dm` | ✓ | Destination MAC address | `-dm aa:bb:cc:dd:ee:ff` |
| `-dp` | ✓ | Destination port | `-dp 80` |
| `-si` | ✓ | Source IP address (supports spoofing) | `-si 10.0.0.5` |
| `-sm` | ✓ | Source MAC address (supports spoofing) | `-sm ff:45:6f:d7:e8:5a` |
| `-i`  | ✓ | Network interface name | `-i eth0` |
| `-c`  | ✓ | Total number of packets to send | `-c 1000000` |
| `-t`  | ✗ | Thread count (default: 10) | `-t 16` |
| `-h`  | ✗ | Show help menu | `-h` |

### Examples

**Basic test against a local server:**
```bash
sudo ./ThermoFlood -di 192.168.1.100 -dm aa:bb:cc:11:22:33 -dp 80 \
                   -si 192.168.1.50  -sm ff:ee:dd:cc:bb:aa \
                   -i eth0 -c 500000
```

**With MAC and IP spoofing + increased thread count:**
```bash
sudo ./ThermoFlood -di 192.168.1.100 -dm aa:bb:cc:11:22:33 -dp 443 \
                   -si 10.0.0.1      -sm de:ad:be:ef:00:01 \
                   -i eth0 -c 1000000 -t 20
```

---

## ⚠️ Issues & Limitations

1. **Root Necessity** — `AF_PACKET` requires `CAP_NET_RAW`, available only to root or processes with the appropriate capability set.

2. **Same Subnet Requirement** — Because v2 operates at Layer 2, the destination MAC address must be reachable on the local network segment. For targets behind a router, use the router's MAC as the destination MAC.

3. **Modern Mitigation** — Many modern firewalls and ISPs employ SYN Cookies or ingress filtering (BCP 38), which can detect and drop spoofed packets or absorb the flood's impact.

4. **Platform Support** — Tested on Arch Linux `AF_PACKET` is Linux-specific and will not compile on macOS or BSD without significant changes.

---

## 💬 Future Expectations

1. Randomize source ip, source mac mode
2. Also add support for other Flood methods

---

## ⚖️ Disclaimer

ThermoFlood is for **educational and authorized testing purposes only**. Unauthorized use of this tool against systems you do not own or have explicit written permission to test is **illegal and unethical**. The developer, Piyumila Perera, assumes no liability for misuse or damage caused by this software. Use it to learn, to defend, and to understand the architecture of the web not to destroy.

---

<div align="center">

Developed by Piyumila Perera  |  Network Security Research  |  v2.0.0

*Exploring the depths of the OSI model, one packet at a time.*

</div>

# ✨ Raven Edge

**High-Performance Kotlin Implementation of Wireguard and AmneziaWG.** 🚀
Currently Linux Only

Raven Edge is a Kotlin server implementation of the AmneziaWG protocol (a WireGuard fork with DPI-evasion obfuscation features). Built with Kotlin coroutines for concurrency and Netty using native io_uring and epoll transports, it delivers high-performance UDP handling optimized for modern Linux kernels. ✨

## ✨ Key Features

- 🔹 Full WireGuard and AmneziaWG v2 protocol support, including handshake, data transport, and cookie replies
- 🔹 AmneziaWG obfuscation: junk packet injection (Jc, Jmin, Jmax), packet padding (S1–S4), dynamic magic headers (H1–H4), and CPS signature packets (I1–I5)
- 🔹 IPv4/IPv6 routing with efficient CIDR prefix matching
- 🔹 Dynamic peer management with hot-reload support — add, update, or remove peers at runtime via configuration file changes without service restart or connection drops
- 🔹 High-concurrency architecture using Kotlin coroutines and native Netty event loops (io_uring preferred for best performance)
- 🔹 Optimized I/O: buffer pooling, batched TUN/UDP read/write operations, and zero-copy Unpooled buffers
- 🔹 Built-in observability: periodic stats output to `stats.<interface>.txt`, configurable SLF4J logging (console + file), and optional SHA-1 packet fingerprinting for debugging
- 🔹 Security features: replay protection (BitSet sliding window), under-load cookie challenges, Noise_IKpsk2 handshake with X25519 key exchange, ChaCha20-Poly1305 AEAD, and BLAKE2s hashing (via BouncyCastle)
- 🔹 Linux TUN device management via JNA with automatic interface configuration using iproute2 (addresses, MTU, PostUp/PostDown scripts)

## 📋 Current Status

Linux-optimized server implementation. Requires TUN device support (`/dev/net/tun`), iproute2, and Java 8+. Windows support and client mode are planned for future releases. ❤️

## 🛠️ Installation and Running

**Prerequisites**
- Java 8+ (Temurin JDK or equivalent recommended)
- Linux kernel with TUN support (`/dev/net/tun`)
- iproute2 package for interface management

**Quick Start with Pre-built JAR**

```bash
# Download the latest release 

# Generate keys (equivalent to `wg genkey`)
java -jar ravenedge.jar --genkey

# Create your wg0.conf (see example below)
nano wg0.conf

# Run the server with hot-reload and stats enabled
java -jar ravenedge.jar wg0.conf \
  --hot-reload \
  --log-level=info \
  --log-to-file=/var/log/ravenedge.log \
  --print-stats
```

## 🛠️ Installation

**Prerequisites**
- Java 8+ (Temurin JDK or equivalent recommended)
- Maven 3.9+ 

# Download the latest release

Compile With: 

mvn clean package

After the build completes, two artifacts will appear in the `target/` directory:
- `raven-edge-<version>.jar` (main application)
- `raven-edge-<version>-shaded.jar` (fat JAR with all dependencies — recommended for running)

## 📝 Configuration Example (wg0.conf)

The configuration follows standard WireGuard format with AmneziaWG extensions. Both plain keys (`jc`, `h1`) and `awg`-prefixed keys (`awgjc`, `awgh1`) are supported.

```ini
[Interface]
PrivateKey = YOUR_SERVER_PRIVATE_KEY
ListenPort = 51820
Address = 10.0.0.1/24, fd00::1/64
MTU = 1420
DNS = 1.1.1.1, 8.8.8.8

# AmneziaWG obfuscation parameters (set all to 0 or omit for standard WireGuard compatibility)
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
S3 = 0
S4 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = CLIENT_PUBLIC_KEY
PresharedKey = OPTIONAL_PSK
AllowedIPs = 10.0.0.2/32, fd00::2/128
PersistentKeepalive = 25

[Peer]
PublicKey = ANOTHER_CLIENT_KEY
AllowedIPs = 10.0.0.3/32
```

## 💻 Command-Line Interface

```bash
java -jar ravenedge.jar [OPTIONS] [CONFIG_PATH] 
```

**Options**
- `--genkey` — Generate a new Curve25519 key pair (private + public)
- `--log-level=info` — Set log level: error, warn, info, debug, trace
- `--log-to-file=/path/to/log` — Append logs to file in addition to stdout
- `--print-stats` — Enable periodic stats file output (updated every 10 seconds)
- `--hot-reload` — Watch configuration file for changes and reload peers dynamically
- `--config-scan=60` — Polling interval in seconds for hot-reload (default: 60)
- `--disable-stats` — Disable stats dumper

**Usage Examples**

```bash
# Standard start
java -jar ravenedge.jar wg0.conf

# Run with hot-reload, logging, and stats
java -jar ravenedge.jar /etc/wireguard/wg0.conf \
  --hot-reload \
  --log-level=info \
  --log-to-file=/var/log/ravenedge.log \
  --print-stats

# Generate keys only
java -jar ravenedge.jar --genkey
```

## 🏗️ Architecture

- **Network Layer**: Netty UDP server with native transports (io_uring → epoll → NIO fallback) using Unpooled ByteBuf for efficient zero-copy operations.
- **Peer Management**: Dedicated coroutine-based actor per peer handling Noise protocol state machine, outbound encryption queue, keepalive timers, and rekeying logic.
- **TUN Device**: LinuxTunDevice implementation using JNA for `/dev/net/tun` access, poll(2)-based batch I/O, and a custom BufferPool for memory efficiency.
- **Cryptography**: BouncyCastle-backed implementation of X25519, ChaCha20-Poly1305 AEAD, BLAKE2s, full Noise_IKpsk2 construction, and TAI64N timestamps.
- **Hot-Reload**: Murmur3_128 hash-based file watcher that atomically swaps peer configurations without interrupting active sessions.
- **Routing**: In-memory RoutingTable using sorted IPv4/IPv6 prefix lists for fast longest-prefix-match lookups.

The design prioritizes high concurrency, low latency, and maintainable Kotlin code.

## 🙏 Credits

This is an independent implementation developed for RavenEdge VPN.

Wireguard is a registered trademark of Jason A. Donenfeld

https://www.wireguard.com/

AmneziaWG is fork of wireguard, made by amnezia team

https://github.com/amnezia-vpn/amneziawg-go

*Made with ❤️ and a lot of ☕ in the Kotlin ecosystem.*

Copyright © Friderika Coulson (NanoBee), All rights reserved.

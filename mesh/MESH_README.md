# Mesh VPN - Decentralized P2P Network

> Current implementation status moved to [MESH_STATUS.md](C:/projects/cpp/turbonet/turbo-p2p/mesh/MESH_STATUS.md).
> This README still contains older design intent and historical wording.

A lightweight, decentralized alternative to ZeroTier built on TurboNet.

## 🎯 What is it?

A **zero-config P2P mesh VPN** that creates encrypted tunnels between nodes without central servers.

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Node A     │◄───────►│  Node B     │◄───────►│  Node C     │
│ 10.42.0.1   │  DTLS   │ 10.42.0.2   │  DTLS   │ 10.42.0.3   │
└─────────────┘         └─────────────┘         └─────────────┘
       ▲                                                ▲
       └────────────────────────────────────────────────┘
                     Fully meshed network
```

## 📦 Features

- ✅ **Zero Config** - No central controller needed
- ✅ **NAT Traversal** - Works behind firewalls (ICE/STUN/TURN)
- ✅ **Encrypted** - WebRTC DTLS encryption
- ✅ **Decentralized** - DHT-based peer discovery
- ✅ **Cross-Platform** - Windows/Linux/macOS
- ✅ **Lightweight** - Only ~500 lines of new code

## 🆚 vs ZeroTier

| Feature | ZeroTier | Mesh VPN |
|---------|----------|----------|
| Architecture | Central controller | Fully decentralized |
| Peer Discovery | Controller API | DHT |
| NAT Traversal | Built-in | ICE (STUN/TURN) |
| Encryption | Custom | WebRTC DTLS (standard) |
| Dependencies | ZeroTier servers | Public STUN/TURN |
| Privacy | Controller sees all | Zero metadata collection |

## 🚀 Quick Start

### Build

```bash
cmake -B build -G Ninja
cmake --build build --target mesh_vpn
```

### Run

**Node 1 (Bootstrap)**:
```bash
./build/bin/mesh_vpn 10.42.0.1 16
```

**Node 2**:
```bash
./build/bin/mesh_vpn 10.42.0.2 16 127.0.0.1:9993
```

**Node 3**:
```bash
./build/bin/mesh_vpn 10.42.0.3 16 127.0.0.1:9993
```

### Test

```bash
# From Node 1
ping 10.42.0.2
ping 10.42.0.3

# From Node 2
ping 10.42.0.1
ping 10.42.0.3
```

## 🏗️ Architecture

```
Application (ping, ssh, etc.)
         ↓
    TUN Device (10.42.x.x/16)
         ↓
   Mesh Routing Layer
    ├─ Virtual IP → Peer lookup (DHT)
    └─ Packet forwarding
         ↓
    P2P Network Layer
    ├─ Peer discovery (DHT + Gossip)
    ├─ NAT traversal (ICE)
    └─ Encrypted tunnel (WebRTC DataChannel)
         ↓
      Internet
```

### Components Used

- **`tunnel/`** - TUN device + IP stack (existing)
- **`p2p/`** - P2P networking + DHT (existing)
- **`ice/`** - NAT traversal (existing)
- **`webrtc/`** - Encrypted DataChannel (existing)
- **`mesh.c`** - Routing logic (new, ~500 lines)

## 📚 API Usage

### C API

```c
#include <turbo_mesh.h>

/* Create mesh config */
mesh_config_t config;
mesh_config_init(&config);

config.virtual_ip = "10.42.0.5";
config.virtual_prefix = 16;
config.listen_port = 9993;

/* Create and start mesh */
mesh_network_t *mesh = mesh_create(&config);
mesh_start(mesh);

/* Send IP packet through mesh */
uint8_t ip_packet[1500];
mesh_send_packet(mesh, ip_packet, sizeof(ip_packet));

/* Poll events */
while (running) {
    mesh_poll(mesh, 100);
}

/* Cleanup */
mesh_destroy(mesh);
```

## 🔧 Configuration

### Virtual Network

```c
config.virtual_ip = "10.42.0.5";       /* Your virtual IP */
config.virtual_prefix = 16;            /* /16 network = 65k IPs */
```

### Bootstrap Peers

```c
const char *peers[] = {
    "peer1.example.com:9993",
    "peer2.example.com:9993"
};

config.bootstrap_peers = peers;
config.bootstrap_count = 2;
```

### Network Isolation

```c
config.network_id = "my-private-network";  /* Isolated mesh */
```

## 📊 Statistics

```c
mesh_stats_t stats;
mesh_get_stats(mesh, &stats);

printf("Peers: %u\n", stats.peer_count);
printf("TX: %llu bytes\n", stats.bytes_tx);
printf("RX: %llu bytes\n", stats.bytes_rx);
```

## 🔒 Security

- **Encryption**: WebRTC DTLS 1.2 (industry standard)
- **Authentication**: DTLS-SRTP key exchange
- **Privacy**: No central server, zero metadata collection
- **NAT Traversal**: Secure ICE negotiation

## 🎓 How It Works

### 1. Bootstrap

```
Node A                          Node B
   │                               │
   ├─► DHT: Register 10.42.0.1 ───►│
   │                               │
   ◄── P2P: Connect to A ──────────┤
   │                               │
   ├─► ICE: NAT traversal ────────►│
   │                               │
   ├─► DTLS: Encrypted tunnel ────►│
   │                               │
```

### 2. Packet Routing

```
App sends: ping 10.42.0.2
   ↓
TUN captures IP packet
   ↓
Mesh extracts dst=10.42.0.2
   ↓
DHT lookup: 10.42.0.2 → Peer B
   ↓
Send via encrypted tunnel to Peer B
   ↓
Peer B writes to TUN
   ↓
App receives ping reply
```

### 3. Peer Discovery

```
Node C joins
   ↓
DHT query: "Who is in mesh?"
   ↓
DHT returns: Node A, Node B
   ↓
Connect to A and B
   ↓
Register self in DHT
   ↓
Full mesh established
```

## 🛠️ Advanced Usage

### Custom Encryption

The mesh uses WebRTC DataChannel by default. To use custom encryption:

```c
/* Implement custom tunnel */
int my_tunnel_send(peer_t *peer, const void *data, size_t len) {
    /* Custom encryption here */
}

config.tunnel_send_fn = my_tunnel_send;
```

### Multi-hop Routing

Currently direct peer-to-peer. For multi-hop:

```c
config.enable_relay = 1;         /* Allow packet forwarding */
config.max_hops = 3;             /* Max relay hops */
```

## 📝 TODO

- [ ] Multi-hop routing for non-direct connections
- [ ] IPv6 support
- [ ] Bandwidth limiting
- [ ] QoS prioritization
- [ ] Web UI for node management
- [ ] Optional TurboWASM compute executor on explicitly enrolled compute nodes
      (deferred; not a Mesh RPC, core-library, or ordinary-node dependency)

## 🤝 Contributing

This is part of TurboNet project. See main README for contribution guidelines.

## 📄 License

Same as TurboNet main project.

## 🙏 Credits

Inspired by:
- **ZeroTier** - Virtual networking concept
- **Tailscale** - Mesh architecture
- **WireGuard** - Simplicity philosophy

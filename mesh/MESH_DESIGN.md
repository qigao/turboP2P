# Mesh VPN Design Document

## Overview

A decentralized P2P mesh VPN built on TurboNet, providing ZeroTier-like functionality without central controllers.

## Architecture

### Layer Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                       │
│              (Any IP-based application)                     │
│         ping, ssh, curl, rdp, vnc, games, etc.              │
└──────────────────────┬──────────────────────────────────────┘
                       │ Standard IP traffic
                       ↓
┌──────────────────────────────────────────────────────────────┐
│                   Operating System                           │
│               (Routing table modified)                       │
│         Route 10.42.0.0/16 → TUN device                     │
└──────────────────────┬──────────────────────────────────────┘
                       │ IP packets
                       ↓
┌──────────────────────────────────────────────────────────────┐
│              TUN Virtual Network Device                      │
│                 (turbo_tunnel module)                        │
│   - Captures all IP packets                                 │
│   - Writes received packets to userspace                    │
│   - Cross-platform abstraction                              │
└──────────────────────┬──────────────────────────────────────┘
                       │ Raw IP packets
                       ↓
┌──────────────────────────────────────────────────────────────┐
│                 Mesh Routing Layer                           │
│                   (mesh.c - NEW)                             │
│   ┌─────────────────────────────────────────────┐            │
│   │ 1. Extract dst IP from IP header            │            │
│   │ 2. Lookup virtual_ip → peer_id (DHT)        │            │
│   │ 3. Get or create P2P connection             │            │
│   │ 4. Forward packet to peer                   │            │
│   └─────────────────────────────────────────────┘            │
└──────────────────────┬──────────────────────────────────────┘
                       │ Routed packets
                       ↓
┌──────────────────────────────────────────────────────────────┐
│                  P2P Network Layer                           │
│                   (p2p/ module)                              │
│   ┌──────────────────────────────────────────┐               │
│   │ Peer Discovery (DHT + Gossip)            │               │
│   │  - DHT stores virtual_ip → peer_info     │               │
│   │  - Gossip propagates peer list           │               │
│   │  - Bootstrap nodes for initial contact   │               │
│   └──────────────────────────────────────────┘               │
└──────────────────────┬──────────────────────────────────────┘
                       │ P2P messages
                       ↓
┌──────────────────────────────────────────────────────────────┐
│                  NAT Traversal Layer                         │
│                    (ice/ module)                             │
│   ┌──────────────────────────────────────────┐               │
│   │ ICE (Interactive Connectivity Est.)      │               │
│   │  - STUN for reflexive address discovery  │               │
│   │  - TURN for relay when needed            │               │
│   │  - Full cone, symmetric, port-restricted │               │
│   └──────────────────────────────────────────┘               │
└──────────────────────┬──────────────────────────────────────┘
                       │ NAT-traversed connections
                       ↓
┌──────────────────────────────────────────────────────────────┐
│                 Encryption Layer                             │
│                  (webrtc/ module)                            │
│   ┌──────────────────────────────────────────┐               │
│   │ WebRTC DataChannel over DTLS             │               │
│   │  - DTLS 1.2 encryption                   │               │
│   │  - SRTP key exchange                     │               │
│   │  - Per-connection keys                   │               │
│   │  - SCTP framing                          │               │
│   └──────────────────────────────────────────┘               │
└──────────────────────┬──────────────────────────────────────┘
                       │ Encrypted datagrams
                       ↓
┌──────────────────────────────────────────────────────────────┐
│                    Physical Network                          │
│                      (Internet)                              │
└──────────────────────────────────────────────────────────────┘
```

## Component Breakdown

### 1. TUN Device (`tunnel/src/tun/`)

**Purpose**: Virtual network interface

**Implementation**:
- **Linux**: `/dev/net/tun` API
- **macOS**: `utun` sockets
- **Windows**: WinTun driver

**Data Flow**:
```
App → Kernel → TUN → Userspace → Mesh Router
```

**Key Functions**:
```c
int tun_create(const char *name, const char *ip, const char *netmask);
int tun_read(int fd, void *buf, size_t len);
int tun_write(int fd, const void *buf, size_t len);
```

---

### 2. Mesh Router (`tunnel/src/mesh.c`) - NEW

**Purpose**: Route IP packets to correct peers

**Core Logic**:
```c
int mesh_send_packet(mesh_network_t *mesh,
                      const uint8_t *ip_packet, size_t len) {
    // 1. Extract destination IP
    uint32_t dst_ip = extract_dst_ip(ip_packet, len);

    // 2. Find peer by virtual IP
    mesh_peer_t *peer = mesh_find_peer(mesh, dst_ip);

    // 3. If not found, query DHT
    if (!peer) {
        char dht_key[128];
        sprintf(dht_key, "mesh:%s:ip:%s", mesh->network_id, dst_ip_str);

        char peer_info[256];
        p2p_dht_get(mesh->p2p_node, dht_key, peer_info, &len);

        // Parse peer info and connect
        p2p_connect(mesh->p2p_node, peer_ip, peer_port);

        peer = mesh_peer_create(dst_ip_str);
    }

    // 4. Send via P2P
    return p2p_broadcast(mesh->p2p_node, ip_packet, len);
}
```

**Data Structures**:
```c
typedef struct mesh_network_s {
    char virtual_ip[16];           /* Our IP */
    p2p_node_t *p2p_node;         /* P2P layer */
    mesh_peer_t *peers;            /* Peer list */
    int peer_count;
} mesh_network_t;

typedef struct mesh_peer_s {
    char virtual_ip[16];           /* Peer's virtual IP */
    p2p_peer_t *p2p_peer;         /* P2P connection */
    int is_connected;
    uint64_t bytes_tx, bytes_rx;
} mesh_peer_t;
```

---

### 3. P2P Network (`p2p/`)

**Purpose**: Decentralized peer discovery and messaging

**DHT Schema**:
```
Key: "mesh:<network_id>:ip:<virtual_ip>"
Value: "<real_ip>:<port>"

Example:
  Key: "mesh:default:ip:10.42.0.5"
  Value: "203.0.113.50:9993"
```

**Peer Discovery Flow**:
```
Node A                           DHT                Node B
   │                              │                   │
   ├─ PUT mesh:default:ip:10.42.0.1 → 203.0.113.1:9993
   │                              │                   │
   │                              │  ◄─ GET mesh:default:ip:10.42.0.1
   │                              │                   │
   │                              ├─ RETURN 203.0.113.1:9993 →
   │                              │                   │
   │  ◄─────────────── P2P CONNECT ─────────────────┤
   │                              │                   │
```

---

### 4. NAT Traversal (`ice/`)

**Purpose**: Establish direct connections through NATs

**ICE Process**:
```
1. Gather candidates
   - Host: 192.168.1.5:9993
   - Server Reflexive (STUN): 203.0.113.1:45678
   - Relay (TURN): 198.51.100.1:12345

2. Exchange candidates via P2P signaling

3. Connectivity checks (STUN binding requests)
   - Try all candidate pairs
   - Select best working pair

4. Nominated pair → direct connection
```

**Fallback Strategy**:
```
1. Direct connection (both public IPs)
   ↓ fail
2. Server reflexive (STUN)
   ↓ fail
3. Relay (TURN)
```

---

### 5. Encryption (`webrtc/`)

**Purpose**: Secure peer-to-peer tunnels

**WebRTC DataChannel Stack**:
```
┌─────────────────┐
│  Application    │ IP packets
├─────────────────┤
│  DataChannel    │ Message framing
├─────────────────┤
│  SCTP           │ Reliable/ordered delivery
├─────────────────┤
│  DTLS           │ Encryption (TLS 1.2)
├─────────────────┤
│  UDP/ICE        │ NAT traversal
└─────────────────┘
```

**Security Properties**:
- **Encryption**: AES-128-GCM or AES-256-GCM
- **Authentication**: SHA-256 HMAC
- **Key Exchange**: DTLS 1.2 handshake
- **Perfect Forward Secrecy**: Ephemeral keys per session

---

## Message Flow Examples

### Example 1: Ping Between Nodes

```
Node A (10.42.0.1)                               Node B (10.42.0.2)
       │                                                │
  [1]  │ App: ping 10.42.0.2                          │
       ↓                                               │
  [2]  │ Kernel: Route to TUN device                  │
       ↓                                               │
  [3]  │ TUN: Capture ICMP echo request               │
       │   src=10.42.0.1 dst=10.42.0.2               │
       ↓                                               │
  [4]  │ Mesh: Lookup peer for 10.42.0.2             │
       │   → Found in local cache                     │
       ↓                                               │
  [5]  │ P2P: Send via existing connection            │
       ├────────── Encrypted DataChannel ─────────────►│
       │                                               ↓
       │                                          [6]  │ P2P: Receive packet
       │                                               ↓
       │                                          [7]  │ Mesh: Forward to TUN
       │                                               ↓
       │                                          [8]  │ TUN: Write to kernel
       │                                               ↓
       │                                          [9]  │ Kernel: Deliver to app
       │                                               ↓
       │                                         [10]  │ App: Receive ping
       │                                               │
       │ ◄────────── ICMP echo reply ──────────────────┤
```

### Example 2: New Peer Joins

```
Node C (joining)                  DHT                Node A (bootstrap)
       │                           │                        │
  [1]  │ mesh_start()              │                        │
       │  - Register virtual IP     │                        │
       ├─ PUT mesh:default:ip:10.42.0.3 = 203.0.113.3:9993 →
       │                           │                        │
  [2]  │ mesh_connect_peer("10.42.0.1")                    │
       ├─ GET mesh:default:ip:10.42.0.1 ─►                │
       │                           ├─ RETURN 203.0.113.1:9993 →
       │                           │                        │
  [3]  │ p2p_connect(203.0.113.1, 9993)                    │
       │   - Create P2P peer                               │
       │   - Initiate connection                           │
       ├────────────── TCP SYN ───────────────────────────►│
       │                           │                        │
  [4]  │ ◄──────────── TCP SYN-ACK ────────────────────────┤
       │                           │                        │
  [5]  │ ICE: Exchange candidates  │                        │
       ├────────── STUN Binding ──────────────────────────►│
       │ ◄─────── STUN Success ────────────────────────────┤
       │                           │                        │
  [6]  │ DTLS: Handshake           │                        │
       ├──────── ClientHello ─────────────────────────────►│
       │ ◄─────── ServerHello ─────────────────────────────┤
       │                           │                        │
  [7]  │ DataChannel established   │                        │
       │ Mesh: Peer connected      │  Mesh: Peer connected  │
       │                           │                        │
```

## Performance Characteristics

### Latency

| Scenario | Latency |
|----------|---------|
| Direct connection (same LAN) | < 1ms |
| Direct connection (Internet) | RTT + encryption overhead (~2-5ms) |
| STUN reflexive | Same as direct |
| TURN relay | RTT(client→TURN) + RTT(TURN→peer) |

### Throughput

| Transport | Throughput |
|-----------|------------|
| Direct UDP (ICE) | Limited by network bandwidth |
| TURN relay | Limited by TURN server bandwidth |
| Encryption overhead | ~2-5% (AES-GCM hardware accelerated) |

### Scalability

| Metric | Limit | Notes |
|--------|-------|-------|
| Peers per node | ~256 | Configurable |
| Network size | Unlimited | DHT scales horizontally |
| Packet rate | ~100k pps | Limited by TUN device |

---

## Comparison with ZeroTier

| Feature | ZeroTier | Mesh VPN |
|---------|----------|----------|
| **Architecture** | ||||
| Controller | Required | None (fully decentralized) |
| Peer discovery | Controller API | DHT |
| Bootstrap | Moon/Planet servers | Any mesh node |
| **Security** | |||
| Encryption | Custom (Salsa20/Poly1305) | WebRTC DTLS (AES-GCM) |
| Key exchange | Custom | DTLS 1.2 (standard) |
| Authentication | Controller-managed | DTLS certificates |
| **NAT Traversal** | |||
| Method | Custom UDP hole punching | ICE (industry standard) |
| STUN | Built-in | External STUN servers |
| TURN | Built-in | External TURN servers |
| **Privacy** | |||
| Metadata | Controller sees all | Zero collection |
| Logging | Controller logs | Local only |
| **Implementation** | |||
| Code size | ~50k lines C++ | ~500 lines C (new) + existing modules |
| Dependencies | None | libuv, OpenSSL, libsrtp |
| Platforms | All major | All major |

---

## Security Considerations

### Threat Model

**Trusted**:
- Local network (LAN)
- Endpoint devices
- DHT entries (integrity via signatures)

**Untrusted**:
- Internet transit
- NAT devices
- STUN/TURN servers
- Other mesh nodes (until authenticated)

### Security Mechanisms

1. **Encryption**: DTLS 1.2 with AES-256-GCM
2. **Authentication**: DTLS certificate validation
3. **Integrity**: HMAC-SHA256
4. **Replay Protection**: DTLS sequence numbers
5. **DoS Protection**: Connection rate limiting

### Attack Scenarios

| Attack | Mitigation |
|--------|------------|
| Man-in-the-middle | DTLS certificate pinning |
| Replay attack | DTLS sequence numbers |
| DHT poisoning | Sign DHT entries with node key |
| Packet injection | DTLS encryption + MAC |
| DoS flood | Rate limiting + connection limits |

---

## Future Enhancements

### Short-term (< 1 month)

- [ ] Multi-hop routing for non-direct peers
- [ ] IPv6 support
- [ ] Bandwidth limiting per peer
- [ ] QoS prioritization

### Medium-term (< 3 months)

- [ ] Web UI for node management
- [ ] Mobile app (Android/iOS)
- [ ] NAT type detection and optimization
- [ ] Dynamic route selection (shortest path)

### Long-term (< 6 months)

- [ ] Byzantine fault tolerance
- [ ] Formal security audit
- [ ] Wireguard protocol compatibility
- [ ] Hardware acceleration (DPDK)

---

## References

- **ZeroTier**: https://www.zerotier.com/
- **Tailscale**: https://tailscale.com/
- **WireGuard**: https://www.wireguard.com/
- **ICE RFC**: https://tools.ietf.org/html/rfc8445
- **DTLS RFC**: https://tools.ietf.org/html/rfc6347
- **WebRTC**: https://webrtc.org/

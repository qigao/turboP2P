# Mesh VPN Design Document

> Current status note: `MESH_STATUS.md` is the operational truth for what is
> implemented today. This document is the design map: it separates the current
> beta data/control plane from longer-term Tailscale/ZeroTier-like product
> features.

## Overview

A decentralized P2P mesh VPN built on TurboNet. The current implementation is
beta-grade mesh routing with DHT-backed discovery, learned relay routes,
operator-pinned routes, admission allowlists, static packet policy, and
ICE-based direct-path groundwork. The first local-egress cut for subnet-router and exit-node roles is
implemented. A local static MagicDNS name table is also implemented, but
product-grade controller policy, DNS serving/search domains, platform route/NAT
management, service manager integration, and large-scale validation are planned
layers, not current GA behavior.

## Subnet Router / Exit Node Cut

The smallest compatible cut reuses the current packet-mode tunnel and mesh
route policy, but only for steering traffic to a known next hop. Existing
`route_rules` already parse CIDRs and use longest-prefix match, so a client can
pin `192.168.50.0/24` or `0.0.0.0/0` toward a router's mesh virtual IP without
adding a public ABI field.

That is not enough by itself to make a node an exit node or subnet router. The
receiving router also needs explicit local authority to egress non-mesh
destinations to the OS/TUN side; otherwise pinned routes would turn any next hop
into an accidental gateway.

The first compatible implementation adds that explicit local-egress role before
changing protocol traffic:

- `route_rules` remain client-side operator intent: destination CIDR to next
  hop virtual IP.
- router-side configuration declares which non-mesh CIDRs this node will
  egress to the OS/TUN side.
- optional router-side source policy declares which directly authenticated mesh
  virtual CIDRs may use that local egress.
- `mesh_handle_ip_packet()` delivers packets matching those local-egress CIDRs
  to `on_packet_received` only when the source is also allowed, instead of
  trying to forward them again.
- `mesh_send_packet()` accepts non-mesh destinations only when a policy rule
  explicitly matches; unmatched non-mesh traffic continues to fail closed.
- exit-node is the same mechanism with `0.0.0.0/0`, plus OS routing/NAT owned
  by the daemon or deployment layer rather than the mesh protocol.

This cut preserves learned routes as observed mesh state and keeps subnet/exit
advertisement out of the wire protocol until controller policy, admission, and
operator UX are defined.

### State Ownership

- Client-side route intent is owned by `route_rules`. It is static operator
  policy: destination CIDR to a direct next-hop virtual IP. It must not be
  learned from peers or merged into the learned route table.
- Learned mesh reachability is owned by `mesh->routes`. It remains virtual-IP
  reachability only, expires on TTL, and never becomes authority for Internet or
  attached subnet egress.
- Router-side egress ownership is a separate local policy surface. A node
  becomes a subnet router or exit node only for CIDRs in that local egress set.
  Non-mesh destinations remain closed unless both client-side `route_rules` and
  receiver-side `local_egress_cidrs` allow the path. The packet must arrive from
  a direct peer whose completed `MESH_HELLO` identity binds that peer to the
  packet source virtual IP. When `local_egress_allow_cidrs` is configured, that
  authenticated source must also match the source CIDR allowlist. Relayed local
  egress remains closed until the data plane carries an authenticated origin.
- OS routing and NAT are daemon/deployment state, not mesh protocol state. The
  mesh library should hand matching packets to the local packet callback; the
  daemon decides how to install routes, NAT, and platform firewall rules.

### Data Plane

1. Client TUN packets enter `mesh_send_packet()`.
2. Multicast and unmatched non-mesh destinations fail closed.
3. Destinations matching explicit `route_rules` are sent only to the pinned
   next hop. If that next hop is unavailable, send fails instead of falling back
   to direct or learned routes.
4. Router-side `local_egress_cidrs` plus direct-peer source binding and optional
   `local_egress_allow_cidrs` make `mesh_handle_ip_packet()` deliver matching
   non-mesh packets to `on_packet_received`; otherwise incoming non-mesh packets
   are dropped.
5. Return traffic follows normal OS/TUN routing back to the client's mesh
   virtual IP. It uses normal direct/learned mesh reachability rather than the
   client's outbound non-mesh route rule.

### Failure Strategy

- Missing pinned next hop: fail the send with no fallback.
- Missing router-side egress rule: drop at the receiving router.
- Egress callback, OS route, or NAT failure: the daemon owns retry/logging; the
  mesh core must not silently reclassify the packet as learned mesh traffic.
- Ambiguous overlapping CIDRs: longest-prefix match applies on the client; local
  egress policy should use the same rule so subnet routes beat exit routes.
- Policy removal during traffic: new packets fail closed immediately. Existing
  in-flight packets may already have crossed the mesh transport and are handled
  by the receiver's current local policy.

## ACL / Network Policy Evolution

The current admission surface is intentionally small:

- `peer_allow_cidrs` gates direct peer admission by virtual IP.
- `peer_allow_node_ids` gates direct peer admission by stable node identity.
- `peer_protocol_major` gates direct peer admission by mesh protocol generation.
- `packet_policy_rules` gates data-plane packets by direction, source/dest CIDR,
  IP protocol, and source/dest port.
- The same virtual-IP allowlist is already reused to suppress learned routes,
  routed control signaling, direct-connect attempts, and relay forwarding toward
  disallowed destinations.

That should evolve into a full ACL without changing the public ABI in the first
implementation cut. The compatibility path is to compile the existing config
fields into one internal policy table and make every admission or forwarding
decision call that evaluator. Existing fields remain the only external source of
truth until a controller/config update is explicitly approved.

### Policy Model

The internal ACL should use four dimensions:

| Dimension | Initial values | Later values |
|-----------|----------------|--------------|
| Subject | peer node ID, peer virtual IP/CIDR | groups, tags, owner, device posture |
| Action | admit peer, learn route, send control, forward packet, direct-upgrade | subnet egress, exit-node use, service access |
| Resource | peer virtual IP/CIDR, destination CIDR, control message class | named services, route advertisements |
| Effect | allow or deny | priority, audit-only, expiry |

Default behavior stays compatible:

- no configured policy means current permissive mesh behavior.
- existing allowlist fields compile to allow rules for the corresponding
  direct peer subjects.
- packet policy defaults to allow when no rules exist for the packet direction.
- once rules exist for a packet direction, unmatched packets fail closed for
  that direction.
- once any allowlist/policy is configured for a decision class, unmatched
  subjects fail closed for that decision class.
- deny rules, when introduced, win over allow rules at the same or narrower
  scope.

The main fact source must be the compiled policy snapshot owned by
`mesh_network_t`. Cached peer fields, route entries, diagnostics, and controller
mirrors must be derived from that snapshot. Policy updates must be built and
validated off to the side, then posted to the mesh owner loop for a single
pointer replacement. The owner loop releases the previous snapshot only after
the replacement, so readers never race reclamation. Failed validation leaves the
old snapshot active.

### Migration Cuts

1. Internal evaluator only, no public change.
   Compile `peer_allow_cidrs`, `peer_allow_node_ids`, and
   `peer_protocol_major` into an internal policy table. Replace direct calls to
   allowlist helpers with action-specific evaluator calls, preserving all
   current results.
2. Add diagnostics around the existing policy.
   Expose only already-public information for now: allow CIDRs, allow node IDs,
   protocol-major requirement, and packet policy rules. Internal logs should
   report action and resource for blocked decisions.
3. Introduce richer config/controller policy after product approval.
   New fields should describe rules rather than adding another near-duplicate
   allowlist. The old fields compile into the same table and remain supported as
   compatibility aliases.
4. Extend subnet/exit-node policy as separate actions.
   Subnet egress and exit-node use should not be inferred from peer admission.
   They need explicit resource CIDRs and fail-closed forwarding semantics.

Security tests that do not require public contract changes:

- invalid CIDR and invalid node-id config fails during `mesh_create()`.
- configured allowlist and protocol-major policy are visible through existing
  getters.
- disallowed peers cannot become direct peers, cannot inject learned routes,
  cannot receive routed control messages, and cannot be used as relay
  destinations.
- identity mismatch between P2P key and `MESH_HELLO` node id disconnects the
  peer before ICE state is created.

## Control Plane Versioning And Capability Negotiation

Current control-plane compatibility is based on `MESH_HELLO`:

```text
MESH_HELLO:<virtual_ip>[:<advertise_ip>:<port>]:node=<node_id>:proto=<major>.<minor>
```

Older HELLO forms without `node=` or `proto=` are still parsed for backward
compatibility. When `peer_protocol_major` is configured, a peer that omits the
protocol version is rejected; otherwise it can still connect as a legacy peer.

Versioning rules should be:

- `major` changes only when a peer cannot safely interoperate with older
  control-plane semantics.
- `minor` changes when a peer adds backward-compatible behavior.
- a node may use a feature only when both peers advertise the same major and the
  needed capability bit.
- unknown minor versions and unknown capability bits must be ignored.
- absence of a capability means the feature is unavailable, not implicitly
  enabled.
- route learning and packet forwarding must keep fail-closed defaults when a
  capability is missing.
- routed `MESH_CTRL` forwarding remains disabled by default. Hop-by-hop
  capability checks authenticate only adjacent peers and cannot authenticate
  the origin named inside a forwarded control payload. Re-enabling it requires
  an end-to-end authenticated envelope with origin identity and replay
  protection; direct control messages do not need this routed capability.
- raw mesh IP packets over an ICE selected pair require
  `MESH_CAP_SELECTED_PAIR_IP` on both peers; without that negotiated bit, data
  remains on the existing P2P stream transport and incoming selected-pair
  payloads are ignored.
- direct ICE peers derive capability state from their authenticated
  `MESH_HELLO`. A capability bitmap repeated inside `MESH_ICE_AUTH` is not an
  identity proof and must not enable routed ICE by itself.

The wire-compatible capability extension appends optional key-value tokens after
the existing `proto=<major>.<minor>` field, for example:

```text
MESH_HELLO:<virtual_ip>:node=<node_id>:proto=1.1:caps=<hex-bitmap>
```

Peers parse tokens by key, not by positional fields, and store the negotiated
result on the peer object as derived state:

```text
negotiated = local_capabilities & remote_capabilities
```

Capability bits are narrow, but only explicitly enabled bits are operational:

| Bit | Capability | Current state |
|-----|------------|---------------|
| 0 | routed ICE signaling | reserved, not advertised until end-to-end origin authentication exists |
| 1 | selected-pair IP data | enabled for directly authenticated peers when ICE is built |
| 2 | signed route announcement | reserved; signature format and verification are not implemented |
| 3 | policy epoch awareness | reserved; controller snapshot epochs are not implemented |

Old HELLO forms remain accepted unless `peer_protocol_major` requires a versioned
peer. Unknown capability bits and minor versions are ignored; features that need
a new behavior must explicitly check the negotiated bit before relying on it.

## MagicDNS Static Name Cut

The first MagicDNS implementation is deliberately a mesh-owned static map, not a
FakeDNS cache and not a tailnet-wide DNS service.

Current source of truth:

- `mesh_config_t.magic_dns_domain` owns the optional suffix for one mesh
  instance.
- `mesh_config_t.magic_dns_records` owns static `name=virtual_ip` records.
- `meshctl` / `meshd` YAML expose those as `magic_dns_domain` and
  `magic_dns_names`.
- configured names are normalized to lowercase and validated as DNS labels.
- configured IPs must be valid IPv4 addresses inside the mesh virtual prefix.

Current behavior:

- `mesh_resolve_magic_dns()` resolves exact record names.
- with a configured suffix, short records also resolve through
  `short.<magic_dns_domain>`.
- fully qualified records can be resolved by their short leftmost name when the
  configured suffix matches.
- `mesh_reverse_magic_dns()` returns the configured record name; short records
  are returned with the configured suffix.

Boundaries:

- no DNS listener answers these names yet.
- no OS search domain is installed.
- no control-plane record distribution or conflict resolution exists.
- automatic node-name records are not synthesized from peer state yet.
- FakeDNS synthetic addresses remain tunnel cache state and must not become mesh
  identity.

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

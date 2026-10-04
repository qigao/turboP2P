# TurboNet Tunnel Design

## Overview

TurboNet Tunnel is a high-performance **tun2proxy** implementation designed to capture network traffic from a virtual network interface (TUN device) and route it through proxy protocols.

It runs entirely in userspace, providing a lightweight TCP/IP stack implementation to terminate connections and translate them into proxy streams.

## Features

*   **Platform Support**: Linux, macOS, Windows, Android, iOS.
*   **Packet Capture**: Reads raw packets directly from TUN devices.
*   **Userspace IP Stack**: Parses IPv4/IPv6 headers and terminates IPv4 TCP/UDP sessions locally without requiring kernel forwarding.
*   **NAT & Session Management**: Tracks connections with full 5-tuple matching.
*   **Multi-Protocol**:
    *   SOCKS5 CONNECT (RFC 1928)
    *   HTTP CONNECT
    *   Direct TCP (`TUNNEL_PROXY_NONE`)
    *   Shadowsocks, VMess, and Trojan are represented in public configuration but are not implemented as proxy transports yet.
*   **UDP Support**: UDP sessions exist, but SOCKS5 UDP ASSOCIATE and full-cone NAT are not complete.
*   **High Performance**: Zero-copy packet path where possible, built on top of `Salts::CNet` over NativeIO.

## Implementation Status

This document describes the current implementation. Planned API surface is called out explicitly instead of being treated as complete behavior.

| Area | Current status |
| --- | --- |
| Event loop | `tunnel_run()` and non-blocking `tunnel_poll()` drive TUN polling plus one caller-owned `CNet` client. `tunnel_poll()` currently ignores its reserved timeout parameter. |
| TCP proxying | SOCKS5 CONNECT, HTTP CONNECT, and direct TCP are implemented. |
| UDP proxying | UDP relay modes return `TUNNEL_ERR_NOT_SUPPORTED`; packet mode and local session bookkeeping remain available. SOCKS5 UDP wire helpers do not provide a relay transport. |
| IPv6 | IPv6 header parsing exists. End-to-end IPv6 NAT, routing, and packet generation are incomplete. |
| Routing rules | `tunnel_create()` and `tunnel_set_routes()` apply IP include/exclude ranges. Domain rules fail with `TUNNEL_ERR_NOT_SUPPORTED` until a trusted domain-to-flow identity is available. |
| Config files | `tunnel_create_from_file()` supports the existing simple key-value parser. YAML string parsing remains a placeholder. |
| Fake DNS | `tunnel_config_t.dns.fake_dns_range` and the persisted `dns.fake_dns_range` key control the FakeDNS CIDR when FakeDNS is enabled; default remains `198.18.0.0/15`. |
| Shadowsocks / VMess / Trojan | Configuration fields remain for ABI stability; creation/reconfiguration rejects these transports. |

## Architecture

The system follows a layered architecture where IP packets are intercepted, processed by a lightweight NAT/Session layer, and converted into stream-based proxy connections.

```mermaid
graph TD
    subgraph "OS Kernel"
        NIC[Physical NIC]
        TUN[TUN Device]
    end

    subgraph "Application Layer"
        UserApp[User Application] --> TUN
    end

    subgraph "TurboTunnel"
        PacketRX[Packet Receiver]
        IPStack[Lightweight IP Stack]
        NAT[NAT / Session Manager]
        
        subgraph "Proxy Adapters"
            SOCKS5[SOCKS5 Client]
            HTTP[HTTP CONNECT]
            Direct[Direct TCP]
        end
        
        PacketTX[Packet Transmitter]
    end

    TUN --> PacketRX
    PacketRX --> IPStack
    IPStack --> NAT
    
    NAT --> SOCKS5
    NAT --> HTTP
    NAT --> Direct
    
    SOCKS5 --> PacketTX
    HTTP --> PacketTX
    Direct --> PacketTX
    
    PacketTX --> NIC
```

### Data Flow

#### 1. Outgoing Packets (TUN -> Internet)

1.  **Capture**: User application sends a packet to the specific IP CIDR (e.g., `10.0.0.0/8`). The OS routes this to the TUN interface.
2.  **Read**: `tunnel_tun_*` reads the raw IP packet.
3.  **Parsers**: `tunnel_ip_stack` parses IP/TCP/UDP headers.
4.  **Session Lookup**: `tunnel_session` checks if a session exists for the `(SrcIP, SrcPort, DstIP, DstPort, Proto)` tuple.
    *   **New Session**: A new proxy connection is initiated to the configured proxy server.
    *   **Existing Session**: The payload is extracted and queued for the existing proxy connection.
5.  **Proxy Forwarding**: The payload is sent through the selected implemented proxy transport. SOCKS5 and HTTP perform their CONNECT handshakes before data flow; direct mode connects to the target endpoint directly.

#### 2. Incoming Packets (Internet -> TUN)

1.  **Receive**: Data arrives from the proxy server on the physical socket.
2.  **Decapsulation**: The proxy client strips proxy framing where applicable.
3.  **Session Lookup**: The associated internal session is retrieved.
4.  **Packet Generation**: `tunnel_ip_stack` constructs a fake IP packet (e.g., TCP ACK or UDP Response) appearing to come from the original destination IP.
5.  **Write**: The raw packet is written back to the TUN interface.
6.  **Delivery**: The OS receives the packet on the TUN interface and delivers it to the waiting user application.

## Components

### 1. TUN Interface (`src/tun`)
Platform-specific implementations for creating and managing TUN devices.
*   **Windows**: Uses Wintun or TAP-Windows.
*   **Linux/Android**: Uses `/dev/net/tun`.
*   **macOS/iOS**: Uses `utun` devices.

### 2. IP Stack (`src/stack`)
A minimal implementation of TCP/IP required for masquerading. It does *not* implement a full congestion control algorithm. IPv4 TCP/UDP packet building is implemented; IPv6 is currently limited to parsing.

### 3. Session Manager (`src/session`)
The core logic that maps raw IP tuples to proxy client objects. It handles:
*   Connection tracking (conntrack).
*   Timeout management (closing idle connections).
*   LRU eviction for max session limits.

### 4. Proxy Adapters (`src/proxy`)
Protocol implementations that wrap generation-checked `CNet` TCP/TLS connections.
*   **SOCKS5**: Authenticates and sends CONNECT commands.
*   **HTTP**: Sends `CONNECT host:port HTTP/1.1`.
*   **Direct**: Opens a direct TCP stream to the target.
*   **Planned**: SOCKS5 UDP ASSOCIATE, Shadowsocks AEAD, VMess, and Trojan.

## Configuration

Configuration is handled via the `tunnel_config_t` structure or the existing simple key-value file parser. YAML string parsing is still a placeholder and should not be treated as supported behavior yet.

```c
typedef struct {
    tunnel_tun_config_t tun;        /* Device settings (IP, MTU) */
    tunnel_proxy_config_t proxy;    /* Upstream proxy settings */
    tunnel_dns_config_t dns;        /* DNS hijacking and fake DNS */
    tunnel_route_config_t route;    /* Split routing rules */
    // ...
} tunnel_config_t;
```

## FakeDNS / Mesh Boundary

FakeDNS and mesh identity are intentionally separate state domains.

- FakeDNS maps DNS A-record queries to per-tunnel synthetic IPv4 addresses for domain tracking. The default range is `198.18.0.0/15`; callers can set `tunnel_config_t.dns.fake_dns_range` before `tunnel_create()` or `dns.fake_dns_range` in the key-value config file to choose another IPv4 CIDR.
- Mesh virtual IPs, stable `node_id` values, DHT entries, route policy, and peer admission remain owned by `mesh`. The mesh examples expose those through `meshctl` / `meshd` status JSON as `node.virtual_ip`, `node.node_id`, `direct_peers[].virtual_ip`, and `direct_peers[].node_id`.
- Mesh now has a local static MagicDNS map for configured mesh names and virtual IPs. A FakeDNS synthetic address is still not a mesh virtual IP and must not be used as the source of truth for node identity or peer admission.
- The simple key-value file parser exposes `dns.hijack`, `dns.fake`, and `dns.fake_dns_range`.

## MagicDNS / FakeDNS Persistence Plan

Current persisted tunnel configuration is the simple key-value file accepted by `tunnel_create_from_file()`. Its DNS surface includes `dns.hijack`, `dns.fake`, and `dns.fake_dns_range`; unknown DNS keys are ignored by the parser.

Source-of-truth boundaries:

- Tunnel runtime owns packet capture, DNS hijacking, FakeDNS allocation state, and route/session behavior for one `tunnel_t`.
- `tunnel_config_t` is the in-memory source of truth for tunnel creation. `dns.fake_dns_range` is parsed into that structure before tunnel creation.
- The key-value config file is the persisted source of truth for existing tunnel options. It now accepts FakeDNS range, but MagicDNS settings remain mesh-side configuration and are not persisted in tunnel config.
- FakeDNS owns ephemeral domain-to-synthetic-IPv4 mappings. These mappings are cache state and should not be persisted.
- MagicDNS is a separate name-to-mesh-identity layer owned by the mesh/control-plane side. Tunnel should consume already-resolved routing/session intent rather than deriving mesh identity from FakeDNS addresses.

Current safe slice:

- Keep FakeDNS CIDR parsing shared between in-memory and file configuration.
- Reject invalid persisted `dns.fake_dns_range` before tunnel creation side effects.
- Keep absent-key semantics as the default `198.18.0.0/15`.

Future MagicDNS work:

- Expand mesh-side MagicDNS beyond local static records into DNS serving, search-domain handling, and control-plane distribution.
- Do not persist FakeDNS cache mappings; they are derived runtime state.

## Threading Model

TurboNet Tunnel is designed to be single-threaded (per instance) or event-driven, with one caller-driven `CNet` owner per proxy.

*   **Non-blocking I/O**: All socket and TUN operations are non-blocking.
*   **Event Loop**: `tunnel_poll()` or `tunnel_run()` drives TUN polling and the proxy's `CNet` client.
*   **Concurrency**: User acts as the driver; explicitly calling the currently non-blocking `tunnel_poll` allows integration into existing application loops (e.g., game engines or UI threads). The timeout parameter is reserved until TUN and NativeIO waits share one wake mechanism.


## CNet transport ownership（迁移阶段 F）

代理独占一个 CNet client；`tunnel_poll()` 在拥有者线程推进，禁止递归 poll。连接 observer 保留到 CLOSED/FAILED；session 销毁立即撤销应用回调和 user_data，内存由 poll 返回后的有界列表扫描回收。`tunnel_stop()` 先释放 session，再排空并销毁 client；重启重新初始化同一代理的 client。回调内 stop/destroy 延后到本轮 poll 返回，避免仍在执行的 session 调用栈访问已释放对象。底层排空失败时保留拥有者并报告错误，禁止强行释放仍被 CNet 引用的内存。

握手写入成功入队只表示 admission；对应的 `on_send` 才提交下一协议阶段并请求响应读取。SOCKS5 greeting/auth/CONNECT 和 HTTP CONNECT 均处理任意分片；CONNECT 响应同包尾部作为借用数据交付。HTTP 头最多 4096 字节，扫描依据长度，不要求 NUL。应用发送复制一次到 Salts retained buffer，再由 CNet 持有到写入终态；应用原始缓冲区可在 admission 返回后释放或修改。session 的 ACK、序号和发送计数只在发送/暂存 admission 成功后提交；flush 失败保留原缓冲区。

TLS 使用 CNet 可复用的验证 profile；CA、SNI 在初始化时消费，活动连接持有独立引用。`tls_verify=0` 配合 TLS 返回 NOT_SUPPORTED；`tunnel_config_init()` 和 HTTPS URL 解析默认启用验证。新配置先验证字符串、端口和信任材料，再关闭旧连接并提交配置，旧握手不会读取新凭据。SS/VMess/Trojan、direct TCP 上配置 TLS，以及 UDP relay 均明确拒绝，不创建无功能连接。

硬上限：连接/observer 为 `TUNNEL_MAX_SESSIONS`（65536），命令和事件队列各 256，NativeIO 请求为连接上限的 4 倍；单次发送/接收 65536 字节，TLS I/O 使用 CNet 最低容量。连接、写入和 TLS 握手期限为 30 秒，读取期限使用 session_timeout（0 采用既有 300 秒默认值）。这些值集中在代理创建入口，失败不切换网络后端。

`test_proxy_cnet` 使用真实 loopback TCP/TLS 与私有 CA，经过生产 `tunnel_poll()` 和 NAT/session SYN 路径。测试不打开特权 TUN 接口，因此 Linux TUN 系统配置、Windows/macOS 运行和完整 IPv6 TUN 转发仍须平台集成验证。

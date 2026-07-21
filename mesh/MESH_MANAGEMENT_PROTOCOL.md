# Mesh 节点管理与 Gossip 协议设计（MMP/1）

## 文档状态

本文定义目标架构和 wire protocol，不表示当前代码已经实现这些能力。当前实现和
测试状态仍以 [`MESH_STATUS.md`](MESH_STATUS.md) 为准。平台整体边界见
[`MESH_PLATFORM_DESIGN.md`](MESH_PLATFORM_DESIGN.md)。面向用户的 Controller、enrollment、
Grants、CLI/API 和审计查询见
[`MESH_PRODUCT_CONTROL_PLANE.md`](MESH_PRODUCT_CONTROL_PLANE.md)。

协议名称为 Mesh Management Protocol，版本记为 MMP/1。

## 决策摘要

节点管理采用两个互补机制：

- Gossip 传播成员状态、运行状态、链路指标、期望状态摘要和审计锚点。这些数据允许
  最终一致，且每一种记录都有明确 owner、版本和 TTL。
- 目标 RPC 传递需要立即执行并返回结果的管理命令。命令必须端到端签名、持久化去重、
  幂等执行并返回签名回执。

MMP 不把 Gossip 当作 consensus，也不允许收到任意字符串后执行 shell。高风险动作由
本地 policy 和管理签名共同授权；exit profile 还需要 quorum。信任根只能通过本机部署
渠道变更，不提供远程 operation。

每台主机运行独立的常驻 `mesh-agent`。OS service manager 负责保证 agent 存活；agent
通过受限的本地 supervisor adapter 管理 `meshd`。`meshd` 停止或重启时，管理网络仍然
可达。远程协议永远不能停止 `mesh-agent` 自身。

## 当前事实与设计约束

当前代码提供了可复用基础，但不能直接承载生产管理命令：

- [`P2P_MSG_GOSSIP`](../p2p/include/p2p_types.h#L63) 已有枚举，但
  [dispatcher](../p2p/src/protocol/handlers.c#L120) 没有对应 handler。
- `p2p_gossip_start()` 当前只对本地 node ID 发起 Kademlia lookup，用于 bucket refresh，
  并不实现成员 Gossip（[`node.c`](../p2p/src/core/node.c#L942)）。
- DHT STORE 会接受已连接 peer 的 value 并覆盖本地副本；value 没有 owner signature、
  epoch 或 TTL，因此 DHT 只能作为发现提示，不能作为管理事实源
  （[`handlers.c`](../p2p/src/protocol/handlers.c#L277)）。
- `MESH_CAP_ROUTED_CONTROL`、`MESH_CAP_SIGNED_ROUTES` 和 `MESH_CAP_POLICY_EPOCH` 仍是
  reserved capability（[`turbo_mesh.h`](include/turbo_mesh.h#L57)）；现有 routed control 因缺少
  端到端 origin authentication 而 fail closed，并已有对应
  [回归测试](tests/test_mesh_paths.c#L517)。
- 当前 P2P 有序 stream 已只接受下一个期望 counter；重复、跳号、认证失败和 counter
  耗尽均返回 `P2P_ERR_CRYPTO`，且失败不推进接收状态，并已有 replay/out-of-order/wrap
  回归测试（[`p2p_crypto.c`](../p2p/src/crypto/p2p_crypto.c#L145)、
  [`test_p2p.c`](../p2p/tests/test_p2p.c#L1682)）。MMP 仍必须保留独立的
  sequence/duplicate/command journal 防线，不能只依赖相邻 transport。
- P2P identity 和 ephemeral handshake key 已统一使用 TurboUtils `turbo_secure_random()`；
  CSPRNG 失败返回 `P2P_ERR_CRYPTO`，不提交半生成 identity，也不继续握手，并有成功、
  零长度和非法参数契约测试（[`p2p_crypto.c`](../p2p/src/crypto/p2p_crypto.c#L31)、
  [`test_p2p.c`](../p2p/tests/test_p2p.c#L250)）。
- P2P 的 `P2P_MSG_CUSTOM` payload 上限为 65536 字节，发送 API 对超限数据会截断。MMP
  encoder 必须在调用发送 API 前执行更严格的显式长度校验，禁止依赖截断行为
  （[`internal.h`](../p2p/src/internal.h#L47)、[`p2p_api.c`](../p2p/src/api/p2p_api.c#L912)）。

## 目标与非目标

### 目标

- eu、bj、sh、local 等节点无需逐台 SSH 即可查询、启动、停止、重启和诊断 `meshd`。
- 节点离线后重新加入时，成员和期望状态可以自动收敛。
- 所有状态变化都能追溯到稳定 node identity、管理 signer 和单调版本。
- 数据面停止时管理面仍可用；管理面分区时数据面不被自动停止。
- 新能力通过独立 daemon、协议版本和 feature negotiation 加法式上线。
- 队列、记录、消息、重试、签名验证和审计存储全部有上限。

### 非目标

- MMP 不承载业务 packet、媒体数据或通用文件传输。
- MMP/1 不传播私钥、token、密码或包含秘密的完整配置。
- MMP/1 不提供任意 shell、任意文件路径、任意环境变量或远程代码执行。
- Gossip 不保证线性一致、全局顺序或同时执行。
- DHT 不保存命令、命令结果、policy 正文或管理信任根。
- `mesh_network_t` 不拥有 OS service manager、命令 journal 或管理授权状态。

## 候选方案与取舍

| 方案 | 优点 | 主要问题 | 结论 |
|------|------|----------|------|
| 管理能力嵌入 `meshd` | 进程和端口最少 | `meshd` 停止后无法接收启动命令；管理状态与 packet runtime 耦合 | 不采用 |
| 仅 SSH/tmux/systemd | 直接复用部署能力 | 无成员收敛、期望状态、幂等回执和统一审计；密钥权限过大 | 只保留 break-glass |
| 中央 controller + agent | 容易做强编排和 UI | controller 可达性成为管理依赖，边缘分区时状态不可交换 | 可作为 MMP 上层，不作为底层协议 |
| sidecar agent + Gossip/RPC | 数据面停止后仍可管理；弱连接下可收敛；无单一事实副本 | 新增进程、endpoint、身份和部署单元 | 采用 |

选择 sidecar 的迁移成本为中等：需要新 executable、service unit、管理配置、证书和本地
IPC，但不修改现有 packet wire format，也不要求一次性迁移所有节点。运行成本是每台主机
一个低频控制进程和一组有界管理连接；换取的是数据面故障时仍有独立恢复路径。

## 总体架构

```text
                           管理签名者 / CI / CLI
                                    │
                         signed desired state / RPC
                                    ▼
┌──────────────────────────────────────────────────────────────┐
│ MMP management overlay                                      │
│ membership │ anti-entropy │ desired state │ command │ audit │
│                                                              │
│ eu mesh-agent ── bj mesh-agent ── sh mesh-agent ── local     │
└─────────┬─────────────┬─────────────┬─────────────┬──────────┘
          │ local IPC   │ local IPC   │ local IPC   │ local IPC
          ▼             ▼             ▼             ▼
       meshd          meshd          meshd          meshd
          │             │             │             │
          └──────────── Mesh data plane / TUN ──────┘
```

### 进程边界

`mesh-agent`：

- 使用独立 P2P/CoroNet context 和管理 endpoint，生命周期不依赖 `meshd`。
- 拥有 MMP identity、membership、record store、command journal 和 audit anchor。
- 只通过 `mesh_supervisor_ops_t` 白名单操作 `meshd`。
- 不创建 TUN，不安装路由，不修改 NAT/firewall，不进入 packet 热路径。
- 默认以非特权账户运行；service manager ACL 只授予查询和管理固定 `meshd` unit 的能力，
  本地 IPC 使用 OS peer credential、固定 message schema 和请求/响应大小上限。

`meshd`：

- 继续拥有 Mesh runtime、TUN 和原子化 OS platform transaction。
- 通过本地只读/命令 IPC 暴露 status、reload 和 graceful shutdown。
- 不解析 MMP 网络帧，不保存集群成员表。

OS service manager：

- systemd、Windows SCM 或 launchd 保证 `mesh-agent` 自动启动和崩溃恢复。
- `meshd` 是否运行由 agent 的 desired-state reconciler 和 service manager 共同决定。
- 手工停用 agent 属于本机管理员 break-glass 操作，不通过 MMP 暴露。

### 传输边界

MMP 是 transport-independent 的应用协议，要求下层提供：

- 可靠、有序的 peer stream。
- adjacent peer authentication 和传输加密。
- 显式 connect/close/error 语义。
- 64 KiB 以上的帧接收不是必需能力。

首个实现复用 TurboP2P 的 authenticated stream 和 CoroNet event loop，但使用独立
management context。MMP frame 暂装入 `P2P_MSG_CUSTOM`；magic 和 MMP HELLO 将它与
现有 `MESH_HELLO:` 等文本 payload 区分。MMP/1 不启用未实现的 `P2P_MSG_GOSSIP`
handler，避免让通用 P2P 层拥有 Mesh 管理状态。

当前内部 runtime 先实现了与 endpoint discovery 解耦的可靠 byte-stream framing：
`mesh_mgmt_transport` 使用固定 16 KiB frame buffer，并最多保留一个不超过 16 KiB、尚未消费的
recv chunk，因此拆包和一块内多帧都不会丢字节或产生无界扩容。完整 frame 以 borrowed receipt
返回；dispatcher/领域层用完其 borrowed view 后，单 event-loop owner 必须以匹配 generation
显式 commit。陈旧 receipt 不推进连接。非法长度/canonical frame 或 recv/send ambiguity 令
transport terminal，调用方必须关闭 socket，不得在半可信字节流上继续。

首个 socket adapter 接受 caller-owned、已经完成握手的 CoroNet TLS 1.3 connection，并以
RFC 9266 exporter query 作为类型、open-state、版本和客户端证书验证门；raw TCP、未完成 TLS、
非 TLS 1.3 或客户端未验证 server certificate 均在分配 transport 状态前拒绝。adapter 释放
每个 recv buffer，但不关闭 socket。

当前另有内部 `mesh_mgmt_p2p_adapter`：它只接受 `p2p_peer_get_public_key()` 已能返回加密握手
静态公钥的 peer，并把该 32-byte key 作为 remote transport peer ID。每条 `P2P_MSG_CUSTOM`
必须承载且只承载一个不超过 16 KiB 的完整 MMP frame；callback bytes 必须在 callback 返回前
由 transport 同步消费和 release。adapter 发送前仍由通用 transport 完整解码 frame，因此不会
触发 P2P API 对超大 payload 的静默截断。外层 handler 先按 `TMGM` magic 分流，旧 custom
payload 返回 `NOT_MMP` 且不改变 MMP 状态。该 adapter 不是 TLS adapter 的 fallback，也不注册
handler、不拥有 peer/node。静态公钥“可读取”本身不等于节点已认证；只有后续 signed HELLO
通过 certificate/management-key/transport-key 联合校验后才建立 MMP identity。P2P 握手身份
绑定、降级和密钥派生专项审查仍是 production 门槛。

agent 使用独立的 management-transport X25519 identity，不读取或复用数据面 X25519
private key。管理证书同时绑定 transport peer ID、Ed25519 management key 和被管理的
data-plane node ID；HELLO 必须把 transport 认证结果与该绑定逐项比较。

当前 P2P 加密接收路径已对可靠有序 stream 强制校验预期 nonce/counter；这只关闭相邻
transport replay，不替代 MMP 的端到端 sequence、duplicate cache 和 command journal。
production binding 的剩余安全门槛是对握手身份绑定、降级、密钥派生及 MMP 多层 replay
状态做专项审查。在门槛全部通过前，MMP 只允许实验环境的 observer 模式，不能执行远程
副作用。

MMP/1 targeted RPC 只允许 direct 或一层 management relay：

```text
origin agent -> target agent
origin agent -> management relay -> target agent
```

relay 必须与 target 有已认证的直接 session。任意多跳不是 MMP/1 的兼容要求；Gossip
仍可通过多轮邻接交换跨越多跳拓扑。部署可配置多个 relay，relay 只提供可达性，不拥有
desired state 或命令授权。

relay 的 session table 只从完成认证的 HELLO 建立，键为 `(target node ID, node epoch,
incarnation)`。更高 epoch/incarnation 替换旧 session。HELLO 携带每连接随机
`connection_id`；同版本重复连接按双方 node ID、initiator ID 和 connection ID 的 canonical
tuple 确定唯一保留者。close 事件必须携带 session generation，只能删除对应代的 entry，
避免旧连接的迟到 close 清掉新连接。

endpoint 由显式配置或已签名的 DHT endpoint record 发现。首个部署建议 eu 作为 bootstrap/
management relay，bj、sh、local 只需出站连接，并在可达时建立 direct session。监听端口
必须配置且启动时检查占用；可以选择空闲的 8443，但 agent 不停止 Docker Compose、
不抢占 80/443/8443，也不把 eu relay 自动解释为 exit node。

当消息跨 relay 转发时，hop transport 只认证相邻 peer；origin 和 target 必须依靠
MMP envelope 的端到端签名重新验证。MMP/1 payload 不承载秘密，因此 relay 可见
管理动作元数据是明确限制。未来若需要传输 secret，必须增加独立的端到端加密 feature，
不能仅依靠 hop encryption。

## 单一事实源与合并规则

| 状态 | 唯一 owner | 合并键 | 合并规则 |
|------|------------|--------|----------|
| agent 存活/能力 | 节点自身 | node ID | 较高 node epoch/incarnation/sequence |
| suspect/dead 观察 | 观察节点 | subject + reporter | SWIM 状态规则和 TTL |
| `meshd` 实际状态 | 节点自身 agent | node ID + service | 较高 node epoch/incarnation/sequence |
| link metric | 执行测量的节点 | origin + neighbor + path | 较高 sequence；短 TTL |
| desired service state | 被授权的 policy owner | target + service | 较高 policy epoch/generation |
| policy/config 引用 | policy owner 或 quorum | target scope | 较高 policy epoch；签名满足权限 |
| command | 发起 signer | command ID | immutable；重复请求返回既有结果 |
| command result | 目标 agent | command ID + target | terminal 状态不可回退 |
| audit anchor | 生成日志的节点 | node ID + log epoch | 较高 sequence；append-only |

通用 last-writer-wins map 不进入核心设计。每一种 record kind 都有类型化 validator 和
merge function，未知 kind 不能修改已知状态，也不能在未协商 feature 时继续扩散。

Gossip 数据使用内层 `SignedRecord`，避免转发节点冒充原始 owner。其 canonical 字段为：

```text
record_kind | record_key | owner_principal_key | owner_node_id? |
owner_epoch | incarnation | sequence | issued_at | expires_at |
payload_hash | canonical_payload | owner_signature
```

`owner_node_id` 对节点运行状态、membership self record 和 link metric 是必填；对 operator、
CI 或 policy authority 发布的 desired state 可以为空。外层 MMP envelope 认证本次相邻
发送者，内层 owner signature 决定 record 是否能修改事实源。任意 peer 可以转发已经验证
的 SignedRecord，但不能重写 owner、version、expiry 或 payload。

时钟只用于 expiry、展示和审计；状态新旧不能只比较 wall clock。每个节点持久化：

- `node_epoch`：节点 enrollment authority 授予；重新注册时递增。
- `incarnation`：agent 每次启动以及反驳 SUSPECT 时递增并原子保存。
- `session_id`：每次 agent 启动生成的随机 128-bit ID；`meshd` 的启动实例另用
  `service_instance_id` 标识，随机 ID 本身不参与新旧排序。
- `origin_sequence`：当前 principal session/incarnation 内单调递增的 64-bit 序号。

incarnation 必须先原子持久化再发送新 session 的任何 frame。序号 wrap 使用 RFC 1982
serial arithmetic；跨 incarnation 不比较 sequence。

## MMP/1 Wire Envelope

### Framing

MMP frame 按以下顺序编码：

```text
fixed prefix | canonical header TLVs | canonical payload TLVs | signature
```

fixed prefix：

| 字段 | 类型 | 约束 |
|------|------|------|
| magic | 4 bytes | ASCII `TMGM` |
| major | u8 | MMP/1 为 `1` |
| minor | u8 | 首版为 `0` |
| kind | u8 | 见消息类型表 |
| flags | u8 | 未知 flag 必须拒绝 |
| header_length | u16 | network byte order，最大 512 |
| payload_length | u32 | network byte order，受 frame 上限约束 |

header 和 payload 使用 TLV：

```text
field_id:u16 | field_length:u16 | value:field_length bytes
```

Canonical encoding 规则：

- 整数使用 network byte order 和字段规定的固定宽度。
- TLV 按 `field_id` 严格升序；未声明可重复的字段出现两次即拒绝。
- string 是无 NUL 的 UTF-8，并受字段长度上限约束。
- IP endpoint 使用 address-family + binary address + u16 port，不使用自由格式字符串。
- minor 版本新增的未知 TLV 可以跳过；缺少当前 kind 的 required TLV 必须拒绝。
- 禁止把 C struct 内存直接当作 wire bytes，避免 padding、endianness 和 ABI 差异。

### Required header fields

| ID | 字段 | 长度 | 说明 |
|----|------|------|------|
| `0x0001` | mesh_id_hash | 32 | BLAKE2b-256 mesh namespace |
| `0x0002` | origin_principal_key | 32 | Ed25519 public key |
| `0x0003` | origin_node_id | 32 | node principal 的数据面 X25519 identity；非节点 principal 全零 |
| `0x0004` | target_node_id | 32 | 全零表示 Gossip fanout；命令必须非零 |
| `0x0005` | principal_epoch | 8 | certificate/enrollment epoch |
| `0x0006` | incarnation | 8 | agent incarnation；非节点 principal 为零 |
| `0x0007` | session_id | 16 | agent 或 operator/CI 的随机 session ID |
| `0x0008` | origin_sequence | 8 | origin 单调序号 |
| `0x0009` | message_id | 16 | 随机消息 ID；用于 relay/duplicate suppression |
| `0x000a` | issued_at_ms | 8 | Unix epoch milliseconds |
| `0x000b` | expires_at_ms | 8 | 必须晚于 issued_at |
| `0x000c` | forward_budget | 1 | direct 为 0；允许一层 relay wrapper 时为 1 |
| `0x000d` | payload_hash | 32 | BLAKE2b-256 canonical payload |
| `0x000e` | certificate_serial | 8 | 授权证书序号 |

signature 固定为 64-byte Ed25519。签名输入是：

```text
"TurboMesh-MMP-v1\0" || fixed_prefix || canonical_header_tlvs || canonical_payload
```

signature 字段自身不包含在签名输入中。接收端先完成 frame 长度、TLV canonical 和资源
上限检查，再计算 hash 和验证签名，最后才解析可产生状态变化的 payload。

当前代码包含未安装的内部 `mesh_mgmt_codec`、`mesh_mgmt_transport`、
`mesh_mgmt_coronet_adapter`、`mesh_mgmt_envelope`、
`mesh_mgmt_identity`、`mesh_mgmt_session`、`mesh_mgmt_replay` 与
`mesh_mgmt_dispatch`，以及握手 owner `mesh_mgmt_connection`、`mesh_mgmt_peer`、
`mesh_mgmt_peer_signer`、`mesh_mgmt_p2p_adapter`、`mesh_mgmt_p2p_peer` 静态模块。codec 在任何
密码运算前验证 magic、major、已知 kind/flag、16 KiB frame、512 B header、精确总长以及
header/payload TLV 的严格升序、去重和边界。envelope 冻结上表 14 个 common-header field ID，
按固定宽度 canonical 编解码，计算并常量时间比较 payload BLAKE2b-256，并验证 domain-separated
Ed25519 signature；只有完整通过后才返回 borrowed payload view 与已解码 header。MMP/1.0
当前拒绝未知 header field 和非零 minor；HELLO 虽能协商 minor 0，未来 minor 仍必须先增加
对应 envelope/parser 才能开放。identity/session 已实现 direct trust certificate、frame/cert
时间窗口、HELLO/ACK schema、transport/key/node/session/incarnation binding 和
capability/resource negotiation。Stream V1 ticket request/issued payload 与 signed endpoint
record payload 已有固定 schema；前者还有认证 session 到 responder ticket store 的领域适配，
其余消息 payload schema 仍未实现。
replay 实现每个认证 origin/session 的有界 message-ID cache
与 RFC 1982 sequence gate；dispatch 唯一持有 `structural decode -> envelope verify -> session
gate -> replay prepare/commit -> typed observer event` 顺序。它们仍不做多级证书链、
rotation/revocation、通用 ACL/角色授权、command journal 或持久化。内部 agent runtime 已能
创建专用 P2P node/listener、独占 peer/message callback、管理有界 per-peer MMP runtime，并按
显式 bootstrap endpoint 自动重连，并能在 direct-trust 验证后应用 signed endpoint frame；但仍
不主动读取 DHT、读取 daemon 配置或加载持久密钥，也不是可部署的 service。因此即使真实 TLS
1.3 loopback 与真实加密 P2P
双向握手均已验证，也不能视为完整的 MMP/1 agent。

当前 vendored Monocypher 暴露的是 `curve25519 + BLAKE2b` 的 `crypto_eddsa_*` 接口，
不是 RFC 8032 Ed25519。MMP/1 使用已经作为 P2P 私有依赖存在的 OpenSSL EVP Ed25519，
并通过薄 `mesh_mgmt_crypto` adapter 隔离第三方类型和错误码。该内部 adapter 已实现从
32-byte private seed 派生 public key、one-shot Ed25519 sign/verify 和 Monocypher
BLAKE2b-256，失败输出清零；RFC 8032 与 BLAKE2b-256 固定向量已有回归。它不生成或持久化
密钥。domain-separated frame 和 payload hash 已由 envelope 组成完整验证流水线；direct
issuer signature 与 principal/node/transport binding 由 identity/session 负责，完整 PKI、
revocation 与 operation authorization 仍由后续 trust/policy 层负责。

## 消息类型

| kind | 名称 | 通道 | 作用 |
|------|------|------|------|
| `0x01` | HELLO | direct | 版本、feature、证书和 node binding |
| `0x02` | HELLO_ACK | direct | 接受的版本/feature 或明确拒绝原因 |
| `0x03` | FORWARD | one relay | 包装一个完整、已签名的 targeted RPC frame |
| `0x10` | PROBE | direct | SWIM direct ping |
| `0x11` | PROBE_ACK | direct | 确认 probe nonce 和目标 incarnation |
| `0x12` | INDIRECT_PROBE | direct | 请求第三方探测 subject |
| `0x13` | INDIRECT_ACK | direct | 返回间接探测结果 |
| `0x14` | MEMBERSHIP_DELTA | gossip | ALIVE/SUSPECT/DEAD/LEFT record |
| `0x20` | DIGEST | gossip | 本地 record version/hash 摘要页 |
| `0x21` | DELTA_REQUEST | direct | 请求缺失或更新的 record keys |
| `0x22` | DELTA_BATCH | direct | 返回有界 signed records |
| `0x30` | COMMAND_REQUEST | targeted RPC | 提交幂等管理命令 |
| `0x31` | COMMAND_ACCEPTED | targeted RPC | 表示命令已验证并持久化 |
| `0x32` | COMMAND_RESULT | targeted RPC | 返回执行阶段或 terminal result |
| `0x33` | COMMAND_STATUS | targeted RPC | 按 command ID 查询既有结果 |
| `0x40` | AUDIT_ANCHOR | gossip | 发布本地审计 hash-chain anchor |
| `0x50` | STREAM_TICKET_REQUEST | direct | 请求一个有界、一次性的 Stream V1 admission ticket |
| `0x51` | STREAM_TICKET_ISSUED | direct | 返回与 request message ID 关联的 responder-owned ticket |
| `0x7f` | ERROR | direct/RPC | 结构化协议错误；不包含 secret |

Gossip kind 只发送给已建立 HELLO 的相邻 peer。Targeted RPC 优先 direct；需要 relay 时，
origin 将 inner frame 的 `forward_budget` 设为 1，relay 验证 inner signature 后把原始 frame
逐字节放入自己签名的 FORWARD payload，并把 outer `forward_budget` 设为 0。target 同时
验证 outer relay 和 inner origin，禁止嵌套第二层 FORWARD。relay 不修改 inner frame，
不替 target 做命令授权，也不缓存执行结果。encoder 必须保证 FORWARD wrapper 与 inner
frame 的总长仍不超过协商后的 frame 上限；超限直接返回 `RESOURCE_EXHAUSTED`，不得截断。

## HELLO 与能力协商

连接完成后双方必须先交换 HELLO，其他 MMP frame 在 HELLO_ACK 前全部拒绝。

HELLO payload 包含：

- 支持的 `(major, min_minor, max_minor)`。
- feature bitmap：membership、anti-entropy、targeted RPC、audit anchor、stream ticket。
- agent build/version 和 platform enum。
- management certificate 及其 issuer chain hash。
- principal type；node principal 还必须声明 management key 与 data-plane node ID 的绑定。
- 每连接随机 `connection_id`，只用于重复连接的确定性裁决，不作为身份。
- 本地最大 frame、digest entries 和 delta batch limits。

协商结果取双方能力交集和各项资源限制的较小值。major 不同直接返回
`UNSUPPORTED_VERSION`；未知 minor 和 feature 被忽略，不能隐式启用。

证书是 canonical signed authorization record，至少包含 principal type、management public
key、可选 management-transport peer ID、可选 managed node ID、mesh ID、roles、target
scope、validity、serial、issuer key 和 issuer signature。node principal 必须同时绑定
transport peer ID 与 managed node ID；operator/CI/policy authority 不伪造 node ID，但仍受
role 和 target scope 约束。
首次 trust root 通过本机配置/部署注入，不进行 trust-on-first-use。

当前 MMP/1.0 certificate wire format 冻结为以下 canonical TLV。`issuer_signature` 的签名
输入为 `"TurboMesh-MMP-Cert-v1\0" || field 0x0001..0x000d`；signature TLV 自身不进入
签名输入。

| ID | certificate 字段 | 长度 |
|----|--------------------|------|
| `0x0001` | format_version | 1 |
| `0x0002` | principal_type | 1 |
| `0x0003` | management_key | 32 |
| `0x0004` | transport_peer_id | 32 |
| `0x0005` | managed_node_id | 32 |
| `0x0006` | mesh_id_hash | 32 |
| `0x0007` | roles | 8 |
| `0x0008` | target_scope_hash | 32 |
| `0x0009` | not_before_ms | 8 |
| `0x000a` | expires_at_ms | 8 |
| `0x000b` | serial | 8 |
| `0x000c` | principal_epoch | 8 |
| `0x000d` | issuer_key | 32 |
| `0x000e` | issuer_signature | 64 |

首个内部 validator 只接受本机配置的 issuer 直接签发的 certificate；`issuer_chain_hash` 是
该 direct trust anchor public key 的 BLAKE2b-256。多级 chain、rotation overlap、revocation
cache 和 quorum issuer 尚未进入这个切片，不能把 direct-validator 宣称为完整 PKI。

HELLO/HELLO_ACK payload field ID 同样固定。HELLO 为 `0x0001..0x000f`：major、min_minor、
max_minor、features、platform、build_version、certificate、issuer_chain_hash、principal_type、
management_key、managed_node_id、connection_id、max_frame、max_digest_entries、
max_delta_batch。HELLO_ACK 为 `0x0001..0x0007`：selected_major、selected_minor、features、
max_frame、max_digest_entries、max_delta_batch、peer_connection_id。两者都必须严格升序且
不允许 minor 0 的未知字段。

当前内部 `mesh_mgmt_session` 状态机要求双方都发送 HELLO、验证远端 HELLO、发送 ACK 并
收到与本地协商结果完全一致的 ACK 后才进入 `ESTABLISHED`。HELLO 验证逐项比较 transport
peer ID、certificate management key、managed node ID、envelope origin、mesh、principal
epoch、certificate serial 和有效期；任一失败令该 session 进入 terminal `FAILED`。未建立
session 的其他 kind fail closed；建立后仍按 negotiated feature gate 拒绝未协商能力。
session 接口接收 raw frame 并在边界内部强制执行 envelope verification，不接受由调用方
声称“已验证”的可伪造 C struct。HELLO 验证成功后保存签名 header 的 `session_id` 与
`incarnation`，HELLO_ACK 及建立后的每个 frame 都必须与其一致，禁止在同一相邻 session
内静默切换 origin session。
该模块仍是未安装且未接网络的纯状态机，不保存私钥、不读取 trust store、不做撤销查询，
也不拥有 transport send/close。

当前内部 `mesh_mgmt_connection` 把一个相邻连接的 bounded transport、dispatcher、已认证
transport peer ID 和同步 typed-event consumer 收敛到同一个 event-loop owner。接收顺序固定为
`receive receipt -> authenticate/dispatch -> synchronous consumer -> receipt commit`；consumer 只能在
回调期间借用 envelope view，必须先复制需要延后使用的数据。分发失败会先消费已完整读取的
transport receipt，再把连接置为 terminal；consumer 拒绝时 replay 已经由 dispatcher 提交，
因此同样先提交 receipt 再 terminal，禁止在同一连接重试产生不确定副作用。HELLO/HELLO_ACK
发送采用 `send -> local session mark` 顺序；send 之后若状态提交失败，外部副作用无法回滚，连接
立即 terminal，由上层关闭 socket。该 owner 不记录日志、不保存私钥，也不拥有/关闭 CoroNet
socket；CoroNet adapter 只在 live TLS 1.3 socket 上构造借用 IO。实际 `mesh-agent` listener、
连接重试、endpoint discovery、持久化密钥加载、post-handshake envelope 构造和事件领域编排仍未实现。

当前内部 `mesh_mgmt_peer` 在 connection owner 之上驱动相邻握手，但不持有私钥：未来 agent
注入 HELLO/HELLO_ACK builder，builder 只在同步调用期间借出完整 signed frame。driver 在任何
socket send 前重新验证本地 HELLO signature、direct-trust certificate、时间、mesh、transport
identity、node/management identity、connection ID、features 与资源上限；并保存 HELLO 的本地
origin session binding。收到远端 HELLO 后，先让 consumer 接受 typed event 并提交 receipt，
再调用 ACK builder；返回的 ACK 必须签名有效、与 accepted negotiation 逐字段一致，并与本地
HELLO 使用同一 principal/node/session/incarnation/epoch/certificate binding。builder 失败、签名
无效、ACK 不一致或 send ambiguity 都令 peer 和 connection terminal，且不会重试该 HELLO。

当前内部 `mesh_mgmt_peer_signer` 实现上述 builder 契约。它在初始化时重新验证 direct-trust
certificate、management private/public key、mesh/node/transport 绑定，复制由 agent 已加载的
32-byte Ed25519 seed，并在 destroy 时通过不可优化掉的 wipe 清除 seed 与 frame buffer。每个
HELLO/ACK frame 使用 TurboUtils 系统 CSPRNG 生成独立 message ID，使用 agent session 的
incarnation/session ID 和单调 sequence，并限制本地 frame TTL 不超过 60 秒；CSPRNG、时间溢出、
payload 编码或签名失败均不推进 sequence，也不返回可发送 frame。测试可显式注入 clock/entropy，
生产默认没有弱随机 fallback。该模块不生成、读取或持久化 key，不替代 OS keychain/受限密钥文件。

当前内部 `mesh_mgmt_p2p_peer` 是一个 per-connected-peer composition root：初始化时比较
`p2p_node_get_public_key()` 与本地证书 transport binding，以远端已学习的 P2P 静态公钥初始化
connection，再组合 adapter、短期 signer 和 peer driver。它能在真实的两个加密 P2P 节点之间
双向发送 signed HELLO/HELLO_ACK 并建立 session；本地 transport key 不匹配、未认证远端、
非完整单 frame borrow、签名或协议失败都会 fail closed。它借用 node/peer，不注册全局 callback，
也不负责 peer 表或连接策略。

当前内部 `mesh_mgmt_agent_router` 在一个 P2P node 上独占 peer/message callback，使用
TurboUtils `turbo_vec_t` 一次性分配不超过 64 个固定 slot，并为每个已通过 P2P 静态密钥握手的
peer 创建上述短期 runtime。router 初始化时先核对本地 P2P key、证书 transport binding、signer
模板和 dispatch 资源配置；任一不一致均在注册 callback 前失败。每个 router 启动时从系统
CSPRNG 取得 128-bit connection namespace，再与 checked 64-bit 单调序号组合 connection ID；
同一 router 生命周期内不会复用，随机源失败、全零 namespace 或序号空间耗尽时拒绝新连接，
不使用弱随机 fallback。MMP 消息只路由到对应 slot，旧 custom payload 交给显式 legacy callback；
协议失败、未知 MMP peer 和容量耗尽均关闭相关 transport，断连 callback 只回收对应代 runtime。
stop 会先断开所有受管 peer，再注销 callback，但不销毁 P2P node。真实双节点回归已覆盖 signed
HELLO/ACK、legacy 分流、断连清理以及同一 node 重连时 connection ID 更新；可选 close callback
携带 transport/protocol/local-stop 原因，使外层只在唯一错误消费边界安排重连或隔离。

当前内部 `mesh_mgmt_endpoint_pool` 提供与 router 解耦的有界拨号事实源。它按预期的 32-byte
transport identity 建索引，最多保存 64 个 endpoint；本机 static 配置优先级高于 discovery
record，verified record 只能通过显式 `apply_verified` trust boundary 进入，必须已有非零 epoch、
未过期且不能覆盖 static 记录。同 endpoint 绑定两个 identity、同 epoch 内容冲突、过期或倒退
update 均 fail closed；pool 不读取原始 DHT bytes，也不把普通 DHT value 自行解释为可信地址。
caller event loop 显式调用 tick；每次连接只有一个 DIALING 状态和有界 timeout，失败采用配置化
指数退避及最多 25% CSPRNG jitter。连续 protocol failure 达到配置阈值后进入 QUARANTINED，只有
显式 reset 才能恢复；随机源失败同样隔离该 endpoint，不使用同步重试或弱随机 fallback。verified
record 在连接存续期过期时不会中途伪造 close，但该连接关闭后转为 EXPIRED 且不再拨号。
signed session 的 remote transport identity 不在 pool 时返回 `NOT_FOUND`，绝不隐式视为 admission
成功：严格 outbound bootstrap owner 必须拒绝该 session；listener 若要接受动态成员，必须另外
通过 signed membership policy，不能拿“连接来自某个已配置 IP”代替身份授权。

当前内部 `mesh_mgmt_agent_runtime` 是上述两个 owner 的一次性 composition root。初始化要求显式
非零 listen port、调用方提供的 P2P private key、借用的 signer/dispatch template、全部 retry/
timeout/quarantine 上限和可选 static bootstrap；没有 80、443 或 8443 默认值。它创建专用 P2P
node，先完成 transport identity 对照和所有 bootstrap 校验，再安装 router、启动尚未拨号的 pool
并 bind listener。owner loop 显式 poll，先推进 endpoint 状态再运行一次 CoroNet NOWAIT；stop
停止重连、以 local-stop 断开受管 peer、注销 callback 并销毁专用 node，停止后的实例不可重启。
未知 signed session 默认拒绝；只有显式 admission callback 可把 `NOT_FOUND` 转为接受，IP 来源
永远不能替代 membership policy。真实双节点回归覆盖首次连接、显式入站准入、停止、backoff 以及
使用相同 identity/port 重建 listener 后自动恢复 signed session。

runtime 不读取或持久化 key。配置文件、secure key loader、DHT 获取/刷新与 anti-entropy、
bootstrap/relay 选择、service manager 和审计落盘仍由后续 daemon owner 实现。
该 runtime 使用专用 node，因此其 callback 注册不会与现有 Mesh 数据面 handler 叠加。

runtime 可显式消费已经存在于本地 P2P DHT cache 的 endpoint frame：先构造 canonical owner key，
再读取一个完整 signed MMP frame，使用调用方 trust store 提供的 certificate/issuer 验证并调用
`apply_verified`。该入口只读 cache，不启动同步 network lookup；cache miss 明确失败，避免在 owner
API 内运行事件循环造成 callback 重入。主动 lookup、refresh timer 和 certificate store 仍属于
后续 daemon owner。

本地发布路径从已验证的 signer/certificate 事实源构造 owner/transport binding，使用 OS CSPRNG
生成 message ID，并使用调用方显式提供的非零 `first_endpoint_record_epoch`。签名 frame 写入本地
DHT cache 后，只推送给当前已连接 peer。非法 endpoint、随机源失败、certificate 无法覆盖 frame
TTL 或签名失败均不推进 epoch；只有 cache store 成功才推进。该路径不启动 iterative lookup，
也不能替代 refresh/anti-entropy。跨重启 epoch 的持久化与单调推进属于 daemon owner；不得从
wall clock 或每连接 HELLO sequence 隐式推导。

当前 listener 独占性还有一个部署阻断项：Windows CoroNet IOCP TCP listener 在 bind 前设置
`SO_REUSEADDR`，没有 `SO_EXCLUSIVEADDRUSE` 或等价的公开 listener option；实测第二个 listener
可在相同 host/port 上成功启动。因此 runtime 只能传播常规 bind 失败，尚不能兑现“已占用端口
必定 fail fast”。不能用进程内表或 advisory lock 把这一点伪装成 OS 级独占；生产部署前应先在
CoroNet 增加跨平台 exclusive-listener 选项，由 P2P management listener 显式启用并补跨进程测试。

## Stream V1 ticket delivery

`STREAM_TICKET_REQUEST` 与 `STREAM_TICKET_ISSUED` 只允许在已建立、协商了
`stream-ticket` feature 的相邻 MMP session 上 direct 传输，`forward_budget` 必须为 0；
不得 gossip、relay 或降级到未签名控制消息。当前 fail-closed 基线只接受具有
`OPERATOR` role 的 node principal。更细粒度的 per-stream ACL 尚未实现，因此不能用该基线
替代产品级用户、网络或媒体权限策略。

request 是精确 56-byte canonical TLV payload：

| ID | request 字段 | 长度 |
|----|--------------|------|
| `0x0001` | stream_id | 16 |
| `0x0002` | stream_epoch | 8 |
| `0x0003` | admission_generation | 8 |
| `0x0004` | ttl_ms | 8 |

issued 是精确 304-byte canonical TLV payload：

| ID | issued 字段 | 长度 |
|----|-------------|------|
| `0x0001` | request_message_id | 16 |
| `0x0002` | ticket_id | 32 |
| `0x0003` | mesh_id_hash | 32 |
| `0x0004` | initiator_node_id | 32 |
| `0x0005` | initiator_principal_key | 32 |
| `0x0006` | responder_node_id | 32 |
| `0x0007` | responder_principal_key | 32 |
| `0x0008` | stream_id | 16 |
| `0x0009` | stream_epoch | 8 |
| `0x000a` | admission_generation | 8 |
| `0x000b` | issued_at_ms | 8 |
| `0x000c` | expires_at_ms | 8 |

responder 不接受 request payload 自报的 mesh 或 initiator 身份；这些 claim 必须从已验证的
远端 MMP certificate/session 派生。本地 responder 身份由 owner 注入。owner 在确认 response
容量后才写入 responder-owned ticket store；若后续 envelope 签名或发送失败，必须显式
invalidate 已签发 ticket。initiator 只有在 response origin 与已认证 responder 相同、
`request_message_id` 匹配、双方身份与原 request claim 一致、时间和 60 秒硬 TTL 均有效时，
才能把 ticket 交给 TLS secure-bind。

MMP envelope signature 只证明 ticket 的控制面来源与完整性；数据连接仍必须通过双方
Ed25519 私钥证明和该 TLS 1.3 连接的 RFC 9266 exporter 完成 secure-bind。dispatcher 仍只
产生 borrowed typed event，不修改 ticket store；MMP delivery 只能通过
`mesh_stream_mgmt_ticket` 领域边界执行 issuance，后续 bind 状态迁移和失败 invalidation 仍由
responder-owned `mesh_stream_bind` store 统一承载。通用相邻 connection owner 已能发送完整
frame，但实际 MMP endpoint/listener、ticket response envelope 构造/签名和跨节点编排仍未实现。

## Membership Gossip

Membership 使用 SWIM 风格 probe，但状态合并服从 MMP 的签名和 owner 规则。

每个 protocol period：

1. 从 ALIVE members 中随机选择一个 subject。
2. 发送 PROBE，并等待基于该 link SRTT/RTTVAR 的 direct timeout。
3. 超时后选择最多 `indirect_fanout` 个不同 peer 发送 INDIRECT_PROBE。
4. direct 和 indirect 都失败才发布 SUSPECT；不得立即发布 DEAD。
5. subject 收到自己的 SUSPECT 后递增 incarnation 并发布 ALIVE 进行反驳。
6. SUSPECT 超过 suspicion timeout 后转为 DEAD；显式 graceful leave 使用 LEFT。

同一 `node_epoch` 下，较高 incarnation 胜出。同一 incarnation 的状态优先级为：

```text
LEFT > DEAD > SUSPECT > ALIVE
```

因此 ALIVE 不能在相同 incarnation 下覆盖 SUSPECT；subject 必须递增 incarnation。
较高 node epoch 表示重新 enrollment，可以覆盖旧 epoch 的 tombstone。

默认部署参数不是 wire 语义，必须可配置：

| 参数 | 建议默认值 | 约束 |
|------|------------|------|
| protocol period | 5 s | 加 0-20% jitter |
| direct timeout | `clamp(SRTT + 4*RTTVAR, 2 s, 10 s)` | 未知 RTT 使用 3 s |
| indirect fanout | 3 | 不超过可用 peers |
| suspicion timeout | `max(15 s, 3*direct_timeout)` | 分区时不触发破坏性动作 |
| dead retention | 10 min | 之后保留 tombstone 摘要 |
| tombstone retention | 24 h | 有容量上限 |

SUSPECT/DEAD 只影响发现和路由候选，不得自动停止远端服务、撤销身份或删除配置。

## Anti-entropy

Gossip 不广播完整状态表。每个节点周期性选择少量 peer 交换 DIGEST：

```text
record_key_hash | record_kind | owner_key | owner_epoch |
incarnation | sequence | payload_hash | expires_at
```

接收端比较类型化 version 后发送 DELTA_REQUEST，发送端用 DELTA_BATCH 返回完整 signed
record。DIGEST 和 batch 都分页，cursor 绑定 snapshot generation；snapshot 变化导致旧
cursor 失败并重新开始，不能返回混合代状态。

DELTA_BATCH 中每条数据都是完整 SignedRecord；batch sender 不是 record owner 时，接收端
仍验证内层 owner signature。Record store 只保存每个 merge key 的当前值、必要 tombstone
和 bounded command result。
过期 derived record 可从 owner 重新获取；过期 authoritative desired state 不自动回退到
更旧版本，而是进入 `desired_state_stale` 并停止新动作。

DHT 仅发布 signed management endpoint record：

```text
mgmt:<mesh_id_hash>:node:<node_id> -> endpoint record + expiry + signature
```

key 本身也是 canonical 输入：`mesh_id_hash` 与 `node_id` 都是 32-byte ID 的 64 个小写十六进制
字符，完整 key 精确为 139 bytes（另加一个本地 C string NUL）；不接受大写、缩写、额外分隔符、
尾随字符或全零 ID。consumer 必须先由该 key 解析 expected mesh/node，再验证 value，不能由 value
反向决定查询 key 的 owner。

DHT value 是一个精确完整的 signed MMP endpoint frame，不内嵌 enrollment certificate 或 trust
anchor。certificate 由独立的 enrollment/membership trust store 按 owner node 取得；缺失、过期或
issuer 不匹配时不得消费该 DHT value。这样 DHT overwrite 不能同时替换 endpoint 与其信任根。

endpoint record 复用 `MEMBERSHIP_DELTA (0x14)` envelope，不增加新的 wire kind；其 payload
是以下 8 个严格升序、不得重复或扩展的 canonical TLV field：

| Field ID | 名称 | 编码与约束 |
|----------|------|------------|
| `1` | record kind | `u8 = 1` |
| `2` | owner node ID | 32-byte，非零，必须等于 DHT key 中的 node ID |
| `3` | transport peer ID | 32-byte，非零，必须等于 enrollment certificate 绑定值 |
| `4` | address family | `u8 = 4`（IPv4）或 `u8 = 6`（IPv6） |
| `5` | address | IPv4 4-byte 或 IPv6 16-byte network-order binary address |
| `6` | port | big-endian `u16`，非零 |
| `7` | record epoch | big-endian `u64`，非零且只允许单调增加 |
| `8` | expires at | big-endian Unix epoch milliseconds `u64`，必须等于 envelope expiry |

IPv4 payload 精确为 120 bytes，IPv6 payload 精确为 132 bytes；不接受 hostname、尾随 field、
IPv4-mapped IPv6、unspecified 或 multicast address。envelope 必须是无 target、无 forwarding、
flags 为 0 的 node-principal 签名，并受配置化 TTL 上限约束。验证顺序固定为 envelope signature、
direct issuer certificate、mesh/node/principal/transport/time binding、payload schema，最后才调用
endpoint pool 的 `apply_verified`。消费者不得把普通 DHT value、解析成功但未认证的 payload，或
仅 IP 匹配的来源转换成 verified record。DHT 命中不能直接改变成员状态；只有完成
authenticated HELLO 后节点才进入 ALIVE 候选。

publisher 必须把 record epoch 当作 owner 持久化状态：每次成功发布后递增；编码、CSPRNG、签名
或 cache store 失败不得推进。跨进程重启必须从持久化的更大 epoch 恢复，不得复用每连接 sequence
或 wall clock。当前 internal runtime 只要求调用方提供首个 epoch，尚不负责持久化。

远端 link metric 只是有 TTL 的观测输入，不能直接安装 route 或绕过本地 path policy。
route manager 只消费已验证、满足 capability 的 immutable snapshot，并继续执行可行性、
身份、exit permission 和迟滞检查；异常低 metric 不构成授权。

## Desired state 与命令 RPC

### Gossip desired state

适合掉线后收敛的操作表达为 signed desired-state record：

- `meshd.service = RUNNING | STOPPED`
- `service_generation`
- `prestaged_config_hash`
- `policy_epoch`
- `not_before` 和 `expires_at`
- `required_current_generation` 可选前置条件

`STOPPED` 只停止 `meshd`，不停止 `mesh-agent`。包含 secret 的 config 必须由部署系统预先
放到目标节点；MMP 只引用 content hash。hash 不存在或校验失败时 fail fast，不修改当前
配置。

### Immediate command RPC

MMP/1 仅允许以下类型化操作：

| operation | 最低角色 | 行为 |
|-----------|----------|------|
| QUERY_STATUS | observer | 返回只读 snapshot |
| RECONCILE_SERVICE | operator | 使 `meshd` 达到签名 desired state |
| RESTART_SERVICE | operator | 幂等 restart generation |
| APPLY_PRESTAGED_CONFIG | policy_admin | 校验 hash 后原子替换/回滚 |
| COLLECT_DIAGNOSTICS | operator | 运行预定义、有时限和输出上限的 profile |
| SET_EXIT_PROFILE | policy_admin + quorum | 应用已预置 policy/profile epoch |

没有 `EXEC`、`SHELL`、任意 argv 或任意 path operation。诊断 profile 在构建时注册，不能
由网络 payload 注入命令行。

COMMAND_REQUEST 包含 command ID、operation、target、policy epoch、generation、deadline、
preconditions 和类型化参数。目标处理顺序固定为：

```text
decode -> verify signature -> check replay/expiry -> authorize ->
validate preconditions -> persist ACCEPTED -> execute side effect ->
persist RESULT -> send signed result
```

COMMAND_ACCEPTED 只表示命令已写入 bounded journal，不表示副作用完成。发送方在 timeout
后使用相同 command ID 重试；目标必须返回已有状态，不能再次执行。新 command ID 表示
新操作。

命令状态机：

```text
RECEIVED -> VERIFIED -> AUTHORIZED -> ACCEPTED -> RUNNING
     \          \            \                    ├-> SUCCEEDED
      \          \            ├-> PRECONDITION_FAILED
       \          ├-> REJECTED                      ├-> FAILED
        ├-> INVALID                                 └-> INTERRUPTED
        └-> EXPIRED
```

`SUCCEEDED`、`FAILED`、`REJECTED`、`PRECONDITION_FAILED` 和 `EXPIRED` 是 terminal。agent
在 RUNNING 时崩溃，重启后查询 OS service manager 和本地 transaction 状态，将命令收敛
为 SUCCEEDED、FAILED 或 INTERRUPTED；不得假定副作用未发生。

MMP/1 不提供命令 cancel。新的较高 service generation 可以 supersede 尚未开始的旧 desired
state，但不能伪装为对已执行副作用的回滚。

## 授权、安全与审计

### 身份与角色

management-transport X25519 identity 只用于 adjacent session key agreement。MMP 使用
独立 Ed25519 management key 做端到端签名，数据面 X25519 private key 不进入 agent。
授权证书把 transport identity、management key 和 managed data-plane node ID 绑定起来。

基础角色：

- `observer`：读取 status、参与 membership/digest。
- `operator`：service reconcile、restart、bounded diagnostics。
- `policy_admin`：配置/policy epoch 和 exit profile。
- `trust_admin`：签发、轮换、撤销管理证书和 trust bundle。

本地 policy 对 signer、role、target scope、operation 和时间范围再次求交。网络证书允许
但本地 policy 拒绝时，以拒绝为准。

### Quorum

当前可由网络触发且至少要求本机 trust policy 定义的 `m-of-n` 独立签名的动作是：

- 启用或扩大 exit profile。
- 应用会降低 audit/security policy 的已预置配置。

修改 trust root、quorum、trust-admin 集合或配置签名 authority 在 MMP/1 中没有 operation，
只能通过本机部署渠道完成；未来版本即使开放也必须要求 quorum 和显式新 capability。

Quorum signature 只证明授权，不把 Gossip 变成 consensus。多个 authority 发布冲突的同
epoch record 时全部拒绝并报告 `AUTHORITY_CONFLICT`，由更高 epoch 的合法记录解决。

每个 signer 签署同一个 canonical authorization hash：`mesh ID + operation + target scope +
policy epoch + payload hash + expiry`。目标节点去重 signer key、重新检查每张证书的 role 和
scope，再按本机固定的 quorum policy 计数。MMP/1 不提供网络修改 trust root、quorum 或
本机 break-glass policy 的 operation；未知 operation 不能借 quorum bundle 获得授权。

### Replay 与 downgrade

接收端同时检查：

- transport counter/window；失败立即断开 adjacent peer。
- `(origin principal key, principal epoch, incarnation, session ID, sequence)` 单调窗口；
  非节点 principal 的 session 也必须有短期、有界状态和有效 expiry。
- message ID 的短期 duplicate cache。
- command ID 的持久化 idempotency journal。
- issued/expires 和允许的 clock-skew；wall clock 异常时停止执行新命令但可继续转发
  已认证连接上的 direct probe，不合并或转发无法确认 validity 的 signed record。
- HELLO 协商的 major/minor/features；未协商 capability 不得使用。

当前内部 `mesh_mgmt_replay` 在初始化时一次性分配 configurable cache，容量必须在
`1..8192`，TTL 必须在 `1 ms..10 min`；frame expiry 更早时取更早者。每个 gate 只绑定一个
已认证的 `(principal key, epoch, incarnation, session ID)`，sequence 采用 64-bit RFC 1982
strict-newer 比较，允许同一 origin 的合法跳号。cache 不淘汰未过期 message ID；全部占用时
返回 `RESOURCE_EXHAUSTED`。`prepare` 只判定且不修改事实源，调用方完成其余纯解析/授权后才
`commit`；过期 token 或并发推进后的 stale token 均 fail closed。该状态由单 event-loop owner
串行访问，不提供内部锁，也尚未持久化。

当前内部 `mesh_mgmt_dispatch` 只返回 borrowed、typed observer event，不调用 callback、不执行
命令、不发送网络数据。`FORWARD` 和全部 `COMMAND_*` 即使已协商 targeted-RPC feature 也返回
`SIDE_EFFECT_DISABLED`，且拒绝不会消耗 sequence/message-ID replay 状态。membership、
anti-entropy、audit 与 error payload 目前只完成 envelope 级认证和类别分发；消息专属 schema
在对应 parser 实现前不得合并进领域事实源。Stream ticket typed event 同样不在 dispatcher
执行副作用；只有上述领域命令在完成专属 schema、session、role、identity、时间和容量检查后
才可修改 responder ticket store。

`mesh_mgmt_connection` 是 dispatcher 之上的唯一 receipt/callback 顺序边界；它不把 consumer
错误写成成功，也不在 parser/auth 热路径写日志。稳定 connection result 连同底层 transport
result、dispatch result/stage 和 consumer result 由未来 agent 边界消费并只记录一次。所有
dispatch/consumer/IO ambiguity 都是连接级 terminal，不允许回退到未签名控制消息。
出站普通 frame 也复用 dispatcher 的 observer-safe kind 基线和已协商 feature gate；在完整
policy/command journal 落地前，`FORWARD` 与全部 `COMMAND_*` 不会进入 socket send。

旧节点或不支持 MMP 的 peer 保持现有数据面行为，但不能转发或执行 MMP。禁止把 MMP
失败回退为未签名 `MESH_CTRL:` 文本。

### Audit

每个被接受或拒绝的管理命令记录：

- command ID、origin signer、target、operation。
- 验证/授权结果和稳定 reason code。
- precondition、前后 service/config generation。
- accepted/start/finish 时间和 result hash。
- 本地 agent session ID、`meshd` service instance ID、agent version 和 policy epoch。
- membership 变化来源：signed LEFT、本机 service command、transport close 或 probe timeout；
  crash/断网只能报告检测结果，不能伪称知道是谁关闭了节点。

本地 audit entry 进入 hash chain；AUDIT_ANCHOR 只 Gossip chain head 和持久化位置标识，
不传播敏感正文。远端 anchor 可以证明后续篡改，但单独的 Gossip anchor 不能证明管理员
没有删除整个日志存储，因此生产环境仍需外部 append-only sink。

## 资源与流量上限

| 资源 | MMP/1 默认上限 |
|------|----------------|
| frame | 16 KiB |
| canonical header | 512 B |
| targeted RPC relay depth | 1 |
| digest entries/page | 128 |
| delta records/batch | 64，且总 frame 不超过 16 KiB |
| Gossip fanout | `min(3, connected_peers)` |
| in-flight command/origin | 32 |
| in-flight command/node | 128 |
| command request lifetime | 最大 1 h，超过即拒绝 |
| command result journal | 4096 条；terminal record/tombstone 至少保留 24 h |
| message duplicate cache | 8192 IDs 或 10 min |
| membership subjects | 256，与当前 Mesh peer 上限一致 |
| metric records | 每个邻接 path 1 个当前值，默认 TTL 30 s |
| protocol input rate | 每 peer 10 frame/s，burst 50；RPC response 另计有界额度 |

所有上限都可在本机配置中调低；HELLO 协商只能取较小值，远端不能提高本机限制。
长度、kind、feature、forward budget 和基础 rate limit 在签名验证前检查，降低 crypto
DoS 成本。journal 不淘汰尚未过期的 command ID；容量耗尽时拒绝新命令。terminal entry
可以压缩为带 result hash 的 tombstone，但保留期必须覆盖最大 command lifetime、clock
skew 和重试窗口，防止淘汰后再次执行。

Membership 每节点每 period 发送 O(fanout) probe；record store 为 O(nodes + links +
bounded commands)。Anti-entropy 的完整 digest 为 O(records)，但通过分页、随机 peer 和
速率限制摊销，不能在 owner loop 单次遍历并发送无界快照。

## 线程与 C 模块边界

管理核心使用单个 CoroNet owner loop。membership timer、record merge、command state 和
peer send 都在 owner loop；外部线程通过 `coro_post()` 投递 immutable command。锁内不做
I/O、签名验证或 callback。

建议的内部接口保持 opaque，不在第一阶段发布 public ABI：

```c
typedef struct mesh_mgmt_s mesh_mgmt_t;
typedef struct mesh_mgmt_snapshot_s mesh_mgmt_snapshot_t;

mesh_mgmt_result_t mesh_mgmt_create(
    const mesh_mgmt_config_t *config,
    const mesh_mgmt_transport_ops_t *transport,
    const mesh_supervisor_ops_t *supervisor,
    mesh_mgmt_t **out_mgmt);
mesh_mgmt_result_t mesh_mgmt_start(mesh_mgmt_t *mgmt);
mesh_mgmt_result_t mesh_mgmt_stop(mesh_mgmt_t *mgmt);
void mesh_mgmt_destroy(mesh_mgmt_t *mgmt);

mesh_mgmt_result_t mesh_mgmt_receive(
    mesh_mgmt_t *mgmt, const mesh_mgmt_peer_id_t *peer,
    const uint8_t *frame, size_t frame_len);
mesh_mgmt_result_t mesh_mgmt_submit(
    mesh_mgmt_t *mgmt, const mesh_mgmt_command_request_t *request);
mesh_mgmt_result_t mesh_mgmt_get_snapshot(
    mesh_mgmt_t *mgmt, mesh_mgmt_snapshot_t **out_snapshot);
void mesh_mgmt_snapshot_destroy(mesh_mgmt_snapshot_t *snapshot);
```

`mesh_mgmt_transport_ops_t` 只负责 connect/send/close 和 peer identity；
`mesh_supervisor_ops_t` 只负责 query/reconcile/restart/apply-prestaged/diagnostics。协议解析、
授权和状态合并不进入 adapter。`mesh_mgmt_result_t` 包含稳定 error code、失败 stage 和可选
platform code，不依赖日志表达失败。每个 create 都有对应 destroy，snapshot 由调用方显式
释放。

create 只在成功时写 `out_mgmt`。start 成功后 receive/timer/callback 都在 owner loop；跨线程
submit/get-snapshot 由 wrapper 复制输入并 `coro_post()`。stop 幂等，只有在停止 timer、拒绝
新命令、取消 pending receive、完成 journal flush 且 callback 已退出后才完成；destroy 只
接受 stopped handle。adapter callback 不能在持锁状态调用。

## 错误语义

ERROR 和 command result 使用稳定 reason code：

| code | 含义 |
|------|------|
| INVALID_FRAME | 长度、canonical TLV 或字段格式错误 |
| UNSUPPORTED_VERSION | major/minor 不可协商 |
| UNSUPPORTED_FEATURE | 请求未协商能力 |
| AUTH_FAILED | certificate/signature/node binding 失败 |
| REPLAYED | sequence、message ID 或 command ID 重放 |
| EXPIRED | frame/command 已过期 |
| CLOCK_UNSAFE | 本机 wall clock 不可信，停止新副作用 |
| PERMISSION_DENIED | role、scope、local policy 或 quorum 不满足 |
| PRECONDITION_FAILED | generation/boot/config hash 不匹配 |
| RATE_LIMITED | peer/origin 额度耗尽 |
| RESOURCE_EXHAUSTED | 队列、journal、record store 或 frame 上限 |
| NOT_FOUND | target、prestaged config 或 command ID 不存在 |
| BUSY | 已有互斥 platform transaction |
| AUTHORITY_CONFLICT | 同 epoch 的 authority record 冲突 |
| INTERNAL | 本地 adapter/持久化失败；携带可操作阶段信息 |

Parser/auth/merge 层只返回错误。相同错误只在被消费的 agent 边界记录一次，Gossip 热路径
不写 INFO 日志；计数器按 reason 聚合。

## 兼容性、迁移与回滚

### 协议兼容

- MMP 有独立 magic 和 version，不改变现有 P2P header、Mesh virtual IP 或 packet format。
- 首版绑定 `P2P_MSG_CUSTOM`，旧 `mesh` payload 继续按原规则处理。
- MMP handler 只有在 magic、HELLO 和 feature negotiation 成功后启用。
- 未安装 `mesh-agent` 的节点仍可参与数据 Mesh，但不出现在 management ALIVE 集合中。
- 禁止自动把 `P2P_MSG_GOSSIP` 枚举解释为 MMP；以后若改用专用 type，需要新的 feature
  和 mixed-version 测试。

### 实施阶段

1. **M0 基线**：P2P checked CSPRNG 与 ordered-stream
   replay/out-of-order/counter-exhaustion 回归已完成；继续固化 node identity、DHT
   overwrite、routed-control fail-closed 和协议 golden vectors。
2. **M1 安全与 codec**：复核 transport counter 与握手 binding；实现 OpenSSL Ed25519
   adapter、canonical TLV parser、证书和资源限制，不执行副作用。
3. **M2 observer agent**：部署独立 `mesh-agent`，只做 HELLO、membership、digest、status；
   `meshd` 完全由现有方式管理。
4. **M3 observe-only desired state**：接收和展示期望状态，输出 reconcile plan，但不执行。
5. **M4 limited RPC**：开放 QUERY_STATUS、COLLECT_DIAGNOSTICS 和 RESTART_SERVICE，启用
   command journal、回执和恢复测试。
6. **M5 service reconcile**：开放 RUNNING/STOPPED、prestaged config 和原子 rollback。
7. **M6 privileged policy**：安全数据 envelope、route authentication、quorum 和外部审计
   均达标后，才开放 exit profile。

每一阶段通过停止/卸载 `mesh-agent` 和关闭 MMP endpoint 回滚；`meshd` 原配置、TUN 和
数据协议保持不变。agent 不得在 rollout 过程中接管已有 service unit，除非配置显式
`management_mode = active`。

## 验证范围

### Codec 与密码

- 每种 kind 的 canonical golden vector 和跨端序测试。
- truncated、overflow、重复/乱序 TLV、unknown flag/kind、超大 frame fuzz。
- RFC 8032 Ed25519 test vectors、错误 key/signature 和 certificate chain。
- transport replay、MMP sequence replay、message ID duplicate 和 command replay。
- signature verification 前的长度/rate limit，验证无未界定分配。

### Membership 与 anti-entropy

- deterministic fake-clock 状态机：ALIVE、SUSPECT、refute、DEAD、LEFT。
- higher incarnation/node epoch、同 incarnation precedence 和 serial wrap。
- ring、star、partition/heal、重复/乱序/丢失消息和随机 peer churn。
- digest pagination、snapshot generation 变化、expired record 和 bounded tombstone。
- 256 节点模拟下的消息率、内存上限和收敛 P50/P95/P99。

### 命令与恢复

- duplicate command 只执行一次并返回相同 result。
- ACCEPTED 前持久化失败不产生副作用。
- RUNNING 阶段 agent/meshd/主机崩溃后的实际状态查询和收敛。
- prestaged hash 不匹配、配置验证失败和 platform transaction rollback。
- 未授权 signer、越权 target、过期证书、撤销、quorum 不足和 authority conflict。
- 管理分区只产生 stale/degraded，不自动停止健康数据面。

### 部署矩阵

- local/eu/bj/sh 四节点：启动、重启、停止 `meshd` 后仍能通过 agent 重新启动。
- agent 仅出站连接、NAT、单层 relay、Gossip 多轮传播和 bootstrap 更换。
- Linux systemd、Windows SCM、macOS launchd adapter。
- management port 与 80/443/8443、Docker 和现有服务冲突时 fail fast，不自动抢占端口。
- CoroNet pending receive、peer close、agent shutdown 和重复 close regression。

## 完成条件

MMP/1 进入 production 需要同时满足：

- 数据面停止后 agent 仍可认证、查询并重新拉起 `meshd`。
- 所有 Gossip record 都有 owner、签名、version、TTL、merge rule 和容量上限。
- 所有命令都有 target、role、precondition、idempotency journal、signed result 和审计记录。
- DHT poison、origin spoof、replay、downgrade、relay 篡改和 update flood 被测试拒绝。
- management partition 不触发破坏性动作，恢复后状态在定义时间内收敛。
- mixed-version 节点不误执行未知命令，不回退到未签名 control。
- eu/bj/sh/local 的重复测试脚本保留节点或显式标记临时节点，不再默认清理长期 agent。

## 一手资料

- [SWIM paper](https://www.cs.cornell.edu/projects/quicksilver/public_pdfs/SWIM.pdf)：
  failure detection 与 infection-style membership dissemination 的原始设计。
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)：Ed25519 签名格式与测试向量。
- [RFC 1982](https://www.rfc-editor.org/rfc/rfc1982.html)：有限序号空间的 serial arithmetic。
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)：若后续替换当前握手，
  用于 handshake、cipher state 和 nonce 语义；MMP 不自行发明 Noise 变体。

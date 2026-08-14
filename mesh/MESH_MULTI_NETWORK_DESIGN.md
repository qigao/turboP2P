# Mesh 多逻辑网络与 Subnet 隔离设计

## 文档状态

- 状态：目标架构与增量迁移设计
- 日期：2026-08-14
- 范围：一个安全 Mesh 信任域内的多逻辑 Network、IPAM、路由、数据面隔离、控制原语和生命周期
- 非实现声明：本文定义尚未全部进入公开 API 或 wire protocol 的目标契约；“目标”不得当作当前能力销售

本文使用以下证据标签：

- `事实`：来自当前实现、测试或现有设计文件。
- `推论`：根据当前结构得出的影响判断，仍需实现和测试验证。
- `目标`：本设计选择的未来契约。
- `计算`：可由列出的输入和公式复算的容量或边界。

### 当前实现状态（2026-08-14）

`事实`：本轮已完成一个默认关闭、面向嵌入方的实验性切片：

- additive `mesh_fabric_t` / logical `mesh_network_t` V2 API；旧 `mesh_create()` API 和 ABI 保留；
- 一个既有 Noise/P2P underlay 上复用多个 Network，使用严格 `TMN2` OPEN/DATA/CLOSE frame；
- Ed25519 `MTK1` membership ticket、issuer allowlist、node identity digest、generation/policy/key epoch、
  expiry、source/destination IP 和 packet replay 检查；
- userspace Network 支持重叠 IPv4；direct-member packet 和显式 subnet-router/exit packet 按
  `network_uid` 隔离；删除一个 Network 不关闭共享 fabric；
- 每个 Network snapshot 可原子携带至多 256 条 canonical IPv4 route；最长前缀、metric、node ID
  给出确定性选择，next hop 必须是 authorized member，且其签名 ticket 必须具有对应 router/exit role；
- route 当前只把 packet 经一个认证 Noise hop 交给终止该 external prefix 的 gateway callback，不允许
  gateway 再把同一 `TMN2` frame 转发给其他 Mesh member；
- hard limit：64 Network、256 authorized peer/Network、256 route/Network、4096 binding、64 KiB frame；
  所有 runtime mutation 由同一 caller/owner loop 串行；
- canonical `TCN1` 控制文档（含 digest 绑定的 bounded route body）、resource ID、单 owner bounded
  Network reconciler，以及
  `meshctl networks list/get/plan/apply/delete` 与 Iris Controller adapter；
- reconciler 对 userspace membership/address/MTU/peer allowlist/route snapshot 一次校验并应用；OS attach
  或包含 DNS snapshot 的文档仍返回 UNSUPPORTED，不制造虚假的 applied observation；
- standalone control agent 可显式注入 caller-owned fabric，准入时校验 Network resource ID、Mesh、目标
  node 与 generation 绑定，随后执行 APPLY/DELETE；durable 模式先写 operation-result WAL 再推进
  observed/operation，重启在开放 ingress 前从最终状态重建已完成和未完成的 userspace Network；
- transport-neutral `MeshNodeIPC/1` 已实现 canonical codec、显式 Mesh scope、有界 copied-frame channel、
  单 owner operation 去重/result retention，以及 Network APPLY/DELETE executor；独立 `FlowMQ::FlowMQ`
  ROUTER/DEALER mTLS adapter、generic runtime 与 `mesh_node_network_control_service` 组合已完成同进程
  真实 mTLS 的双 Network APPLY、独立 DELETE、fabric attach/detach、RESULT/exact ACK 和 shutdown drain
  测试；`meshd` 已接默认关闭的 FlowMQ/mTLS 配置和唯一 fabric underlay owner，跨进程恢复未实现；
- ASan 开发配置下的双 Network 隔离、重叠地址、generation fencing、签名拒绝、容量和独立删除测试。

`事实`：以下仍未实现，因此当前不能按本文“完成条件”宣称完整生产级 multi-network：

- Network-scoped DHT、普通成员间 multi-hop route、MagicDNS、完整 packet-policy/telemetry 和 secure relay；
- Controller 权威存储、ticket/IPAM 签发、可部署 agent 服务、FlowMQ ROUTER/DEALER mTLS 到 `meshd`
  的实际配置接线、certificate-to-identity binding 与跨进程恢复；
- per-Network TUN/VRF/namespace、OS route/DNS/firewall transaction 和 rollback；
- inter-Network gateway、OS gateway transaction、IPv6、fuzz/TSan、64 Network 饱和和跨平台/大规模
  churn 验证。

因此当前可用边界是“一个 Mesh/Noise 信任域内、共享 underlay 的 userspace IPv4 Network，支持直连
成员和显式授权的单跳 terminal subnet-router/exit”。Controller/CLI 路由是可注入的集成面，不是已经
部署的控制服务；普通 Mesh 多跳仍不得借此能力启用。

## 决策摘要

一个 Mesh 可以包含多个相互隔离的逻辑 Network。三层概念固定如下：

```text
Mesh
  identity / trust / enrollment / Controller authority
  shared authenticated P2P underlay
    |
    +-- Network production
    |     address pools, memberships, routes, DNS, packet policy
    |
    +-- Network backup
          independent pools, memberships, routes, DNS, packet policy
```

- `Mesh` 是身份、信任、管理和物理 P2P 会话复用边界。
- `Network` 是 Mesh 内独立的三层转发、地址、策略和服务发现域，也可称 segment。
- `AddressPool` 是 Network 内为节点分配 overlay 地址的 CIDR。
- `ExternalRoute` 是通过 subnet-router/exit 到达的外部 CIDR，不等于一个新 Network。
- 一个节点可以加入零到多个 Network；同一对节点的 Noise/P2P underlay 连接可以被多个 Network 复用。
- Network 之间默认没有路由、发现或服务可见性。加入两个 Network 的节点不会自动成为网关。
- 跨 Network 转发只能由显式 gateway intent、双向 policy 和同一 committed generation 启用。
- 不改变当前 `network_id` 字符串的安全语义。迁移时它映射为外层 `mesh_id`；逻辑 Network 使用新的
  128-bit `network_uid`。
- 现有 `mesh_create()`、`mesh_send_packet()` 和 IPv4 API 保持单个隐式 `default` Network 行为。
  多 Network 使用 additive v2 API 和明确的协议能力协商。

## 当前事实与主要缺口

### 已有能力

`事实`：`mesh_config_t` 当前有一个 `virtual_ip`、一个 `virtual_prefix` 和一个可选
`network_id`；`mesh_network_t` 内部也只保存一份这些字段
（[`turbo_mesh.h`](include/turbo_mesh.h)、[`mesh.c`](src/mesh.c)）。

`事实`：当前 `network_id` 会被 SHA-256 后传给 P2P pinned security 配置，因此它已经是
Noise/P2P 信任命名空间的一部分，而不只是显示名称。

`事实`：当前 DHT 地址 key 使用
`mesh:<network_id>:ip:<virtual_ip>`，路由、peer lookup、MagicDNS 和 packet policy 主要以
IPv4 字符串或 IPv4 地址为 key。

`事实`：`mesh_send_packet()` 接收裸 IPv4 packet，从 offset 16 提取 destination；接收路径在
处理 MMP、HELLO、route/control 文本后，把其余 payload 当作裸 IP packet。当前 data frame
没有逻辑 Network 标识。

`事实`：当前已有 pinned CIDR、learned route、local egress、subnet-router 所需的源 CIDR
检查和 packet policy。这能表达“同一 overlay 经 router 访问多个外部 LAN”，但不能表达一个
Mesh 内多个隔离的 overlay Network。

`事实`：控制原语已有 `NETWORK` 与 `ROUTE` 的 APPLY/DELETE kind、generation、epoch、
precondition、payload digest、64 KiB frame 上限以及 operation terminal state；目前没有完整的
typed multi-network payload。

### 风险结论

- `HIGH / 事实`：只在 Controller 增加 Network 记录而不改变 data frame、route key 和 peer address
  key，会导致同地址或同前缀的 Network 串流量。影响 packet forwarding、DHT、ACL、DNS 和审计。
- `HIGH / 事实`：直接把当前 `network_id` 改成子网 ID 会同时改变 P2P trust namespace，造成节点
  无法握手或错误地扩大/缩小信任域。
- `HIGH / 推论`：当前 peer 以单个 `virtual_ip` 公告和查找，不能安全表达同一 underlay peer 在多个
  Network 中拥有不同地址，也不能表达重叠地址。
- `MED / 推论`：即使 Mesh data plane 已区分 `network_uid`，同一 OS routing table 上的重叠 CIDR
  仍然歧义。需要 network namespace、VRF/routing compartment 或显式 userspace Network handle。
- `MED / 事实`：当前控制 envelope 能标记 NETWORK resource，但没有定义 Network/AddressPool/
  Membership 的强类型不变量；不同 adapter 自行解释 payload 会形成多个事实源。

## 目标与非目标

### 目标

- 一个 Mesh 下创建、查询、更新、drain 和删除多个逻辑 Network。
- 节点按授权加入多个 Network，并在每个 Network 使用独立地址、DNS、route 和 packet policy。
- 所有 lookup、route、policy、replay、telemetry 和审计都显式携带 `network_uid`。
- 共享 underlay peer session，不按 Network 重复 NAT traversal、Noise 握手和物理连接。
- 允许不同 Network 使用重叠 CIDR，但只有具备 OS isolation capability 的节点才能同时 attach
  这些 Network 到系统网络栈。
- 保留现有单 Network 用户行为，并提供可回滚的分阶段迁移。
- 明确定义事实源、ownership、容量、背压、失败、关闭与验证门槛。

### 非目标

- 第一版不提供二层 Ethernet bridge、ARP 广播域、任意 multicast 或 VXLAN 兼容。
- 第一版不让 Network membership 自动授予 external subnet、exit 或 inter-network gateway 权限。
- 不通过 per-Network 复制完整 P2P node 来实现生产架构。
- 不把 H2、WebSocket、FlowMQ 或 DHT 当作 Network 事实源。
- 不在本设计中发明新的密码算法。链路认证沿用 P2P Noise；端到端 data envelope 复用
  [`MESH_PLATFORM_DESIGN.md`](MESH_PLATFORM_DESIGN.md) 的安全数据面迁移轨。
- 第一实现阶段只启用 IPv4；schema 和内部地址类型从开始保留 IPv6，但不对未声明能力的节点下发。

## 候选方案比较

| 方案 | 优点 | 问题 | 结论 |
|------|------|------|------|
| 每个 Network 启动一个独立 `mesh_network_t`/P2P node | 对当前代码改动最少，天然隔离地址 | 重复监听端口、DHT、Noise session、ICE、peer 和 timer；多 Network 节点成本线性上升 | 仅可作为测试/过渡，不作为生产架构 |
| 一个 route table 中加入多个 CIDR | 简单，复用现有 API | 没有独立身份/策略域，重叠地址和串网无法解决 | 不采用 |
| 共享 Mesh fabric，按 `network_uid` 建立独立 Network context | underlay 复用；隔离边界明确；支持多成员和重叠地址 | 需要 v2 frame、peer/address 分层和内部重构 | 采用 |
| 每个 Network 使用独立 Mesh/Noise trust domain | 强隔离，当前 `network_id` 可复用 | 同一组织内密钥、连接和运维重复；无法表达共享 Mesh 能力 | 保留为强租户隔离部署选项 |

## 总体架构

```text
Product Controller
  Mesh / Network / Membership / RouteGrant authoritative database
  policy compiler + signed per-node snapshots + durable operation journal
                         |
                  H2 / RFC 8441 WS
                         |
                    mesh-agent
        signed snapshot validation / reconcile owner
                         |
        FlowMQ secure typed local control plane
                         |
                       meshd
      OS transaction owner / TUN / DNS / route / firewall
                         |
                    Mesh fabric
  identity + Noise/P2P peers + ICE + shared physical paths
       |                  |                    |
 Network A context   Network B context   Network C context
 address/route/ACL   address/route/ACL   address/route/ACL
       |                  |                    |
  packet/flow API      packet/flow API      packet/flow API
```

依赖方向固定为：

```text
CLI/H2/WS/FlowMQ adapters
        -> typed Network commands and immutable snapshots
        -> agent reconcile owner
        -> meshd platform adapter
        -> Mesh fabric + Network contexts
        -> P2P/CoroNet transports
```

领域核心不知道 JSON、HTTP route、WebSocket frame 或 FlowMQ socket pattern。adapter 只做认证结果
绑定、格式转换、deadline 和错误映射。

## 标识、命名与兼容映射

### 标识

| 标识 | 大小 | 创建者 | 语义 |
|------|------|--------|------|
| `mesh_id` | 32 bytes | Controller/security domain | 身份、信任和管理域；不可变 |
| `network_uid` | 16 bytes | Controller CSPRNG | Mesh 内逻辑 Network；不可变，不从名称或 CIDR 推导 |
| `network_name` | 1..63 UTF-8 bytes | operator | Mesh 内唯一显示名；可修改 |
| `managed_node_id` | 32 bytes | enrollment | 稳定节点身份，不是 IP |
| `membership_id` | 16 bytes | Controller | node 与 Network 的授权关系 |
| `route_id` | 16 bytes | Controller | route intent 的稳定身份 |

`network_uid` 由 Controller 使用 `turbo_uuid_v4_generate()` 生成。生成失败必须使 create transaction
失败，不能回退到时间、进程 ID 或弱随机数。控制 envelope 的 32-byte `resource_id` 定义为：

```text
SHA-256("mesh-network/v1" || mesh_id || network_uid)
```

显示名、CIDR、DNS suffix 和 address pool 都不能成为身份。

### 旧配置映射

旧 `mesh_config_t.network_id` 不改字段或含义：

```text
mesh_id = SHA-256(legacy network_id UTF-8 bytes)
default network_uid =
    first_16_bytes(SHA-256("mesh-default-network/v1" || mesh_id))
```

旧 `virtual_ip + virtual_prefix` 成为 default Network 的单个 IPv4 membership/address pool。这个
映射是确定的，因此同一旧配置在升级后仍进入同一个网络。映射只用于兼容；新 Network ID 必须随机
生成，不能继续从名称推导。

## Controller 领域模型

### Mesh

```text
Mesh {
  mesh_id,
  display_name,
  trust_epoch,
  policy_epoch,
  lifecycle,
  created_at
}
```

Mesh 是最外层事实源和 RBAC scope。删除 Mesh 是独立的高风险操作，不由删除一个 Network 隐式触发。

### Network

```text
Network {
  network_uid,
  mesh_id,
  name,
  generation,
  lifecycle: ACTIVE | DRAINING | TOMBSTONED,
  address_families,
  mtu,
  dns_suffix?,
  policy_digest,
  address_pool_digest,
  membership_epoch,
  route_epoch,
  key_epoch,
  not_before,
  not_after
}
```

不变量：

- `network_uid` 和 `mesh_id` 创建后不可变。
- 每次 mutation 必须带 `precondition_generation`；成功后 generation 严格递增。
- `mtu` 必须扣除 underlay、Network envelope 和安全 tag 的最坏开销后仍可承载最小 IP MTU。
- lifecycle 只能 `ACTIVE -> DRAINING -> TOMBSTONED`；tombstone 不可复活为同一 UID。
- snapshot 的 policy、pool、membership、route 和 key epoch 必须被同一个 signed manifest digest
  绑定，节点不能拼接不同 generation 的部分状态。

### AddressPool

```text
AddressPool {
  pool_id,
  network_uid,
  family,
  prefix,
  reserved_ranges,
  allocation_policy,
  generation
}
```

- 同一 Network、同一 address family 的 AddressPool 不得重叠。
- node address、DNS service address、gateway address 和 reserved range 不得冲突。
- 不同 Network 的 pool 可以重叠；这不代表某个节点的 OS adapter 一定能同时 attach。
- V1 allocation 由 Controller transaction 完成，不由 DHT/Gossip 抢占或选主。

### NetworkMembership

```text
NetworkMembership {
  membership_id,
  network_uid,
  managed_node_id,
  node_key_epoch,
  addresses[],
  roles[],
  generation,
  state: PENDING | ACTIVE | REVOKED,
  not_before,
  not_after
}
```

地址租约必须绑定
`(mesh_id, network_uid, managed_node_id, node_key_epoch, membership_generation)`。Noise 身份只证明
节点是谁；只有 ACTIVE、未过期且 key epoch 匹配的 membership 才允许打开 Network data session。

### RouteGrant

```text
RouteGrant {
  route_id,
  network_uid,
  origin_node_id,
  destination_prefix,
  next_hop_role: SUBNET_ROUTER | EXIT | NETWORK_GATEWAY,
  capabilities: ADVERTISE | USE | ADMINISTER,
  metric_policy,
  route_epoch,
  expires_at
}
```

ADVERTISE、USE 和 ADMINISTER 分开授权。一个 subnet-router 发布 external CIDR 不会创建新 Network；
它只给当前 Network 增加经过该节点的目的前缀。

### NetworkGateway

NetworkGateway 是 northbound 复合资源，编译为两个 Network 的 membership、route 和 policy snapshot：

```text
NetworkGateway {
  gateway_id,
  left_network_uid,
  right_network_uid,
  gateway_node_id,
  allowed_prefix_pairs[],
  allowed_protocols_ports[],
  generation,
  state
}
```

V1 只支持 routed gateway，不支持二层 bridge。gateway 节点加入两侧 Network 仍不足以转发；只有两侧
snapshot 都处于相同 gateway generation 且本地 platform transaction commit 后，数据面才进入
ACTIVE。任一侧失败保持 fail-closed。

## 单一事实源与派生状态

| 状态 | 唯一事实源/owner | 派生状态 |
|------|-----------------|----------|
| Mesh、Network、membership、route grant desired state | Controller database transaction | API view、audit、per-node compiled snapshot |
| accepted operation 与幂等结果 | Controller durable journal | watch event、CLI wait |
| 节点已验证 desired snapshot | agent reconcile owner + durable checkpoint | FlowMQ publication、status |
| TUN、OS route、DNS、namespace/firewall | `meshd` platform transaction owner | OS inspection/status |
| underlay peer/path | Mesh fabric owner loop | Network binding、diagnostics |
| Network address/route/policy runtime | 对应 Network context，fabric owner loop | lookup cache、selected route |
| DHT descriptor、DNS table、telemetry | 可重建派生状态 | 不得反向修改 Controller desired state |

Controller 发布每节点编译后的 bounded snapshot，不向每个节点复制整个 Mesh 的全部 membership。
snapshot 至少包含本节点 membership、允许建立会话的 peer capability 摘要、可用 route、policy digest、
epoch、有效期和签名。需要更多记录时使用 digest 引用的分页/增量集合；不得突破 64 KiB control frame。

## Agent APPLY 与 DELETE 事务

### APPLY

```text
Controller transaction commits Network generation N
  -> durable outbox records targeted intent
  -> agent authenticates envelope and verifies signature/expiry/precondition
  -> agent validates local capability and immutable snapshot
  -> meshd stages interface/address/route/DNS/policy
  -> Mesh fabric stages Network context and membership
  -> platform transaction commits
  -> Network context atomically switches to generation N
  -> agent persists applied receipt and publishes observation
```

任一步在 commit 前失败：释放 staged resources，保留上一有效 generation。platform 外部副作用已部分
发生时，`meshd` 必须按同一 transaction journal 回滚；回滚失败进入 ERROR 且保持 packet
fail-closed，不能报告成功。

### DELETE

```text
ACTIVE
  -> Controller commits DRAINING tombstone
  -> stop new membership/session/route/flow
  -> revoke discovery publication and new gateway traffic
  -> drain existing flows until bounded deadline
  -> remove OS route/DNS/interface state
  -> close Network context and release queued payload
  -> report TOMBSTONED applied receipt
```

删除一个 Network 不关闭共享 underlay，也不影响节点的其他 Network。Controller 保留 tombstone 和
resource UID 至少到所有目标节点已确认、离线节点的最大 credential/snapshot validity 已过期且审计
retention 满足之后。过期离线节点重新上线只能收到 tombstone，不能恢复旧 Network。

## Mesh fabric 与 Network context

### 对象边界

`目标`：新增内部/公开的 shared fabric 抽象：

```text
mesh_fabric_t
  owns P2P node, Noise identity, peer-by-node-id table, ICE/path state,
  CoroNet owner context, aggregate queue budget, shutdown state

mesh_network_t
  references one fabric and owns network_uid, membership, addresses,
  route manager, DNS/policy snapshots, per-network counters
```

`mesh_network_t` 继续是 opaque handle，因此内部可以从“整个 P2P 节点”迁移为“逻辑 Network
context”而不暴露结构布局。`事实`：当前 V2 fabric 内部复用一个 legacy `mesh_network_t` 作为
underlay，并为逻辑 Network 创建轻量 opaque handle；legacy `mesh_create()` 自身尚未改写为
private-fabric/default-Network facade。后者是兼容迁移终态。

### Additive v2 API 契约

以下实验性接口已由 [`turbo_mesh_multi_network.h`](include/turbo_mesh_multi_network.h) 提供；当前只承诺
single-owner、userspace、direct-member 与单跳 terminal gateway IPv4 切片：

| API | 参数与所有权 | 成功返回 | 主要错误 |
|-----|--------------|----------|----------|
| `mesh_fabric_create_v2(config, out)` | config 在调用期间 borrowed；成功后 `out` 由 caller 拥有 | `MESH_OK` | INVALID_ARG、NO_MEMORY、NETWORK、UNSUPPORTED |
| `mesh_fabric_attach_network_v2(fabric, spec, out)` | spec、peer 和 route 数组在调用期间 borrowed；创建独立 immutable copy | Network handle | INVALID_ARG、UNAUTHORIZED、CONFLICT、RESOURCE_EXHAUSTED、UNSUPPORTED |
| `mesh_network_apply_snapshot_v2(network, expected_generation, snapshot, out_generation)` | peer/route 在外部副作用前完成有界复制；generation 围栏后原子替换 | applied generation | INVALID_ARG、UNAUTHORIZED、STALE_EPOCH、CONFLICT、NO_MEMORY |
| `mesh_network_send_packet_v2(network, packet, len, deadline_after_ms)` | packet 只在同步调用期间 borrowed；V2 不保留 packet，deadline 必须非零 | sent | INVALID_ARG、TIMEOUT、NOT_FOUND、UNAUTHORIZED、NETWORK、CLOSED |
| `mesh_network_get_route_v2(network, index, out)` | caller 提供输出；按 canonical 稳定顺序返回 snapshot copy | route entry | INVALID_ARG、NOT_FOUND、CLOSED |
| `mesh_fabric_detach_network_v2(fabric, uid, deadline)` | 非零 deadline 是 admission contract；当前同步发送 CLOSE 后立即释放 | drain/tombstone result | INVALID_ARG、NOT_FOUND、BUSY |
| `mesh_fabric_destroy_v2(fabric)` | 停止 underlay 并销毁剩余 Network handle；callback 内禁止调用 | 无 | `void`；caller 必须遵循 single-owner 生命周期 |

`事实`：当前没有 packet queue，因此 `send` 与 `detach` 都是有界同步路径；下文 queue/traffic class/
TUN pause-resume 是后续 scoped routing/platform data plane 的目标契约，不应误读为已实现。

跨线程调用不得直接修改 fabric/network state。实现只能：

- 要求所有 data API 在 owner loop 调用；或
- 通过 `coro_post()`/有界 command channel 把 owned command 移交 owner。

不得给 route、peer、policy 各加一把锁来模拟“线程安全”。

## Peer、地址与 Network open

当前 peer 的单个 `virtual_ip` 身份必须拆成两层：

```text
underlay_peer
  managed_node_id / Noise public key / physical endpoints / paths

network_peer_binding
  network_uid / membership generation / virtual addresses / roles /
  policy epoch / session state
```

underlay peer table 以 `managed_node_id` 为 key。Network 内的 address index 使用
`(network_uid, family, binary_address) -> managed_node_id`。虚拟 IP 不再是 peer 身份。

Noise/P2P session 建立后，双方只获得 Mesh-level authenticated underlay。发送某个 Network 的数据前
执行类型化 `NETWORK_OPEN`：

```text
NETWORK_OPEN {
  network_uid,
  network_generation,
  membership_id,
  membership_generation,
  node_key_epoch,
  policy_epoch,
  capability_digest,
  not_after,
  proof
}
```

`proof` 不是 bearer string 或临时约定，而是 Controller 签发的 canonical
`NetworkMembershipTicketV1`：

```text
NetworkMembershipTicketV1 {
  schema_version,
  mesh_id,
  network_uid,
  membership_id,
  managed_node_id,
  node_public_key_digest,
  node_key_epoch,
  membership_generation,
  address_and_role_digest,
  policy_epoch,
  issued_at,
  not_before,
  not_after,
  issuer_key_id,
  signature
}
```

签名覆盖除 signature 外的完整 canonical bytes，并绑定当前 Noise identity public key digest。
首次 OPEN 携带完整 ticket；只有接收方已缓存同 digest、相同 issuer/key epoch 且 ticket 未过期时，
后续恢复才可只发送 ticket digest。ticket cache 是有界派生状态，miss 必须要求完整 ticket，不能从
DHT 推断 membership。`NETWORK_OPEN` 是 shared P2P underlay 上的类型化 Network control frame，
不是 H2/WS Controller mutation，也不能绕过 MMP/agent 的 desired-state 事实源。

接收方验证 Mesh、peer identity、Network、membership、epoch、有效期和 proof 的完整绑定。成功只创建
该 peer 的 Network binding；失败不得影响同一 underlay 上已经合法打开的其他 Network。

binding 状态：

```text
CLOSED -> OPENING -> ACTIVE -> DRAINING -> CLOSED
             |          |
             +-> REJECTED
```

REJECTED 原因稳定区分 unknown network、not member、stale epoch、revoked、expired、policy denied 和
resource exhausted。Network revoke 必须 fencing 旧 binding；单靠墙钟或删除本地 cache 不足以撤销。

## 数据面 v2

### 作用域

每个 v2 packet/flow envelope 必须语义上绑定以下字段：

```text
protocol version
network_uid
network_generation / policy_epoch
source managed_node_id
destination managed_node_id or authorized gateway
address family
source and destination locator
payload kind and exact payload length
flow/security-context ID
monotonic packet sequence
hop limit
authentication/integrity binding
```

编码使用固定 canonical binary schema、network byte order、显式 version/header length 和 checked
length arithmetic。decoder 必须先验证 magic/version/header/payload length、保留位和上限，再访问
内层 packet。未知 version、未知 Network 或 malformed frame 直接拒绝，不能回退为裸 IPv4。

`HIGH / 迁移要求`：当前接收路径把未识别 payload 当裸 IP。v2 frame 上线前必须增加不可歧义的
frame discriminant，并让 protocol-major/capability negotiation 保证旧 peer 永远不会收到 v2 frame。

### 转发查找

所有数据面 key 从 `destination_ip` 升级为：

```text
(network_uid, address_family, destination_prefix/address)
```

route candidate key 为：

```text
(network_uid, origin_node_id, address_family, destination_prefix)
```

next hop 指向 shared underlay peer 的 `managed_node_id`，而不是另一个 Network 的虚拟 IP。route
advertisement、withdraw、expiry、replay window 和 selected snapshot 都保留 `network_uid`。

Network A route 不得成为 Network B 的 candidate 或 fallback。固定 route 不可用时返回明确失败，
不得尝试同地址的其他 Network。

### Payload security

P2P Noise 提供当前 underlay hop 的 peer authentication、confidentiality 和 integrity，但这不自动
证明多跳 packet 的原始发送者，也不自动阻止受信 relay 读取 payload。

因此分两级发布：

1. Multi-network correctness gate：Network envelope、membership fencing、hop-by-hop secure underlay、
   direct-endpoint source-address validation 和 default-deny forwarding 全部完成。此阶段多跳只允许
   policy 明确标记的 trusted relay；hard tenant confidentiality 与 hostile-relay origin protection
   仍要求不同 Mesh trust domain。
2. Secure relay gate：启用 [`MESH_PLATFORM_DESIGN.md`](MESH_PLATFORM_DESIGN.md) 定义的端到端
   security context；routing header 作为 AEAD AAD，payload 对非端点 relay 保密，destination 验证
   origin、sequence 和 Network binding。未完成独立安全审查前不得宣称“不可信 relay 不可读”。

不使用共享 Network group key 替代逐端点身份，因为任一成员持有 group key 会扩大伪造面。discovery
metadata key 与 packet data key 必须分离。

### Source-address validation

端点和 local-egress/subnet-router 在交付 packet 前必须验证：

```text
authenticated source node
  owns source address in this network generation
  and membership is ACTIVE
  and packet policy allows flow
  and route/gateway capability is valid
```

只比较“源 IP 等于上一个直连 peer 的 IP”不能覆盖多跳 origin，也不能覆盖一个 peer 多 Network。
校验失败计入 spoof/replay audit，packet 被丢弃，不触发动态地址学习。

## DHT、发现、DNS 与路由

### DHT

DHT 只是 derived discovery cache，不能分配地址或授予 membership。新 key 不再包含可变名称：

```text
m2:<hex(HMAC-SHA256(discovery_key_epoch,
                    record_type || network_uid || binary_address))>
```

descriptor 绑定 network UID、address、node ID、endpoint、membership generation、key epoch、expiry 和
signature。只有 Network member snapshot 能取得对应 discovery key；移除成员时按 policy 轮换
discovery key。DHT 缺失或过期只表示需要重新发现，不能改变 Controller membership。

旧 `mesh:<network_id>:ip:<virtual_ip>` key 只服务 default legacy Network，不能被 v2 Network 查询。

### DNS

DNS record key 为 `(network_uid, canonical_name, type)`。每个 Network 默认使用独立 suffix；如允许
相同 suffix，resolver 必须由入站 interface/explicit Network handle 选择视图，不能把多 Network
记录合并为一个无作用域 cache。

同一节点在不同 Network 可以有不同名称和地址。DNS 返回地址后，data plane 仍验证目标 node identity；
DNS 名称或 IP 不是认证身份。

### Route

external subnet、exit 和 inter-network gateway 都是显式 route source：

- subnet-router：当前 Network 到一个外部 prefix。
- exit：当前 Network 到默认路由。
- network-gateway：两个 Network 之间经批准的 prefix pair。

route publish 必须携带 origin authentication、network UID、route epoch、sequence、expiry 和 capability。
learned route 不得越过 Network context。withdraw/expiry 只删除同 source、同 Network 的 candidate。

`事实 / 当前安全切片`：`mesh_network_spec_v2_t` 已携带 `route_epoch` 和 bounded route array。每条 route
使用 canonical IPv4 prefix、kind、metric 和 32-byte managed node ID；snapshot 复制后排序，查找使用
最长前缀，其次较低 metric，最后 node ID。直接成员地址优先于 external route。route 的 next hop 必须
是本 Network 的 authorized peer 或本地节点；OPEN ticket 把 role 签入 Controller 证明，subnet route
要求 `SUBNET_ROUTER`，默认路由要求 `EXIT`。角色在相同 membership/key epoch 下改变会被拒绝。

发送方只向选中的 gateway 建立一个已有的认证 underlay hop。接收 gateway 只有在自己的 snapshot 中也
存在指向本节点且覆盖该目的地址的 route、并且本地签名 membership 具有对应 role 时才交付 callback。
任一侧 snapshot 缺失、peer 未连接、role 不符或 Network 不同都 fail closed。该 callback 是 terminal
gateway 边界：它可交给后续 OS subnet/exit adapter，但当前不能把 origin frame 当成安全多跳 envelope
继续转发。`TCN1` 已在 peer tail 后追加最多 256 个 canonical 40-byte route record，并在原保留字段写入
route count；0-route 旧编码保持原字节不变。`route_digest` 使用 BLAKE2b-256 绑定完整 route tail，decoder
验证 digest、排序、prefix、next hop 和本地签名 role 后，reconciler 才构造 runtime snapshot。当前尚缺
deployable Controller/agent 把这份 document 可靠送达节点，以及 OS gateway side-effect transaction。

## 重叠 CIDR 与 OS 接入

Mesh core 能通过 Network handle 和 `network_uid` 区分重叠地址；OS 应用未必能区分。平台能力分为：

| 接入方式 | 重叠 CIDR | 要求 |
|----------|-----------|------|
| userspace packet/flow API，调用方持有 Network handle | 支持 | 调用方显式选择 Network |
| 每 Network 独立 network namespace/VRF/routing compartment | 目标支持 | platform adapter 宣告并通过隔离测试 |
| 同一全局 routing table 的多个 TUN | 不支持 | Controller 必须在 attach 前拒绝冲突 |

Controller 的 placement/attach planner 根据节点上报的 immutable platform capability 判定。若节点已经
attach Network A 的 `10.60.0.0/16`，又请求 attach Network B 的相同/重叠 prefix，而节点没有经过
验证的 overlap-isolation capability，PLAN 和 APPLY 都返回 CONFLICT；不得依赖 route metric 猜测。

一个 Network 内 pool 重叠始终非法，与平台能力无关。

## 控制原语与 meshctl

### 南向原语

V1 保持现有 resource kind：

| Resource kind | payload |
|---------------|---------|
| `NETWORK APPLY` | per-node compiled Network snapshot，包含 membership、address、policy/DNS/route digest |
| `NETWORK DELETE` | DRAINING/TOMBSTONED intent、deadline、generation |
| `ROUTE APPLY/DELETE` | scoped route intent，必须包含 `network_uid` |
| `NODE OBSERVATION` | platform/network capabilities 与 active Network 摘要 |

AddressPool、Membership 和 NetworkGateway 是 Controller 领域资源；只有节点确实需要独立持久化和
reconcile 时才新增南向 resource kind。当前 `mesh_control_envelope_v1_t.resource_id` 绑定 Network
resource，payload digest 绑定完整 typed document。

所有 mutation 都需要 request ID、base generation、expiry 和 durable receipt。提交结果未知时先按
request ID 查询 operation；禁止盲目重试产生第二个 Network。

### meshctl 命令面

```text
meshctl networks list
meshctl networks get <network>
meshctl networks plan -f network.toml
meshctl networks apply -f network.toml
meshctl networks delete <network> --drain-timeout <duration>

meshctl networks members list <network>
meshctl networks members plan <network> -f members.toml
meshctl networks members apply <network> -f members.toml
meshctl networks members revoke <network> <node>

meshctl networks pools list <network>
meshctl networks pools plan <network> -f pools.toml
meshctl networks pools apply <network> -f pools.toml

meshctl routes plan -f route.toml
meshctl routes apply -f route.toml
meshctl routes delete <route>
```

`subnet` 一词只用于 external subnet router 的用户叙事；overlay 地址资源在 CLI 中使用 `pools`，
避免把 address pool 与 external routed LAN 混为一物。所有 route 命令必须显示所属 Network。

PLAN 至少输出：

- base/current generation 和 plan digest；
- 将加入、移除、drain 的节点；
- address/prefix/DNS 冲突；
- 节点 overlap-isolation、IPv6、MTU 和 protocol capability；
- route/gateway 权限变化；
- 预计受影响 flow 数和需要审批的 HIGH 风险；
- 回滚目标 generation。

## H2、WebSocket、FlowMQ 与 CoroNet 边界

- H1/H2 request/response 用于资源查询、plan、mutation accept 和 durable receipt 查询。
- H1 RFC 6455/H2 RFC 8441 WebSocket 用于有序 watch、agent outbound sync 和 targeted intent。
- FlowMQ 是 agent 与 `meshd` 的本地 typed control plane；NETWORK command/result 使用可靠、有界、
  认证的 channel。
- CoroNet 提供 TCP/TLS/WebSocket/Pipe transport 和 owner event loop，不负责 RBAC、Network
  membership 或 resource generation。
- `pipe://` 只有在外部 OS ACL 已验证的 trusted-local profile 才可用；production 默认是
  FlowMQ over TLS 1.3/mTLS loopback，不允许从 TLS 自动 fallback 到裸 Pipe。
- packet bytes、媒体帧和大对象不通过 H2/WS control frame 或 FlowMQ control command 搬运。

adapter 收到的 CoroNet recv buffer 由 CoroNet 拥有。解析、认证和入队必须在
`coro_socket_free_recv()` 前完成；若 command 要跨 callback/协程挂起或进入队列，必须复制到 bounded
owned document。`coro_context_spawn()` 管理的 coroutine 自动回收，不手工 destroy。

## Ownership、容量与背压

### 线程和所有权

- 一个 `mesh_fabric_t` 由一个 CoroNet context/owner loop 独占所有可变 peer、path 和 Network 状态。
- 每个 `mesh_network_t` 的 route/policy/address state 只能在同一 owner loop 原子替换。
- Controller/agent/FlowMQ adapter 是 producer；fabric owner 是 command consumer。
- data packet buffer 入队成功后所有权 move 给 fabric；失败时 caller 仍拥有 buffer。
- public borrowed packet 只在同步调用期间有效；任何挂起、排队或重传前必须成为 owned bounded buffer。
- immutable snapshot 可以 retain/release；old snapshot 在所有 in-flight readers release 后回收。
- OS side effect 只由 `meshd` platform transaction owner 执行；Mesh callback 不直接修改系统路由。

### V1 配额基线

这些是可配置的初始 hard limit，不是吞吐承诺：

| 资源 | 默认 | hard maximum | 满载行为 |
|------|------|--------------|----------|
| attached Networks / fabric | 16 | 64 | attach 返回 RESOURCE_EXHAUSTED |
| address pools / Network / family | 4 | 8 | Controller PLAN 拒绝 |
| addresses / node / Network / family | 2 | 4 | APPLY 拒绝 |
| route entries / Network（当前 runtime） | 256 | 256 | snapshot 返回 INVALID_ARG；不覆盖旧 snapshot |
| active peer-Network bindings / fabric | 1024 | 4096 | NETWORK_OPEN 拒绝 |
| NETWORK_OPEN timeout | 5 s | 30 s | OPENING 终止并释放 ticket/session state |
| queued packets / peer-Network binding | 64 | 256 | send 返回 BUSY |
| retained bytes / peer-Network binding | 512 KiB | 2 MiB | send 返回 BUSY |
| retained bytes / Network | 8 MiB | 16 MiB | 对该 Network 背压 |
| retained packet bytes / fabric | 32 MiB | 64 MiB | 对所有新 data enqueue 背压 |
| Network detach drain | 30 s | 5 min | 超时后取消未发送 data 并报告 TIMEOUT |
| southbound control document | 64 KiB | 64 KiB | INVALID_ARG/RESOURCE_EXHAUSTED |
| status snapshot | 256 KiB | 256 KiB | 使用分页/游标，不截断为成功 |

`计算`：即使 4096 个 peer-Network binding 各自允许 2 MiB，实际 retained payload 仍受 fabric
64 MiB aggregate cap 限制：

```text
retained_packet_bytes
  <= min(sum(per_binding_retained_bytes),
         sum(per_network_retained_bytes),
         fabric_retained_limit)
  <= 64 MiB
```

`计算 / 当前 runtime`：一个 IPv4 route entry 为 `4 + 1 + 1 + 2 + 32 = 40 bytes`，故单 Network
route payload 上限为 `256 * 40 = 10,240 bytes`，另加 Network 对象和 allocator 开销。apply 先分配并
验证完整新数组；OOM 或非法 entry 时旧 snapshot 不变。

所有乘加在分配前做 checked arithmetic。未来提高 hard limit 必须有峰值内存、饱和队列、P95/P99 和
shutdown benchmark，不按配置文件任意扩容。

### 背压

- control mutation queue 满：返回 RESOURCE_EXHAUSTED；Controller durable outbox 可在原 expiry 内重试，
  不丢弃、不覆盖、不 coalesce mutation。
- observation/status：允许按 `(network_uid, resource_id)` coalesce，但必须递增 gap/dropped counter，
  watch client 通过 cursor 发现 gap 后重新取 snapshot。
- 当前 direct API data send 没有 packet queue，完成同步 admission/send 或返回明确错误；未来引入有界
  queue 后，满载返回 BUSY，由调用方决定 deadline 内重试。
- TUN ingress：达到 high watermark 后暂停 owner loop 的 TUN read；恢复到 low watermark 后继续。
  平台无法暂停时允许显式 packet drop，并记录 Network-scoped drop reason；不能无界复制。
- shutdown 会唤醒所有等待者并返回 CLOSED/INTERRUPTED，不允许无限阻塞。

## 生命周期与关闭

fabric 状态：

```text
CREATED -> RUNNING -> DRAINING -> CLOSED
```

关闭顺序固定：

1. 原子停止接受新的 Network attach、NETWORK_OPEN、route 和 data enqueue。
2. 停止 Controller/FlowMQ ingress，唤醒阻塞 producer。
3. 将未开始的 mutation 标记 INTERRUPTED；已提交外部副作用的 operation 完成 rollback 或返回明确
   unknown/applied observation。
4. 按每 Network deadline drain 或取消已发布 packet/flow，释放 owned payload。
5. 关闭 Network binding，注销 DHT/DNS/route 派生状态。
6. 等待 snapshot reader、recv buffer、queue claim 和 Network handle 归零。
7. 关闭共享 peer/path/session，再停止 CoroNet managed coroutines、listener 和 context。
8. 销毁 fabric 和 platform resources。

删除一个 Network 执行步骤 3..6 的子集，不得提前关闭 fabric。pending recv 通过 CoroNet 的明确
interrupt/close 路径唤醒；不得在还有 live socket/coroutine 时销毁 context 或执行 TLS global cleanup。

## 安全模型

### 授权

有效权限是以下集合的交集：

```text
authenticated principal RBAC
∩ Mesh grant
∩ Network-scoped grant
∩ Route/gateway grant
∩ target node immutable local policy
∩ runtime capability
```

至少定义：

- `network.observe`
- `network.create`
- `network.update`
- `network.delete`
- `network.member.manage`
- `network.attach`
- `route.advertise`
- `route.use`
- `route.administer`
- `network.gateway`

Network admin 不自动拥有 Mesh identity admin；membership admin 不自动获得 route advertise/use；
gateway 需要两侧 Network 的显式权限。

### 威胁与拒绝规则

| 威胁 | 必须行为 |
|------|----------|
| 猜测/伪造 Network UID | membership proof 失败并审计；不返回 Network metadata |
| 跨 Network 重放 packet | Network UID/epoch/security context 不匹配，拒绝 |
| 源 IP spoof | 根据 source node membership/address lease 拒绝 |
| stale membership/route | fencing by generation/key epoch；不接受墙钟“看起来更新” |
| 恶意 route advertisement | 验证 advertise capability、origin、sequence、expiry 和 Network |
| gateway 半应用 | 两侧 generation 未同时 ACTIVE 时不转发 |
| 控制面分区 | 使用未过期 last-known-good snapshot，不扩大权限 |
| snapshot 过期 | 禁止新 session/route；按 policy 关闭或 drain 旧 flow |
| downgrade 到 legacy/raw packet | 非 default Network 禁止；capability mismatch fail closed |
| 队列耗尽攻击 | per-binding、per-Network、per-fabric 三层配额和 reject metric |

审计不得记录 private key、membership proof、discovery key、packet payload 或完整敏感 policy body。

## 错误语义

v2 领域错误必须稳定区分：

| 错误 | 用户可见语义 |
|------|--------------|
| INVALID_ARG | schema、长度、地址、保留位或不变量非法 |
| UNAUTHORIZED | 身份已知但没有 Network/route/action 权限 |
| NOT_FOUND | Network、node、route 或 destination 不存在 |
| CONFLICT | 地址、名称、OS route 或 precondition 冲突 |
| STALE_EPOCH | generation、membership、policy、route 或 key epoch 过旧 |
| RESOURCE_EXHAUSTED | hard capacity 已满 |
| BUSY | 暂时背压；没有接受 packet/command |
| TIMEOUT | deadline 到期且未完成 |
| UNKNOWN_COMMIT | mutation 可能已提交；必须按 request ID 查询 |
| UNSUPPORTED | 节点缺少 multi-network/IPv6/overlap isolation capability |
| CLOSED | Network/fabric 正在 drain 或已关闭 |

旧 API 继续返回现有 `MESH_ERR_*`。新 adapter 在边界映射错误，但内部不能把
UNAUTHORIZED/STALE/CONFLICT 都压成 NOT_FOUND 或 NETWORK。

## 可观测性

每个事件和 metric 至少携带 `mesh_id`、`network_uid`、generation/epoch、node ID 和 operation/request
ID；高基数字段不进入无界 metric label，详细 ID 进入有采样/retention 的 event。

指标包括：

- attached Network、ACTIVE/DRAINING/ERROR 数；
- membership/network-open accept、reject 和各 reason；
- per-Network route candidate/selected/expired/withdraw；
- queue entries、retained bytes、high watermark、BUSY/drop；
- cross-network policy reject 和 spoof/replay reject；
- snapshot current/applied generation、age、signature failure 和 rollout lag；
- TUN/OS stage、commit、rollback、cleanup error；
- shared underlay connection 数与复用的 Network binding 数；
- Network deletion drain duration 和残留离线节点数。

诊断接口必须能回答“这个 packet/flow 属于哪个 Network、使用哪个 policy/route generation、为何选择
该 next hop、在哪个边界被拒绝”，但不能导出密钥或 payload。

## 协议与 API 兼容迁移

### 能力协商

新增能力：

```text
MESH_CAP_MULTI_NETWORK_V2
MESH_CAP_NETWORK_FRAME_V2
MESH_CAP_NETWORK_MEMBERSHIP_V1
MESH_CAP_NETWORK_OVERLAP_OS
MESH_CAP_NETWORK_IPV6
MESH_CAP_SECURE_RELAY_ENVELOPE
```

多 Network peer 必须同时满足 protocol major 和必需 capability。legacy peer 只能加入 deterministic
default Network。v2 节点绝不能把 Network frame 发给只接受裸 IPv4 的 peer。

### 迁移阶段

1. `S0 冻结事实`：保持 legacy tests；加入 design/schema golden vectors，不改变 runtime。
2. `S1 内部分层`：peer table 改为 node identity owner；建立 private fabric + default Network
   compatibility facade，行为仍等价于当前。
3. `S2 scoped state`：route/address/DNS/policy key 全部加入 `network_uid`，但仍只启用 default。
4. `S3 v2 frame`：严格 decoder、capability negotiation、Network OPEN 和同节点两个不重叠 Network。
5. `S4 Controller/agent`：typed Network/membership/route snapshot、bounded reconciler、standalone agent
   APPLY/DELETE、result-WAL-before-observed、restart runtime rebuild 与内部 `meshd` Network IPC 组合已完成；
   meshctl plan/apply/delete 适配面已完成；deployable Controller、主动 agent session、agent 启动接线和
   跨进程恢复仍待完成。
6. `S5 platform`：每 Network TUN/DNS/route transaction；无隔离能力时拒绝重叠 CIDR。
7. `S6 gateway`：双边 generation、route grants、fail-closed inter-network routing。
8. `S7 secure relay`：端到端 envelope、安全审查和跨平台/多跳验证后再开放对应销售承诺。
9. `S8 IPv6`：binary address、route/policy/DNS/platform 全链验证后按 capability 下发。

每阶段默认 feature flag 关闭；未达到该阶段完整 gate 的功能不出现在 stable CLI help 或产品能力表。

### 回滚

- S1/S2 可切回 legacy facade，因为只有 default Network 且 wire 未改变。
- 启用 S3 后，回滚前必须先 drain 所有非 default Network，确认无 active binding、route、TUN 和
  gateway，再把节点切回 legacy protocol。
- Controller 保留 Network record/tombstone；回滚 runtime 不删除管理数据。
- rollback 不允许把多个 Network 合并到 default，也不把重叠地址自动改写。
- OS apply 失败回滚到上一 applied snapshot；没有可验证 rollback snapshot 时保持 fail-closed。

## 验证门槛

### 单元与 property tests

- ID/legacy deterministic mapping、CSPRNG failure propagation 和 resource ID golden vector。
- Network/AddressPool/Membership/RouteGrant schema 的 0、1、max、max+1 和 overflow。
- generation、precondition、tombstone、membership fencing 和 terminal operation。
- 任意生成的 Network/地址/route 集合中，lookup 永远不会返回其他 Network 的 entry。
- 同 Network pool overlap 必拒绝；跨 Network overlap 仅在 platform capability 满足时 attach。
- v2 decoder 对短帧、超长、未知 version、未知 flags、长度溢出和 legacy downgrade fail closed。
- source spoof、stale membership、stale route、cross-network replay 和 gateway half-apply 被拒绝。

### 集成

- 两节点共享一个 underlay，同时打开两个 Network；删除其中一个不影响另一个。
- 单跳 terminal subnet/exit route 在 Network A 交付，Network B 的相同 route 因 role/Network scope 拒绝
  （已覆盖）；三节点普通成员多跳待 secure relay gate 后验证。
- 两个 Network 使用相同 IPv4 地址，通过 userspace handle 正确隔离。
- 无 overlap OS capability 的节点在 PLAN/APPLY 阶段拒绝重叠 attach。
- subnet-router 只能接收获批 external prefix；另一个 Network 的相同 prefix 不被误用（当前 callback
  terminal 边界已覆盖；OS 转发 transaction 待实现）。
- Controller 重启、agent 重启、outbox 重放、ACK 丢失和 UNKNOWN_COMMIT 恢复。
- Network DRAINING 阻止新 flow，deadline 后释放 queue、binding、TUN、DNS 和 route。
- legacy v1 节点只看到 default Network；capability mismatch 不接收 v2 frame。

### 并发、资源与安全

- queue full、per-Network/fabric byte cap、TUN pause/resume、关闭唤醒和 ownership balance。
- CoroNet pending recv、peer close、Network detach、fabric destroy 的顺序回归。
- ASan/UBSan 验证 buffer/length/cleanup；TSan 或等价验证 cross-thread post 与 snapshot swap。
- 模糊测试 Network frame、NETWORK_OPEN、signed snapshot 和 route advertisement decoder。
- 64 Network、256 peer、4096 active binding 的容量边界；典型、峰值和饱和 workload 分开测量。
- 独立安全测试覆盖 malicious member、malicious relay、replay、route injection 和 key epoch rotation。

性能测试结果出来前，不宣称多 Network 对吞吐、延迟或连接数没有影响。

## 架构与实现影响

| 模块 | 影响 |
|------|------|
| `mesh/include/turbo_mesh.h` | additive opaque fabric/v2 address/network API；旧 ABI 保留 |
| `mesh/src/mesh.c` | 从单一 peer/IP/route owner 拆为 fabric owner + Network context；v2 frame dispatch |
| P2P/Noise | 继续作为 Mesh underlay；不为每 Network 复制身份；增加 capability/channel binding |
| DHT | 新 Network-scoped、key-epoch-scoped derived descriptor；legacy key 保留给 default |
| route/path | route key、candidate、replay、metric 和 selected snapshot 全部 Network scoped |
| packet policy | 输入加入 Network、origin node、membership/route generation |
| mesh-agent control | typed Network snapshot、generation/precondition、receipt 和 observation |
| `meshd` | 每 Network OS transaction、overlap capability、drain/delete |
| FlowMQ | 本地 NETWORK command/result/status adapter；不承载 packet payload |
| meshctl/Controller | Network/member/pool/gateway resource、PLAN、RBAC、audit |
| tests | legacy regression、多 Network 隔离、overlap、security、shutdown 和 scale |

`推论`：该重构影响至少 Mesh core、P2P binding、控制面、meshd/platform 和测试，迁移成本明显超过
局部 patch。必须按阶段提交，每阶段保持 default Network regression，而不是一次性替换整个
`mesh.c`。

## 完成条件

只有以下证据全部成立，才可宣称“一个 Mesh 支持多个隔离 Network”：

- 一个 P2P underlay 被至少两个 Network 正确复用。
- frame、route、DHT、DNS、policy、replay、telemetry 全部以 `network_uid` 为 scope。
- node identity 与 per-Network address/membership 已分层。
- unauthorized、stale、cross-network 和 direct-peer spoof packet 在端点与 gateway fail closed；
  hostile-relay origin spoof 必须在 secure relay gate 后通过。
- Network APPLY/DELETE 有 Controller durable receipt、agent reconcile 和 OS rollback。
- 删除/撤销一个 Network 不影响同 fabric 的其他 Network。
- 重叠 CIDR 在 userspace/隔离 OS profile 中通过，在不支持的平台明确拒绝。
- legacy default Network 行为和公开 API regression 通过。
- hard capacity、backpressure、shutdown、ASan/TSan/fuzz 和多节点测试通过。
- secure relay gate 未完成时，文档和销售材料明确受信 relay 的保密边界。

## 仓库依据

- [`turbo_mesh.h`](include/turbo_mesh.h)：当前单 Network public config、route、policy 和 IPv4 API。
- [`mesh.c`](src/mesh.c)：当前 `network_id` 安全 hash、DHT key、peer/route lookup 与裸 IPv4 data path。
- [`test_mesh.c`](tests/test_mesh.c)：当前 default network DHT key 与 packet route compatibility tests。
- [`test_mesh_multihop.c`](tests/test_mesh_multihop.c)：当前多跳 route 以单一虚拟 IPv4 域验证。
- [`mesh_control_primitives.h`](src/mesh_control_primitives.h)：NETWORK/ROUTE resource、envelope、
  frame/status hard limit 与 operation state。
- [`MESH_PRODUCT_CONTROL_PLANE.md`](MESH_PRODUCT_CONTROL_PLANE.md)：Controller、identity、grant、
  IPAM、MagicDNS 和 agent 事实源。
- [`MESH_PLATFORM_DESIGN.md`](MESH_PLATFORM_DESIGN.md)：TUN、route/path、exit、secure data envelope、
  CoroNet owner loop 与 platform transaction。
- [`MESHCTL_PRIMITIVES_DESIGN.md`](MESHCTL_PRIMITIVES_DESIGN.md)：QUERY/PLAN/MUTATE/WATCH、H2/WS、
  timeout、幂等和资源命令树。
- [`MESH_LOCAL_IPC_DESIGN.md`](MESH_LOCAL_IPC_DESIGN.md)：FlowMQ secure local control plane。

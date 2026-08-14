# meshd Typed IPC 设计：FlowMQ Secure Transport + MeshNodeIPC/1

## 文档状态与结论

状态：独立 FlowMQ transport adapter、transport-neutral client/server state machine、双端 runtime、
可注入 agent reconciler 的 prestaged builtin/Native provider，以及拥有 Network reconciler/executor/
server runtime 的 `meshd` 内部组合服务已完成同进程真实 mTLS 组件测试；adapter 还通过独立
server/client current/next leaf、双向 EKU 错配、old pin 移除、进程边界 typed mTLS 往返和 listener
restart 自动重连测试。远程 `mesh-agent` durable/H2 service composition、Controller durable outbox、
certificate identity registry 和在线 session fencing 已实现；FlowMQ provider 仍需由发布进程显式注入，
本地 channel 的自动换证、service-manager crash/restart、生产私钥存储与审计仍是发布缺口。本文只定义
本地控制边界，不改变 Mesh packet wire、
MMP 南向协议或 Controller 事实源。

`决策`：production V1 使用独立包 **`FlowMQ::FlowMQ` over CoroNet TLS/mTLS loopback**。`meshd` 使用
`ROUTER(bind, max_connections=1)`，`mesh-agent` 使用 `DEALER(connect)`，形成一对一双向控制通道。
FlowMQ DATA payload 是独立的 canonical typed protocol `MeshNodeIPC/1`。每个 endpoint 只允许显式
loopback；BIND 要求 client certificate，CONNECT 验证 server certificate；双方还必须校验对端 FlowMQ
HELLO identity。构建只允许 `find_package(FlowMQ CONFIG REQUIRED)` 并链接 `FlowMQ::FlowMQ`，不依赖
TurboFlow facade、旧 target alias 或 FlowMQ 内部子 target。

CoroNet TLS 是字节 transport；FlowMQ 提供 framing、ROUTER/DEALER session、heartbeat、reconnect 和
generation-fenced route。两者都不是业务事实源，也不定义网络资源语义。
`MeshNodeIPC/1` 定义 command、accept、result、status、dedupe 和 restart reconciliation；Controller
desired state、agent WAL/checkpoint 与 `meshd` 当前执行 snapshot 的归属保持不变。

`HIGH 发布前置条件`：CoroNet `Pipe` 没有本方案需要的安全规则，production profile 因此禁止自动使用
Pipe、raw TCP 或 WS。CoroNet 已能导出 verified peer certificate SHA-256；standalone FlowMQ ROUTER v4
和 CONNECT v3 已在各自 admission/READY 前提供对称 certificate-to-HELLO verifier，本 adapter 以有界
immutable exact map 强制双向安装。当前同进程真实 mTLS 测试已覆盖成功路径、双方 unmapped/old-pin
certificate 拒绝、独立 current/next leaf overlap 和双向 EKU 错配；当前显式 TLS client config 禁用
session cache，重连必须重新握手和 mapping。在完成
[`FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md`](FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md) 的生产证书生命周期、
存量 session fencing 与审计门槛前，shared multi-tenant profile 仍保持 pre-production。

## 仓库事实与边界

`事实`：

- 独立 FlowMQ 安装包导出 `FlowMQ::FlowMQ`，public API 提供 `flowmq_router_endpoint`、
  `flowmq_connect_endpoint`、协议 codec 和 CoroNet TLS adapter；本仓库不再 include `turbo_flow_fmq.h`。
- `flowmq_router_endpoint` 返回 `{endpoint_id, generation, session_id}` route token；disconnect/heartbeat
  失效后旧 generation 不可继续发送，避免把重连前 route 误用于新 session。
- ROUTER endpoint API v4 与 CONNECT endpoint API v3 都以同 socket verified leaf certificate SHA-256
  和 claimed HELLO identity 调用 verifier；旧 v3/v2 配置通过 `size` 前缀保持通用 FlowMQ 兼容。
- receive callback 的 frame、payload、topic 和 identity 是 borrowed view，callback 返回后失效。本 adapter
  在 callback 内只校验并复制到有 entry/byte 双硬上限的 owned channel。
- `flowmq_*_endpoint_send_copy()` 的成功只表示本地有界发送队列接受复制，不表示 socket send 完成、
  远端 owner admission、执行或持久化；
  `ACCEPTED`、`RESULT` 与 exact `ACK_RESULT` 仍由 `MeshNodeIPC/1` 表达。
- 本 adapter 只调用独立 FlowMQ 的线程安全、有 entry/byte 硬上限的 `*_send_copy()`，不直接使用
  CoroNet API；FlowMQ completion callback 只收敛本地 socket-send 结果。caller poll 不等待 callback，
  后续 poll 才收敛完成；timeout 不消费 outbound queue head。
- client state machine 在 bounded operation table 中分别跟踪 COMMAND/ACCEPTED/RESULT；terminal result
  保留到上层 durable commit 后调用 exact ACK。outbound 满时 ACK admission 失败且 result 不释放。
- `mesh_node_control_flowmq_provider` 已实现 `mesh_control_provider_v1_t`，一次串行一个 prestaged
  builtin/Native mutation；它只重新编码 typed function document，不接收 path、argv 或 executable bytes。
- Mesh control provider 的 `try_start` 是非阻塞接口；若保留 request 必须在返回前复制，临时满载
  返回 `RESOURCE_EXHAUSTED`，completion 必须保留到 exact ACK
  （[`mesh_control_reconciler.h`](src/mesh_control_reconciler.h)）。
- `meshd` 当前在单一主循环中调用 `mesh_poll()`；Mesh 可变状态必须继续由该 owner 推进，IPC
  callback 不得跨线程直接修改 route、policy、peer 或 packet-path 状态。
- 现有 control frame 上限为 64 KiB，function assignment 已有 232-byte canonical document。

`事实`：当前已实现并完成 Release 组件测试的部分是：`MeshNodeIPC/1` envelope/COMMAND/RESULT
canonical codec、header/body SHA-256、严格 reserved/size/enum 校验、显式 `mesh_id` scope、有 entry/byte
双硬上限且复制 borrowed callback bytes 的 SPSC channel、单 owner command executor、operation binding
去重/冲突拒绝、未 ACK result retention，以及 Network APPLY/DELETE executor。Network executor 会交叉
核对 IPC Mesh、canonical Network document Mesh、resource ID 和 generation，再调用 bounded
`mesh_network_reconciler`；删除一个 Network 不关闭共享 fabric。

`边界`：当前已有可选 FlowMQ 构建依赖、ROUTER/DEALER mTLS adapter、client/server runtime、可注入
reconciler 的 prestaged function provider，以及借用 shared fabric、拥有 Network reconciler/executor/
runtime 的 `meshd` 内部组合服务。`meshd` 已接入默认关闭、严格校验的 flat config，并在启用时让 fabric
成为唯一 underlay owner；组件测试覆盖真实 mTLS 双 Network APPLY、按 resource 独立 DELETE、fabric
attach/detach、RESULT、exact ACK、停止准入和 drain。双向 certificate-to-identity binding、进程边界
往返、真实 current/next leaf overlap、old pin 新连接拒绝、EKU 角色校验和 listener restart 重认证已经
完成。远程 H2 agent runtime、certificate lifecycle、Controller durable outbox 和存量 session
fencing 已作为独立组件实现；`mesh-agent` 已通过有界 async Network provider 接入 FlowMQ，并保证
RESULT 先进入 agent WAL、推进 observed state，之后才 exact ACK。agent restart 会为已持久化的
Network desired state 派生稳定 restore operation；`meshd` 对同 generation、同 document digest 的
重投返回幂等成功。尚未完成的是本地通道无停机自动换证和 `meshd` durable result cache；`meshd`
incarnation 改变仍会丢失内存 result retention，agent 必须按相同 binding 恢复或重投。因此这仍不是
完整的多租户可部署能力清单。

## 目标与非目标

目标：

- 让 agent 以类型化 command 管理 `meshd` 的 network、route、service、DNS/policy snapshot 和
  可查询 diagnostics。
- 让 `meshd` 以类型化 accepted/result/status 返回 observed state，不暴露内部可变结构。
- 支持断线重连、进程重启、同 operation ID 重投、epoch fencing、显式背压和有界关闭。
- 保持数据面自治：IPC 或 agent 故障不停止已经授权并建立的 Mesh flow；新的管理变更停止推进并
  报告 stale/unknown。
- 保持依赖隔离：Mesh control core 不包含 FlowMQ public type，FlowMQ 只是 provider adapter。

非目标：

- 不通过 IPC 发送 shell、任意 argv、宿主路径、动态库名、native executable 或 WASM bytes。
- 不把 FlowMQ delivery、`ACCEPTED` 或进程内排队误报为 durable execution。
- 不用 IPC 替代 Controller transaction、agent WAL、OS service manager 或 Mesh packet protocol。
- V1 不允许多个本地管理 client 直连 `meshd`；ROUTER 的 `max_connections=1` 是强制 profile，不能把
  ROUTER 能力误解为多 authority。

## 候选方案

| 方案 | 优点 | 主要问题 | 结论 |
|------|------|----------|------|
| FlowMQ `ROUTER/DEALER` over TLS/mTLS loopback | 独立包当前公开支持；双向 verifier；route generation fencing；独立双 leaf/EKU 与进程边界往返已验证 | ROUTER 必须限制单连接；生产签发/存储/重载/吊销和存量 session fencing 仍需补齐 | production V1 control 采用 |
| 在同一 control channel 上复用 typed STATUS/QUERY | 不增加认证面；复用 operation/result 协议 | 高频 telemetry 会争抢控制容量 | P1 只允许低频、分页、有界状态 |
| 独立 observation/telemetry/worker endpoint | 隔离容量、超时和可靠性类别 | 当前独立包没有本文可依赖的高级 facade；需要单独设计/验证 | 后续，不列为现有能力 |
| FlowMQ over CoroNet `Pipe` | 无 TCP 端口、跨平台本地 IPC | Pipe 本身没有身份/加密规则，HELLO credential 未加密 | 仅显式 trusted-local profile |
| 直接共享内存或私有 socket codec | 依赖少 | 重复实现 framing、连接、backpressure、认证与生命周期 | 不采用 |

## 总体架构与所有权

```text
Controller desired state
        │ signed MMP intent
        ▼
mesh-agent domain owner ── durable WAL/checkpoint
        │ provider try_start (non-blocking)
        ▼
FlowMQ provider adapter
  owned outbound queue ──> IPC worker ── DEALER/mTLS ──> ROUTER callback
        ▲                                      │             │ copy only
        │ retained completion                  │             ▼
  owned inbound queue <── IPC worker <─────────┘       meshd command queue
                                                           │ bounded drain
                                                           ▼
                                                     meshd/Mesh owner
                                                           │
                                                   immutable applied snapshot
```

单一事实源：

| 状态 | owner / 事实源 | 可丢弃或重建的派生状态 |
|------|---------------|------------------------|
| 全局 desired resource/epoch | Controller transaction store | UI/index/outbox view |
| 节点已 durable accept 的 desired/operation | agent WAL + checkpoint | provider queue、reconciler view |
| Mesh 当前执行状态 | `meshd` owner 的 immutable applied snapshot | metrics、IPC status snapshot |
| IPC connection/session | FlowMQ adapter | route、socket、heartbeat observation |
| 后续 derived observation | `meshd` applied snapshot | agent observed cache |
| 后续 telemetry batch | `meshd` counters/window snapshot | transport queue、agent metrics cache |
| 后续 transfer/Native claim | agent WAL/对应 worker durable journal | transport route/credit observation |
| 未 ACK terminal result | `meshd` result retention；agent 收到后先写 result WAL | outbound frame |
| `meshd` 进程状态 | OS service manager | agent observation |

`目标`：V1 只允许 declarative、可重复 reconcile 的 `meshd` command。`meshd` 重启后，agent 根据
自身 durable desired state 以**相同 operation ID**重发；`meshd` 重新应用完整 snapshot 或验证已经
满足，不需要让两个进程分别维护可写 desired truth。非幂等 diagnostics/action 若不能查询结果或安全
重放，必须拒绝进入这个无 journal profile；以后启用此类 command 前，应增加独立 durable action
journal 和恢复协议。

## FlowMQ 功能拓扑

P1 只依赖独立 FlowMQ 当前公开的 ROUTER/DEALER endpoint：

```text
mesh-agent DEALER(connect) <====== TLS/mTLS ======> ROUTER(bind, max=1) meshd
             │ MeshNodeIPC/1 COMMAND/ACK              │ borrowed callback
             │                                        ▼
       bounded owned queue                      bounded owned queue
             ▲                                        │
             └──── ACCEPTED/RESULT/STATUS/DRAIN ──────┘
```

低频、分页且有界的 QUERY/STATUS 可以复用此通道。高频 observation、telemetry、release worker 和 Native
worker 必须使用独立容量与安全域；但它们是后续 capability，只有独立 FlowMQ package 提供并验证所需
pattern/credit/recovery API 后才落地。本文不再把旧 TurboFlow facade 的 PUB/SUB state、TFPS 或 credit
worker 当作当前 FlowMQ 能力。

不采用以下映射：

- 不让 local `meshctl` 直接加入 ROUTER。CLI 仍通过 Controller/agent API，避免第二个 authority 绕过
  agent WAL、grant 和审计。
- 不用 transport delivery 代替 operation result，不把唯一 audit、chunk/media bytes 或 packet payload
  放入本地 control channel。
- 不在 P1 为每种资源创造新 wire pattern；resource/action 是 `MeshNodeIPC/1` typed body，不是 topic 字符串。

## FlowMQ production endpoint profile

V1 固定 profile：

| 项目 | `meshd` | `mesh-agent` |
|------|---------|--------------|
| pattern | `ROUTER` | `DEALER` |
| mode | bind | connect |
| transport | CoroNet `TLS` | CoroNet `TLS` |
| network bind | `127.0.0.1:<configured-port>` only | connect loopback only |
| TLS | require client certificate | verify peer；client certificate required |
| FlowMQ protocol | installed standalone package version | 与 BIND 端兼容 |
| identity | `meshd:<managed-node-id>` | `mesh-agent:<managed-node-id>` |
| identity check | exact expected HELLO identity + client leaf fingerprint map | exact expected HELLO identity + server leaf fingerprint map |
| remaining gate | 生产证书签发/存储/重载/吊销、存量 session fencing、审计 | 同左；typed authorization 仍不能被 transport binding 替代 |
| frame admission | `FAIL` | `FAIL` |
| max Mesh payload | `MESH_NODE_IPC_MAX_FRAME_SIZE_V1`，64 KiB | 同左 |
| FlowMQ max body | Mesh payload + 最大 identity 开销 | 同左 |

production endpoint 使用独立的 `tls://127.0.0.1:<configured-port>`，端口由 validated deployment config
分配，不硬编码、不复用、不通过扫描发现：

```text
control:         tls://127.0.0.1:<control-port>
```

不得 bind `0.0.0.0`、`::` 或非 loopback 地址。需要 IPv6 时使用显式 `[::1]` listener，并单独完成
证书、hostname 和跨平台测试。CONNECT 使用的 `server_name` 必须匹配证书 SAN，不能因为 socket 连接
目标是 loopback 就关闭 peer verification。endpoint 分别配置 certificate/key/CA reference、exact
expected identity、frame limit、heartbeat、reconnect 和 finite deadline；知道端口不授予连接权限。

证书 material 来自 OS credential store 或权限受控文件 reference，不进入普通 TOML value、CLI、payload
或日志。BIND 端必须设置 `require_client_certificate=1`，CONNECT 端必须设置 `verify_peer=1`。每个节点
在当前限制下使用专用 channel CA/certificate；共享 CA 的多租户部署要等生产证书生命周期、存量
session fencing 和审计门槛完成。轮换采用 current/next trust overlap 和单调 rotation generation，失败时保持旧安全 channel 或
停止新管理操作，禁止降级到 Pipe/plain TCP。

### 可选 trusted-local Pipe profile

`Pipe` 不是 production 默认，也不是 mTLS 的别名。只有部署方已经在 FlowMQ 之外提供并验证 OS 对象
ACL、peer credential 或等价的容器/namespace 隔离时，才可另行设计 `trusted_local_pipe`。当前 adapter
在 profile validation 中拒绝 Pipe；没有可启用的 Pipe fallback。

该可选 profile 使用 CoroNet canonical `pipe://` URI；Windows `pipe://name` 映射 named pipe，Unix
必须使用 owner-only runtime directory 下的 `pipe:///absolute/path`，不能使用默认 `/tmp` 映射。不存在
TLS 失败后自动回退到 Pipe 的路径。

`事实`：CoroNet 在 Windows 上将 `pipe://name` 归一化为 Windows named pipe；Unix 上
`pipe://name` 默认映射为 `/tmp/name.sock`，而 `pipe:///absolute/path` 保留绝对 UDS path。
`ipc://` 只存在于 Unix normalization 分支，不能用于这一跨平台产品契约。production profile 不使用
Pipe；可选 Pipe Unix profile 必须使用受 service manager 管理、owner-only 的绝对 runtime directory，
不使用默认 `/tmp` 映射。
endpoint 的 scheme、managed node ID、平台 path 长度、owner 和类型在创建或 unlink 前必须完整校验。

所有容量和时间必须由 validated config 提供，不能依赖 FlowMQ 的通用大 frame 默认值。至少包括：

- outbound/inbound queue item capacity 与 retained byte capacity；
- FlowMQ frame HWM messages/bytes；
- connect/send/receive timeout、heartbeat interval/timeout、reconnect initial/max；
- stop linger 和每轮 owner drain budget。

控制命令禁止 `DROP_OLDEST`，也不在 CoroNet/owner loop 中使用无限 `BLOCK`。容量满时保留原 desired
operation，返回/记录 `RESOURCE_EXHAUSTED`，释放容量后以同 operation ID 重试。

### 后续 observation、telemetry 与 worker channel

这些流量不得挤占 P1 command/result 的容量，也不能把旧 TurboFlow facade API 当成独立 FlowMQ 的契约。
后续每类 channel 必须先针对当时的 `FlowMQ::FlowMQ` public API 单独设计并完成互操作测试：

- derived observation：last-value snapshot、单调 cursor、gap 检测、bounded resync；它不是 desired 或 audit
  事实源，失败不能反向阻塞 packet owner；
- telemetry：只允许可采样的有界 batch，明确 coalesce/drop/gap，不承载 terminal result 或唯一审计；
- release/Native worker：只传 operation/artifact reference，不传文件块；必须先 durable claim，再 dispatch，
  completion 先持久化后 ACK，禁止自动降级为 at-most-once。

在这些语义有独立实现、硬容量、shutdown protocol 和故障注入前，相应 capability 返回
`RUNTIME_UNAVAILABLE`。

## MeshNodeIPC/1 canonical envelope

FlowMQ 只把以下 bytes 视为 opaque payload。V1 envelope 是固定 128-byte 大端 header，随后是
`body_size` bytes：

| offset | size | field | 约束 |
|--------|------|-------|------|
| 0 | 4 | magic | ASCII `MNIP` |
| 4 | 2 | major | `1` |
| 6 | 2 | minor | 协商后的 additive minor |
| 8 | 2 | kind | stable enum，见下表 |
| 10 | 2 | flags | 未识别位必须拒绝 |
| 12 | 2 | header_size | V1 固定 `128` |
| 14 | 2 | reserved | 必须为零 |
| 16 | 4 | body_size | `header + body <= 64 KiB` |
| 20 | 4 | reserved | 必须为零 |
| 24 | 16 | request_id | 调用幂等 ID；kind 要求时不得全零 |
| 40 | 16 | operation_id | 领域 operation ID；kind 要求时不得全零 |
| 56 | 16 | sender_incarnation | 每次进程启动由 checked CSPRNG 生成 |
| 72 | 8 | sequence | 当前 incarnation 内严格递增，溢出前重启 session |
| 80 | 8 | desired_epoch | command/status 的 fencing epoch |
| 88 | 32 | message_digest | SHA-256(header 中该字段清零后的 128 bytes + canonical body) |
| 120 | 8 | reserved | 必须为零 |

禁止直接发送 C struct；codec 必须逐字段编码，检查整数溢出、exact size、reserved zero、digest、kind
所需字段和 UTF-8/enum/array 上限。minor 只能增加接收端可安全忽略的字段；破坏性语义使用新 major。

Message kind：

| kind | 方向 | 语义 |
|------|------|------|
| `HELLO` / `HELLO_ACK` | 双向 | 协商 schema、capability、frame/queue limit、managed node ID、当前 applied epoch 与 incarnation |
| `COMMAND` | agent -> meshd | 类型化 APPLY/DELETE/START/STOP/RECONCILE；包含 resource kind/id、precondition、provider ID 与 canonical document |
| `ACCEPTED` | meshd -> agent | 已通过 schema/权限/fencing，并进入 `meshd` owned command queue；仅 volatile accept |
| `RESULT` | meshd -> agent | terminal success/failure、applied epoch、observed digest、stable error 与失败 stage |
| `QUERY` / `STATUS` | 双向 | 按 operation/resource 查询，或返回有界 generation-consistent snapshot page |
| `ACK_RESULT` | agent -> meshd | agent 已 durable 记录 terminal result，可释放精确 result |
| `CANCEL` | agent -> meshd | 请求取消尚未开始或可取消操作；不是强制 kill |
| `DRAIN` / `DRAINED` | 双向 | 协商关闭，禁止新 command 并收敛在途结果 |

`COMMAND` body 只接受预注册的 typed resource schema。network builtin 首批 action 是完整 policy/network
snapshot 的 `APPLY` 与带 epoch 的 `DELETE`；route/service 的局部修改也必须生成新的 immutable snapshot，
不能从 IPC callback 直接逐字段改 packet-path map。

V1 `COMMAND` body 使用固定 156-byte 大端 header，随后是 `document_size` bytes：

| offset | size | field | 约束 |
|--------|------|-------|------|
| 0 | 4 | magic | ASCII `MNCM` |
| 4 | 2 | schema | `1` |
| 6 | 2 | action | APPLY/DELETE |
| 8 | 2 | resource kind | stable typed enum |
| 10 | 2 | reserved | 必须为零 |
| 12 | 8 | precondition epoch | 已知前态；不满足则 fenced |
| 20 | 32 | mesh ID | 不得全零；必须匹配本机 owner scope |
| 52 | 32 | resource ID | Network 为 `SHA-256("mesh-network/v1" || mesh_id || network_uid)` |
| 84 | 32 | provider ID | 必须精确匹配本机预注册 provider |
| 116 | 32 | document digest | APPLY 为 canonical document SHA-256；DELETE 全零 |
| 148 | 4 | document size | envelope + command + document 不超过 64 KiB |
| 152 | 4 | reserved | 必须为零 |

一个 Mesh 下的“子网络”在领域模型中称为逻辑 `Network`：共享 Mesh 身份根、Controller authority 和
Noise/P2P underlay，但独立拥有 membership、地址池、route、DNS、policy 与 lifecycle。外部 LAN CIDR
则是某个 Network 的 `ExternalRoute`，不自动创建 Network。命令必须绑定 `mesh_id + resource_id +
desired_epoch`；只传名称、CIDR 或 `network_uid` 都不足以授权执行。

## 事务与状态迁移

```text
agent WAL 已 durable accept desired operation
-> provider try_start 将 canonical COMMAND 复制到 bounded outbound queue
-> IPC worker 通过 FlowMQ DEALER/ROUTER 发送
-> meshd callback 验证 envelope/auth/digest 并复制到 bounded command queue
-> meshd owner 校验 operation ID、epoch/precondition、local policy 和 capability
-> meshd 返回 ACCEPTED（已经 owner admission，但不是 durable execution）
-> 构建/验证新 immutable snapshot
-> 原子替换 applied snapshot，或保持旧 snapshot 并生成失败结果
-> meshd 保留 RESULT 并发给 agent
-> agent provider 暴露 retained completion
-> agent 写入并 fsync result WAL，owner 提交 observed state
-> agent 发送 ACK_RESULT
-> meshd 释放精确 retained result
```

约束：

- FlowMQ send 成功只记为 `TRANSPORT_DELIVERED`，不能转换成 `ACCEPTED`、`APPLIED` 或 durable receipt。
- 相同 operation ID + 相同 resource/action/epoch/digest 是幂等重放；返回 cached/current result。
- 相同 operation ID 携带不同 digest 或 target 是 `CONFLICT` 并记录 security event。
- 较低 desired epoch 是 `FENCED`；同 epoch 不同 digest 是 `CONFLICT`；不得 last-writer-wins。
- 连接断开且提交点未知时，agent 用同 operation ID `QUERY`/重发，不创建新 operation ID。
- `meshd` incarnation 改变意味着其 volatile accept/result cache 已丢失；agent 重新发送全部未完成操作并
  reconcile 当前 desired snapshot。

## 线程、内存与背压

P1 control 只有一个 serialized adapter owner lane。后续 observation/worker channel 必须拥有独立 owner
和容量。agent reconciler owner、FlowMQ owner、`meshd` callback 和 `meshd` Mesh owner 之间只传 ownership-transfer
message。只在 producer/consumer cardinality 被固定为一对一时使用 TurboUtils SPSC ring；若以后增加
worker/lane，必须改用明确 MPSC adapter，不能继续假装 SPSC 安全。

| bridge | producer | consumer | V1 topology |
|--------|----------|----------|-------------|
| agent command outbound | agent reconciler owner | control IPC worker | SPSC |
| agent result inbound | control IPC worker | agent reconciler owner | SPSC |
| meshd command inbound | FlowMQ control owner | `meshd` Mesh owner | SPSC |
| 后续 observation/worker | 未定 | 未定 | 必须独立设计 producer/consumer cardinality |

发送采用 adapter-owned bounded queue + FlowMQ capacity=1 copied-send admission。reconciler `try_start`
只做 canonical encode/copy/admission，绝不等待 TLS/FlowMQ delivery。
FlowMQ receive callback 只做 bounded validation/copy/enqueue，borrowed buffer 不得跨 callback 保存；
`meshd` 主循环按固定 budget drain command，并在调用 `mesh_poll()` 的同一 owner 上修改 Mesh 状态。

容量计算必须在启动时 checked multiply/add 并 fail fast：

```text
queue_retained_bytes <= entry_capacity * (128 + max_body + entry_metadata)
process_ipc_budget >= control queues + retained results + one in-flight send
                    + FlowMQ endpoint/session buffers
global_control_budget >= agent_control_budget + meshd_ipc_budget + provider budgets
```

每个 queue 同时限制 entries 和 bytes。超限不分配、不丢旧 command、不推进 operation state；错误映射：

| 本地结果 | Mesh control 结果 |
|----------|-------------------|
| queue/HWM full、`TURBO_ENOSPC` | `RESOURCE_EXHAUSTED` |
| 未连接、重连中 | `PROVIDER_UNAVAILABLE`，保留 operation 并重试 |
| timeout/断线且结果未知 | `UNKNOWN_COMMIT`，按 operation ID 查询 |
| schema/size/digest 错误 | `INVALID_DOCUMENT` |
| TLS/identity/local policy 拒绝 | `PERMISSION_DENIED` |
| stale epoch/incarnation | `FENCED` / `EPOCH_CONFLICT` |

各 channel 的满载行为固定如下：

| channel | full/slow 行为 | 事实源状态 |
|---------|----------------|------------|
| ROUTER/DEALER command/result | reject admission；保留相同 operation/result 等待 retry/ACK | 不推进或不释放 |
| copied-send timeout | 保留 queue head 与 in-flight completion，等待 callback 收敛 | 不重复发送未知 request |
| route generation 失效 | 返回 unavailable 并保留 queue head | 不使用旧 session route |

### Observability

每个 endpoint 至少暴露 current/peak queue items/bytes、HWM hit、reject、connect/reconnect、heartbeat
timeout、auth deny、callback error、route generation、in-flight send 和 shutdown remainder。control 另报
operation stage/latency、duplicate、fenced、unknown commit 和 unacked results。后续 channel 必须使用自己
的固定-label metrics，不能借用 P1 counters 掩盖语义差异。

metrics 只使用固定 label（channel、kind、stable error），不使用 node/resource/operation ID 作为无界 label。
日志仅在错误被消费或转换的边界记录 correlation ID 和摘要，不记录 payload、credential、artifact input、
文件内容或 session key。

## 安全模型

FlowMQ over mTLS 用于认证“连接者持有本 channel 信任的证书并声明预期 identity”，不传递或替代远程
Controller grant。agent 先验证 Controller signature/grant，再下发已经收窄的 effective command；
`meshd` 仍独立检查 managed node binding、resource/action allowlist、epoch、provider capability 和本机
immutable policy。任何一层都不能扩大上一层权限。

消息 pattern 与安全 profile 正交，loopback 也不是 identity。production 必须同时满足：

- endpoint 只监听显式 loopback；配置出现 wildcard/non-loopback address 时 fail fast；
- server certificate verification 和 mandatory client certificate；CA、SAN、有效期和 key usage
  任一失败都拒绝连接；
- BIND 与 CONNECT 都只接受 exact expected HELLO identity 和 current/next certificate exact mapping；typed command
  仍需通过 Mesh grant/local policy/resource scope 授权；
- 当前实现已在 HELLO admission 期双向拒绝证书/identity tuple mismatch；专用 channel CA 继续作为
  defense in depth，而不是替代 mapping；
- private key 来自 secure reference，不进入 CLI、payload、日志、metrics 或 crash report；
- certificate/current-next trust 轮换、吊销和 rotation generation 可审计；旧 certificate 退出 overlap
  后立即拒绝，失败不得自动切到 Pipe、TCP、WS 或关闭 peer verification；
- TLS、identity、digest、epoch 或 operation collision 失败均 fail closed，并产生有界 security
  audit event。

`trusted_local_pipe` 的 OS ACL/peer credential 属于显式替代 threat model，只能按前述可选 profile 启用；
当前 adapter 不实现该 profile。

## Shutdown 与恢复

agent adapter：

```text
stop provider admission
-> wake/cancel blocked producers
-> drain or reject queued-unstarted COMMAND with explicit state
-> finish current FlowMQ send within bounded deadline
-> receive and persist ready RESULT
-> exact ACK_RESULT for persisted results
-> send DRAIN and wait bounded DRAINED
-> stop FlowMQ app after callbacks quiesce
-> join IPC worker
-> release owned frames/queues/security providers
```

`meshd` adapter：

```text
stop accepting new COMMAND
-> return RESOURCE_EXHAUSTED/SHUTTING_DOWN for new admission
-> drain or cancel queued-unstarted commands by contract
-> finish atomic snapshot apply already in commit phase
-> retain/send terminal RESULT
-> drain active reads/status callbacks
-> send DRAINED
-> stop listener after callbacks quiesce
-> join worker and release queues
-> destroy Mesh owner/state
```

FlowMQ callback 不得调用同一 app 的 stop/destroy。超时关闭必须报告剩余 operation ID；不得通过释放
borrowed/owned payload 来伪装 drain 完成。agent/IPC failure 不销毁最后一个有效 Mesh policy snapshot。

## 模块和依赖边界

当前可选内部 target：

```text
Mesh control core headers
        ▲ provider ops only
mesh_node_ipc_flowmq
        │ public package boundary
        ▼
FlowMQ::FlowMQ
```

- transport-neutral `mesh_node_ipc*` core public header 不包含 FlowMQ header，不暴露其 error/type/lifetime。
- 只有 `mesh_node_ipc_flowmq.h` adapter boundary include standalone `flowmq.h`；业务 owner 依赖 typed IPC API。
- adapter 不 include CoroNet header、不调用 `coro_post()`，也不单独链接 `TurboNet::CoroNet`；FlowMQ 自行
  封装 transport owner、copied-send admission 与 callback quiescence。
- `mesh_node_control_client_runtime` 是 agent CONNECT 侧；`mesh_node_control_runtime` 是 `meshd` ROUTER
  侧；`mesh_node_control_flowmq_provider` 将前者适配为现有 reconciler provider contract。
- `mesh_node_network_control_service` 在 `meshd` owner 上组合 borrowed `mesh_fabric_t`、owned bounded
  Network reconciler、typed executor 和 server runtime。销毁顺序固定为停止命令准入、等待 exact ACK、
  停止 transport、detach 所有 owned Network，再由上层停止/destroy fabric；运行或 drain 中直接 destroy
  返回 `INVALID_STATE`，不得静默丢弃未 ACK RESULT。
- 下游只 `find_package(FlowMQ CONFIG REQUIRED)` 并链接 `FlowMQ::FlowMQ`。不得恢复 TurboFlow facade、
  compatibility target alias 或直接链接 FlowMQ 内部 protocol target。
- 当前 `mesh_control_provider_completion_v1_t` 只能表达 operation ID 与成功/失败，result WAL v1 也只能
  保存 outcome。生产 `RESULT` 所需的 stable error、failure stage、applied epoch、observed/result digest
  和 `meshd` incarnation 必须通过 additive `provider completion/result WAL v2` 接入；不能扩写 V1 struct
  或悄悄丢弃失败上下文。迁移期 V1 adapter 只映射 terminal outcome，产品 API 不得据此宣称完整诊断。
- build feature `TURBOP2P_ENABLE_FLOWMQ_IPC` 默认关闭；dependency、独立证书 lifecycle、撤销审计和
  实际 service 测试门槛全部满足后才允许 production profile 开启。
- 配置增加 loopback endpoint、certificate/key/CA references、rotation generation、exact identities、
  secret references、capacity/time budgets；不改变现有 `mesh_config_t` compat 行为和 Mesh wire capability。

## 验证门槛

### Codec 与状态机

- golden vectors 覆盖每个 kind、大小端、reserved bits、minor compatibility 和 body digest。
- fuzz arbitrary bytes、截断、超长、整数溢出、重复 field、错误 digest 和 unknown kind/flag。
- 相同 operation ID 同内容幂等；不同内容 collision 拒绝；epoch fencing 与 incarnation restart。
- APPLY/DELETE、旧 snapshot 保留、result WAL-before-ACK 和 ACK 丢失重传。

### FlowMQ/资源边界

- 真实 ROUTER/DEALER mTLS agent↔`meshd` integration，不以 mock transport 替代发布测试。
- 已有独立父/子进程角色完成 bounded typed command echo；实际 agent/`meshd` binary 与 service manager
  crash/restart 仍需另测。
- queue entries、bytes、FlowMQ frame HWM 任一先满时稳定背压，内存不超过计算上限。
- callback 返回后立即污染原 receive buffer，验证无 borrowed view 泄漏。
- 断开、重连、半帧、duplicate、heartbeat timeout、`meshd`/agent 各阶段 crash/restart。
- route token generation 在 disconnect/reconnect 后 fencing；旧 route 不能发送到新 session。
- send timeout、late callback、queue head retry 和 shutdown 交错时无 duplicate consume/UAF。
- client/result retention 覆盖 ACCEPTED/RESULT、operation collision、ACK queue full 和 exact ACK；真实 mTLS
  覆盖 client/server runtime、断线后的 route generation fencing，以及现有 reconciler 驱动 prestaged
  Native provider 的 submit/result/ACK/drain；Network 组合测试还必须覆盖 APPLY、fabric attach、未 ACK
  stop 拒绝、同 Mesh 多 Network 隔离、独立 DELETE、exact ACK、drain、detach 和 destroy fencing。
- shutdown 覆盖 active callback、blocked send、queue full、unacked result 和 deadline expiry；ASan/TSan
  无 UAF、double-free、race 或 retained payload 泄漏。

### 安全与平台

- Windows/Linux 上 listener 只绑定 `127.0.0.1`；wildcard/non-loopback、错误/缺失 CA、certificate、key、
  SAN、过期证书和 `verify_peer=0` 全部启动或握手失败。
- 无 client certificate、错误 client CA、错误 HELLO/DATA identity 均拒绝；双向 verifier 已覆盖双方
  unmapped certificate 拒绝和 current/next overlap。显式 client TLS config 禁用 session cache；仍需独立
  双 leaf/EKU、跨 role/node 冒充与存量 session 撤销测试。
- ROUTER/DEALER mTLS endpoint 的任一安全失败都不能触发 Pipe/plain TCP/WS fallback。
- 可选 `trusted_local_pipe` 单独覆盖 Windows DACL/service SID 或 Unix owner/mode/peer credential；未提供
  外部安全 owner 时 profile 必须不可启用。
- node binding mismatch、replay/collision 均拒绝并审计。
- canary secret 检查所有日志、event、metrics、status 和 crash diagnostics。

### 性能

正确性门槛通过后，分别测 command size/queue depth 下的 enqueue、delivery、apply、result P50/P95/P99，
以及对 `mesh_poll()`、packet throughput 和 tail latency 的影响。未测前不宣称 FlowMQ IPC 对数据面“零
影响”，也不以吞吐 benchmark 替代故障与一致性测试。

## 迁移与回滚

1. 先落地 codec、memory-only adapter 和 mock owner，不接真实 Mesh mutation。
2. 已接独立 `FlowMQ::FlowMQ` ROUTER/DEALER mTLS、bounded queues、client/server runtime、可注入
   reconciler 的 prestaged function provider，以及 Network APPLY/DELETE 的内部 `meshd` 组合服务；
   CONNECT 对称 identity hook、Mesh 双向强制 profile、current/next overlap、listener restart 重连和
   adapter 进程边界往返也已完成。
3. 远程 agent service、独立 server/client leaf 校验、client rotation/revocation 和 Controller session
   fencing 已有组合实现；下一步把 FlowMQ provider 注入发布进程，补齐本地 listener/client 自动换证、
   审计和 service-manager crash/restart，再开放 HELLO/QUERY/STATUS 与 canary typed mutation。
4. 以上门槛通过后，canary 开放 declarative network
   snapshot APPLY/DELETE。
5. observation、telemetry、release/Native worker 按独立 FlowMQ 当时公开能力重新设计；side effect 必须先
   接 durable claim，不能复用 P1 control queue 逃避可靠性边界。
6. Native/TurboWASM worker 已有独立进程边界和 exact-digest catalog，但仍默认关闭；它们使用独立
   OS sandbox profile，不复用本地 FlowMQ control channel 的传输身份作为执行授权。
7. 故障注入和跨平台门槛通过后，production profile 才可启用；`trusted_local_pipe` 作为独立非默认
   profile 验证，不进入 TLS fallback 链。

回滚只关闭 `TURBOP2P_ENABLE_FLOWMQ_IPC` 和 agent provider assignment；`meshd` 保留最后一个已验证
applied snapshot，OS service manager 恢复原 compat 配置。禁止在 IPC failure 时自动切换到未认证
transport，也禁止清空 policy 作为“恢复”。

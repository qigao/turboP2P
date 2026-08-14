# Mesh 产品控制面、身份与 Grants 设计

## 文档状态

本文同时记录目标产品层和已经落地的内部控制原语；每一处用 `事实`、`边界` 或 `目标`
区分成熟度，不能把组件测试通过等同于产品闭环。当前实现状态仍以
[`MESH_STATUS.md`](MESH_STATUS.md) 为准；网络平台边界见
[`MESH_PLATFORM_DESIGN.md`](MESH_PLATFORM_DESIGN.md)；节点间管理协议见
[`MESH_MANAGEMENT_PROTOCOL.md`](MESH_MANAGEMENT_PROTOCOL.md)；`meshctl` 的命令树、领域原语、
selector DSL、H2/SSE client 与删除语义见
[`MESHCTL_PRIMITIVES_DESIGN.md`](MESHCTL_PRIMITIVES_DESIGN.md)。

`事实（2026-08-13）`：本轮没有修改 `mesh_config_t` 或 packet wire format；MMP/1 增加了内部
实验性的 `CONTROL_FRAME (0x60)` kind 及 canonical control payload。该 kind 尚未形成公开、
稳定或跨版本协商的产品协议，在加入 capability negotiation 和 golden vectors 之前不能由
第三方依赖。

受控节点 Wasm 执行是独立的可选产品扩展，见
[`MESH_NODE_EXECUTION_DESIGN.md`](MESH_NODE_EXECUTION_DESIGN.md)。它不把通用
`EXEC`/`SHELL` 加入 MMP，也不允许 execution policy 与 network/object policy 混用。

### 2026-08-14 已实现切片

`事实`：仓库现有内部组件已经实现以下可独立验证的基础设施：

- transport-neutral 的 node/network/function/service/route/release 资源、intent、observation、
  operation、event 和 receipt 原语；
- Iris `/v1/control` WebSocket 路由，同时覆盖 HTTP/1.1 RFC 6455 和 HTTP/2 RFC 8441；入口强制
  mTLS transport authorization、MMP 签名消息校验和固定大小二进制 frame；
- 有界 SPSC ownership-transfer channel；网络回调只复制并发布不可变消息，不修改领域状态；
- 单 owner 的 desired/observed 状态、删除 tombstone、operation journal、幂等 request ID、
  optimistic epoch、generation 一致的有界分页 snapshot，以及支持断线续取的有界 event cursor；
- 固定 232-byte function document、runtime-specific admission，以及由 state 有界持有的 reconciliation
  document；DELETE tombstone 保留上一次 APPLY 的 provider 绑定，不依赖远程重新发送宿主信息；
- 有界、非阻塞的 function reconciler strategy/registry：只接受精确预注册的 builtin/Native provider ID，
  串行化同一 function 的 operation，传播 provider backpressure，并将 completion 收敛为 observed state；
- mTLS + `OBSERVE` 鉴权的普通 H1/H2 `GET /v1/control/status`、`/v1/control/events` 和
  `/v1/control/receipts?operation_id=...`；前两者分别按 generation/cursor 分页，receipt 是固定
  128-byte canonical durable view；H1 与强制禁用 fallback 的真实 H2 mTLS client 均已覆盖；
- state、operation、event 与 replay window 的统一 versioned checkpoint；编码采用固定大端格式、
  SHA-256 完整性校验并绑定 mesh/node/controller principal/session，恢复失败不修改现有 owner；
- HMAC chain 的 signed-intent/result WAL：持久化原始签名 frame、provider completion result 和本机
  身份/session binding；owner 只在 WAL fsync 后提交 desired/replay/operation；
- 单槽持久化 worker 与 authenticated checkpoint store：checkpoint 带本机认证密钥的 HMAC 尾标签，
  先执行 temp -> `fsync(file)` -> close -> atomic rename，再以 checkpoint index/HMAC anchor 原子
  compact WAL；worker 在接管 snapshot 内存前核对 V2 checkpoint 摘要、结构和内嵌 committed index，
  防止误传索引删除仍需重放的记录；启动先恢复 checkpoint，再验证并重放 WAL suffix；
- provider completion 使用 retained peek/apply/exact-ACK；关闭时 ready completion 必须先写 result
  WAL 并推进 owner index，不能被 provider `close` 丢弃；
- Network executor 可直接注入 caller-owned fabric，也可使用 transport-neutral async provider；
  Network intent 的 resource/Mesh/node/generation 在 admission 校验。跨进程路径先由本地 `meshd`
  返回 retained RESULT，agent 再落 result WAL、推进 observed 并 exact ACK；启动恢复使用由
  resource/generation 确定派生的 operation ID 重放同摘要文档。所有扫描受 owner
  resource/operation capacity 硬上限约束；
- 独立 agent core 的 TLS listener、CoroNet poll、队列 drain 和可配置超时的 shutdown 生命周期；
- `mesh_control_agent_runtime` 已组合 durable WAL agent、H2-only mTLS outbound client、typed
  HELLO/CLAIM/COMMAND/RECEIPT state machine 与 client leaf lifecycle；command 只有在节点 durable
  receipt 可查询后才向 Controller ACK；
- Controller 使用 authenticated bounded durable outbox worker；在线 session 同时绑定 node、随机
  session ID、durable generation、实际 TLS leaf digest 和 identity-policy generation，重连、换证或
  policy reload 会 fence 旧 session；
- 有界 Controller identity registry 将 node ID、management public key 与 client-certificate
  current/next lifecycle 精确绑定；Controller 只加载 agent 公有证书，不持有 agent 私钥。X.509
  chain、EKU、serial、有效期、吊销和单调 generation 均 fail closed；本机 TLS leaves 另外验证
  key match，并可强制 owner/ACL 安全检查；
- builtin/native/WASM 三类 runtime 的独立权限位与 availability 位。默认仅 builtin 可用；
  Native/WASM 都需要本机显式同时开启权限、runtime availability、精确 provider ID 和 prestaged
  digest binding；WASM 还在认证子进程中运行 TurboWASM。

`事实`：`meshd` 本地边界已有 transport-neutral `MeshNodeIPC/1` canonical codec、显式 Mesh/provider
scope、bounded copied-frame channel、single-owner operation/result retention 和 Network APPLY/DELETE
executor；独立 `FlowMQ::FlowMQ` ROUTER/DEALER mTLS adapter、client/server runtime，以及可直接注入
现有 reconciler 的 prestaged builtin/Native provider 已完成同进程真实 mTLS 组件测试。内部
`mesh_node_network_control_service` 还组合 borrowed fabric、owned Network reconciler/executor/server
runtime，并通过同 Mesh 双 Network APPLY、独立 DELETE、fabric attach/detach、RESULT/exact ACK 与
shutdown drain 的真实 mTLS 测试。`mesh-agent` 现在通过独立 client certificate、exact HELLO identity、
current/next meshd leaf pin 和有界 async Network provider 接入该服务；seam tests 覆盖
WAL-before-ACK、agent restart restore，以及真实 FlowMQ APPLY/DELETE/exact-digest idempotent restore。

`边界`：这还不是完整产品控制面。`meshd` 已有默认关闭的 FlowMQ/mTLS 配置和唯一 fabric
underlay owner 接线；`mesh-agent` 与 `mesh-controller` 已组合成可构建二进制，前者可选择接入
本地 FlowMQ/mTLS Network owner，后者提供 pinned-mTLS、
signed-MMP 校验、durable-outbox-commit 后返回的 H2 提交入口。当前仍没有 Product Controller 数据库、
用户/审批 API、service-manager 安装单元、完整 observation/audit 泵或公开协议协商。当前
Network executor 是嵌入式 userspace fabric 边界，不包含 OS TUN/route/DNS transaction。receipt 是经
mTLS 查询、由本地 WAL/checkpoint 事实源派生的可恢复 view，不是可转发的节点签名审计凭证；operation
超过配置的 terminal retention 后需要依赖外部 Controller/audit store 长期保存。现有 agent core 只接受
一个固定 Controller identity/session。FlowMQ provider 已完成真实 typed transport 闭环；execution
plane 另有 digest 绑定的 Native process 和 TurboWASM child worker、父进程 durable result commit、
超时和 process-tree cleanup。production 强制配置并精确校验 OS sandbox launcher；launcher 参数按
有界 argv 传递且被 process owner 深拷贝，直接 spawn 只允许测试。Controller Grant authoring、
service-manager sandbox profile、跨平台 production isolation 和审计
仍未闭环，因此不能把第三方执行作为成熟多租户能力销售。

## 产品定义

目标产品是身份驱动、策略控制、可审计的 Mesh overlay：

- Controller 提供用户、设备、策略、审批、API、CLI 和审计查询。
- `mesh-agent` 负责节点注册、证书、MMP、期望状态和 `meshd` supervisor。
- `meshd`/Mesh core 负责 TUN、path、route、packet policy 和本地执行。
- 数据流不经过 Controller；Controller 故障不能成为已建立数据流的转发依赖。
- Gossip 用于成员和已签名状态的最终收敛，不承担用户认证或 consensus。

这属于 SDN-like control/data plane 分离，但不是 OpenFlow 式中央逐流编程。Controller
发布身份和网络意图，各节点在本地编译快照约束下选择路径并执行策略。

## 方案定稿：统一节点控制面

`目标`：V1 采用“Controller 事实源 + agent 主动长连接 + 节点本地执行”的统一控制面。
H2/WS 只承担接口和会话，不定义业务状态；builtin、Native 和未来 WASM 只通过同一个
versioned provider contract 接入，不直接处理 HTTP/WebSocket message。

```text
operator / CI / meshctl
          │ H2 resource API
          ▼
┌──────────────────── Product Controller ────────────────────┐
│ identity/grants │ desired state │ operation/audit │ outbox │
└──────────────────────────┬──────────────────────────────────┘
                           │ agent 主动发起 mTLS H2
                           │ typed POST /v1/agent/sync
                           ▼
┌──────────────────────── mesh-agent ─────────────────────────┐
│ transport adapter -> admission -> WAL -> single owner      │
│                              │                              │
│                    bounded reconciler                      │
│              ┌───────────────┼───────────────┐              │
│              ▼               ▼               ▼              │
│        builtin provider  Native worker   TurboWASM worker   │
│              │          (explicit opt-in; both sandboxed)   │
└──────────────┼───────────────┼───────────────────────────────┘
               │ MeshNodeIPC/1 over FlowMQ secure patterns/mTLS loopback
               ▼
             meshd ───────── encrypted Mesh data plane
```

这一方案固定四个契约：

1. **产品资源契约**：Controller 持有 user、device、network、route、service、release、function、
   grant 和全局 desired state；mutation 是带 request ID、base epoch 和 actor 的事务。
2. **南向同步契约**：agent 主动连接 Controller，使用 canonical MMP envelope 同步 `INTENT`、
   `OBSERVATION`、`OPERATION`、`EVENT` 和 `RECEIPT`；网络重传是 at-least-once，业务效果依靠
   request/operation ID 和 provider journal 幂等，不能宣称 wire exactly-once。
3. **节点提交契约**：只有 signed intent 已写入并 `fsync` 本机 WAL 后才返回
   `DURABLE_ACCEPTED`；只有 provider result 已持久化、owner 已提交 observed state 后才 ACK
   provider completion。
4. **执行契约**：provider 只接收类型化、digest 绑定、容量有界的 immutable request。
   控制消息不得携带 shell、任意 argv、宿主路径、动态库名或可执行字节。

生产连接方向必须是 agent -> Controller outbound，使 NAT、家庭宽带和无公网入站端口的节点也能
被管理。Controller 通过该已认证 session 下发命令并接收状态；不得为了管理流量要求用户额外配置
FRP、端口转发或 Controller 到节点的直连。`事实`：当前 `mesh_control_agent_runtime` 已使用 H2-only
`POST /v1/agent/sync` 主动轮询并复用既有 control owner/WAL/reconciler；Controller Iris adapter 从
真实 mTLS socket 取得 leaf digest，不信任 header。当前不是长驻 WebSocket：每次请求至多推进一个
bounded durable mutation，HTTP timeout 后 maintenance coroutine 继续收敛已提交操作。

功能执行的最终授权固定为交集：

```text
effective authority = authenticated controller identity
                    ∩ signed management grant
                    ∩ immutable local node policy
                    ∩ advertised runtime availability
                    ∩ exact provider ID and artifact/config digest
```

任何一项缺失都 fail closed。`MANAGE` 只允许改变 assignment，不包含 `RUN_BUILTIN`、
`RUN_NATIVE` 或 `RUN_WASM`；三类运行权限互不包含。Native 与 WASM 都必须本机预注册、digest 绑定、
显式启用并经过受信 OS sandbox launcher；Native 不经过 TurboWASM，WASM 在独立 child 内使用
TurboRuntime/TurboWASM limits。产品 profile 仍默认关闭两者，直到平台 sandbox 与审计门槛完成。

V1 provider 目录按业务能力预注册，不提供通用插件入口：

| provider class | 目标资源 | 执行位置 | 权限边界 |
|----------------|----------|----------|----------|
| network builtin | network、route、service、DNS/policy snapshot | agent 通过 typed local IPC 调用 `meshd` | resource-scoped `MANAGE` + 本机 network policy |
| node builtin | service lifecycle、version/status、受控 diagnostics | agent 或 OS service adapter | 固定 action enum；不能停止 agent 自身或修改 trust root |
| release builtin | release assignment、pull/mirror/pin/withdraw | 独立有界 transfer worker | manifest/digest、目标 root 和带宽/磁盘 quota 均预配置 |
| Native provider | 预部署的第一方/批准扩展 | 独立低权限 worker process | `RUN_NATIVE` + exact provider/artifact/config digest |
| WASM provider | 预部署 sandbox task | 独立 TurboWASM child，产品默认关闭 | `RUN_WASM` + exact deployment/digest + runtime limits + OS sandbox |

provider ID、ABI/schema version、支持的 action 和资源上限在启动时注册并形成 immutable catalog；
Controller 只能选择 catalog 中能力，不能让节点动态加载控制消息指定的实现。`meshd` IPC adapter
同样是 provider，不允许 agent 穿透其内部结构或直接共享 packet-path 可变状态。production V1 已选择
独立 `FlowMQ::FlowMQ` over CoroNet TLS/mTLS loopback：`meshd` 使用
`ROUTER(bind, max_connections=1)`，agent 使用 `DEALER(connect)`，业务 payload 使用 canonical
`MeshNodeIPC/1`；FlowMQ delivery 不是远端执行或持久化。当前 adapter 拒绝 CoroNet Pipe，安全失败不得
fallback。standalone FlowMQ ROUTER v4 与 CONNECT v3 已提供双向 certificate-to-claimed-identity hook，
Mesh adapter 以 immutable exact map 强制安装并通过独立 server/client current/next leaf、双方
unmapped/old-pin certificate 拒绝、双向 EKU 错配、listener restart 重认证和进程边界往返测试；显式
client TLS config 禁用 session cache。远程 H2 agent path 已有 current/next leaf reload、exact
certificate/HELLO binding 和存量 session fencing；FlowMQ 本地 channel 的自动换证、私钥文件 ACL
统一检查、生产签发和审计仍按
[`FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md`](FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md) 完成，shared multi-tenant
profile 在这些门槛前保持 pre-production。完整 IPC 契约见
[`MESH_LOCAL_IPC_DESIGN.md`](MESH_LOCAL_IPC_DESIGN.md)。

后续 observation、telemetry、release/Native worker 必须使用独立容量和安全域，并针对独立 FlowMQ 当时
公开的 API 重新设计，不能继续依赖旧 TurboFlow facade 的 PUB/SUB state 或 credit worker。唯一 audit、
文件/chunk/media bytes 不进入 FlowMQ；任何 side effect worker 都必须先有 durable claim，不能自动
降级为 volatile dispatch。

资源删除统一使用带 epoch/precondition 的 tombstone intent。对网络、route、service 和 function，
删除表示撤销 desired state，并由 reconciler 收敛实际状态；对 release/file，删除先撤销命名引用和
分发任务，内容寻址数据只有在不再被任何 release/snapshot/pin 引用且 grace period 到期后才由 GC
回收。控制面不直接远程执行文件系统 `unlink`，也不把“元数据不可见”误报为“所有副本已物理删除”。

## 候选方案与取舍

| 方案 | 优点 | 主要问题 | 结论 |
|------|------|----------|------|
| 把用户、OIDC、策略和 UI 全部嵌入 `meshd` | 部署单元少 | 数据面与产品状态耦合；`meshd` 停止后无法管理；扩大 privileged attack surface | 不采用 |
| 只有中央 Controller，没有独立 agent/MMP | 全局状态和 UI 简单 | Controller/网络分区时无法恢复 `meshd`；边缘节点没有自治管理入口 | 不采用 |
| 完全分布式 Gossip 管理，无 Controller 事实源 | 无中央服务 | user/group、审批、policy epoch 和审计查询难以给出单一事实；Gossip 不是 consensus | 不采用 |
| TurboP2P 仓库同时实现 Controller/UI/database | 单仓库交付 | 破坏 networking-only 边界，引入 HTTP/OIDC/storage 类型和发布周期耦合 | 不采用 |
| 独立产品 Controller + `mesh-agent`/MMP + 本地 enforcement | 数据路径无中央瓶颈；可管理；分区时保留自治；仓库边界清楚 | 新增服务、证书、数据库和部署运维 | 采用 |

权衡如下：

- **性能**：packet 热路径只读取预编译 immutable snapshot；Controller、selector 展开、签名
  和 audit export 不在 owner-loop packet path。代价是节点持有额外 agent 和有界 cache。
- **复杂度**：增加 Controller、signer、agent 和两阶段 policy rollout；通过单一事实源、类型化
  模块和明确状态机约束复杂度，不建立通用 workflow/plugin engine。
- **可维护性**：TurboP2P 只维护网络安全语义和协议；产品服务维护用户/API/UI。typed schema
  和 golden vectors 是两者契约，第三方 HTTP/database 类型不穿透 Mesh core。
- **迁移成本**：中高。需要新 executable/service、secure storage、证书、policy compiler、
  Controller 和审计 sink，但可以从 read-only inventory 与 shadow policy 分阶段上线。

## 用户可见行为

### 首次加入

1. 用户安装并启动 `mesh-agent`。
2. agent 本地生成 machine、management、management-transport 和 data-node key；private
   key 不离开节点。
3. 用户通过一次性 enrollment URL/code 完成 OIDC 登录，或服务器使用有 scope、TTL 和
   single-use 约束的 deployment token。
4. Controller 创建 `PENDING_APPROVAL` device，不向其签发 ACTIVE node certificate。
5. 管理员或预审批规则批准 device，Controller 签发有 expiry、roles、tags 和 mesh binding
   的 certificate。
6. agent 收到当前 policy bundle 和允许可见的 peer descriptors，验证后进入 ACTIVE。
7. `meshd` 只有在 agent ACTIVE 且 production policy 有效时才加入 production Mesh。

用户不复制 peer 公钥、不编辑每台机器的路由，也不需要为普通节点开放公网入站端口。

### 日常管理

用户至少能完成：

- 查看 device 的 owner、tags、虚拟 IP、版本、key expiry、last seen 和当前状态。
- 区分 direct、relay、exit 和 subnet-router path，并看到选择原因。
- 批准、暂停、撤销、重新认证或轮换 device identity。
- validate、test、diff、发布和回滚 policy。
- 分别批准“发布 subnet/exit”和“使用 subnet/exit”。
- 查询谁在何时改变了 policy、设备或服务，以及节点离线是命令结果还是故障检测。
- 导出 configuration audit 和 flow metadata 到外部 append-only/SIEM sink。

### 状态不能混用

| 维度 | 状态 | 含义 |
|------|------|------|
| enrollment | PENDING、ACTIVE、EXPIRED、REVOKED | 是否被授权加入 |
| liveness | ONLINE、SUSPECT、OFFLINE、LEFT | agent 可达性观测 |
| service | RUNNING、STOPPED、DEGRADED、UNKNOWN | `meshd` 实际状态 |
| policy | CURRENT、STALE、REJECTED、MISSING | 本地执行快照状态 |
| path | DIRECT、RELAY、UNAVAILABLE | 当前数据路径 |

例如 OFFLINE 不等于 REVOKED，STOPPED 不等于 agent 离线。故障探测不能自动撤销设备，
证书撤销也不能伪造“某管理员关闭了节点”的审计结论。

## 总体架构与依赖方向

```text
OIDC / CI / GitOps
        │
        ▼
┌──────────────── Product Controller ────────────────┐
│ identity registry │ policy authoring │ approvals   │
│ API/CLI/UI        │ audit index      │ signer/HSM  │
└───────────────────────┬────────────────────────────┘
                        │ signed immutable bundles / RPC
                        ▼
┌──────────────── MMP management overlay ────────────┐
│ mesh-agent ─ mesh-agent ─ mesh-agent ─ mesh-agent  │
│ membership │ anti-entropy │ command │ audit anchor │
└────────┬────────────┬────────────┬────────────┬─────┘
         │ local IPC  │            │            │
         ▼            ▼            ▼            ▼
       meshd        meshd        meshd        meshd
         └──────── encrypted Mesh data plane ────────┘
```

依赖方向固定为：

```text
Controller/UI -> product API adapter -> signed policy/enrollment protocol
mesh-agent -> MMP codec + policy verifier + supervisor adapter
meshd -> compiled policy snapshot + Mesh core
Mesh core -X-> Controller database/UI/OIDC/HTTP types
```

TurboP2P 仓库负责 MMP schema、identity verifier、policy semantics/compiler、执行快照和
agent integration contract。OIDC、Web UI、Controller database、HTTP API hosting 和 SIEM
connector 属于独立产品服务，可复用 TurboHTTP，但不成为 `TurboP2P::Mesh` 依赖。

## H2/WS 接口与控制原语

H2 和 WebSocket 是接口承载，不是资源模型、授权事实源或节点功能本身。生产接口按职责分为：

| 接口 | 发起方 | 用途 | 约束 |
|------|--------|------|------|
| Controller H2 resource API | operator/CI/`meshctl` | 查询和事务化修改资源、查询 operation/audit | mutation 写 Controller 事实源，不直接调用节点函数 |
| outbound H2 typed sync | agent | `HELLO`、命令 claim、durable receipt/ACK 与 heartbeat | mTLS、固定上限 canonical frame；断线重连不改变业务语义 |
| outbound RFC 8441 WebSocket | agent（后续优化） | observation/event 低时延流与 cursor 续传 | 只能复用同一事实源和 session fencing，不能改变 receipt 语义 |
| node H1/H2 diagnostic API | 本机或显式授权的运维端 | status/event/receipt 点查与诊断 | 非 Controller 全局事实源，不作为 NAT 后节点的生产下发路径 |

`事实`：当前 agent 使用 H2-only mTLS POST `/v1/agent/sync` 执行 typed HELLO、CLAIM、COMMAND、
RECEIPT、ACK、HEARTBEAT 和 CLOSE；command 只有在本地 WAL durable receipt 可查询后才 ACK。
`目标`：后续可在同一身份/session 事实源上增加 RFC 8441 WebSocket 作为 observation/event 的低延迟
通道，H2 resource API 仍是人和自动化的稳定接口。连接断开后 agent 以 committed cursor 和 pending
operation 重连，Controller 从 durable outbox 重发未确认 intent。不得把 WS connection、HTTP request
arena 或进程内 outbox 当作事实源，也不得静默切换到权限更弱的 plaintext/H1 路径。

`事实`：TurboHTTP 的 `http2_client` 已提供带 `protocol` 的 extended CONNECT 和全双工
`http2_request_stream()`；CoroNet 的 `coro_websocket_t` 是握手后的 transport-independent RFC 6455
session，支持 HTTP/2 transport、client mask、frame/message、PING/PONG/CLOSE。outbound adapter 应
组合这两个现有边界，不再手写 H2 或 WebSocket framing。HTTP2 data callback 与 WebSocket message
callback 给出的内存都是 callback-borrowed view，跨挂起或入队前必须复制/转移到有界 owned buffer。

`事实`：诊断命令入口采用节点侧同一个 Iris WebSocket route，HTTP/1.1 客户端使用 RFC 6455，
HTTP/2 客户端使用 RFC 8441 extended CONNECT；状态读取采用普通 H1/H2 request/response route。
两种 adapter 已复用同一个 transport-neutral owner 和权限模型，不各自保存业务状态。生产方向的
outbound H2 typed-sync adapter、agent service 和 Controller session 已实现；RFC 8441 outbound pump
尚未实现，也不是 durable command/receipt 正确性的前置条件。

控制原语固定为：

| 原语 | 用途 | 不承担 |
|------|------|--------|
| `HELLO` | 协商 schema、capability、cursor 和 session binding | 身份签发、自动授予权限 |
| `INTENT` | 携带带 epoch/precondition 的目标资源变更 | 表达 shell、argv、宿主路径或任意 URL |
| `OBSERVATION` | 节点报告实际资源状态与已应用 epoch | 反写 Controller desired state |
| `OPERATION` | 描述提交、接受、运行和终态 | 作为资源事实源 |
| `EVENT` | 以 cursor 顺序回放资源/operation 变化 | 无限期持久化或替代完整 snapshot |
| `RECEIPT` | 确认消息/命令进入某个明确阶段 | 把“已入队”冒充“已执行” |

生产 session 建立和恢复固定为：

```text
agent resolves Controller endpoint
-> establish mTLS H2 and verify Controller identity/binding
-> RFC 8441 extended CONNECT
-> signed HELLO(node/certificate/incarnation/schema/capabilities/limits/cursors)
-> Controller verifies enrollment/revoke epoch and returns session binding
-> compare desired epoch, durable command sequence and event cursor
-> send a complete signed snapshot or replay a bounded outbox suffix
-> continue bidirectional intent/observation/operation/event/receipt flow
```

`HELLO` 的 capability 只报告本机可用能力，不能授予权限；至少包含支持的 schema/minor、resource
kind、runtime availability、最大 frame、retained bytes、provider IDs、当前 applied epoch、WAL durable
index、event cursor 和 agent incarnation。若 schema、身份 binding 或 cursor 无法安全续接，session
明确失败或要求完整 snapshot；不能猜测跳过，也不能自动切换到较弱协议。

Controller 在事务中同时提交 resource mutation、operation 和 durable outbox record，之后才向 agent
发送。agent 的 transport ACK 只表示 frame 被接收；`DURABLE_ACCEPTED` 才允许 Controller 标记命令
已由节点持久接受。terminal operation/observation 到达后，Controller 原子更新 status index 和 audit，
再清理满足 retention 的 outbox/operation 数据。WS 断线不会回滚 Controller desired state，也不会让
节点扩大本地权限。

控制入口的状态迁移顺序是：

```text
mTLS peer authorization
-> WebSocket binary frame / fixed frame limit
-> verify signed MMP envelope and body digest
-> stateless mesh/node/principal/certificate admission
-> copy borrowed frame into bounded SPSC channel
-> domain owner validates replay and canonical intent
-> atomically submit desired state + operation
-> commit replay record
-> reconciler/provider changes observed state
-> publish operation/event/receipt
```

replay record 必须在有界队列成功接收并且 desired-state transaction 成功后才提交；否则一次
backpressure 失败会永久吞掉合法命令。相同 request ID 返回相同 operation；相同 MMP message ID
重放则拒绝。未知提交结果必须先按 request ID 查询，不能盲目生成另一个业务请求。

`事实`：当前代码完成上述流程到“提交 desired state + operation + 本地 snapshot/event ring”。
`/v1/control/status` 提供 generation 一致的资源/operation 分页；页间状态改变返回 conflict，调用方
必须从 offset 0 重启。`/v1/control/events` 返回 cursor 之后严格递增的有界事件；cursor 落后于
retention 时同样返回 conflict。两个 route 均强制已验证 client certificate、固定 Controller
certificate binding 和双方 `OBSERVE` 权限；Release loopback 测试已实际完成 TLS 请求、二进制
解码、403 拒绝和连接后 shutdown drain。

`边界`：WebSocket adapter 仍只有 Controller 到 agent 的诊断入站 frame，没有主动推送 snapshot、
observation、operation、event 或 receipt 的出站 pump。durable receipt 改由 H1/H2 按 operation ID
查询，避免越过 H1 connection/H2 stream 生命周期保留 Iris WebSocket 指针。当前 H1/H2 响应依赖直连 mTLS，是
operational view，不是可跨代理转发或长期留存的 signed audit artifact。新的 outbound H2 agent
service 已覆盖重连、durable command claim/receipt/ACK，Controller outbox/session 也持久化命令交付
状态；完整 observation/event pump、产品数据库和 signed audit artifact 仍未完成。因此“通过 H2
下发任务并确认 durable accept”已有闭环组件，状态汇总仍不是完整产品闭环。

### 所有权、容量与关闭

- Iris callback 借用 receive buffer；跨 callback 或入队前必须复制为 channel-owned payload。
- 一个 transport producer 对应一个 domain-owner consumer；需要双向传输时使用两个有界 channel，
  不让 socket callback 和 Mesh owner 共享可变状态。
- frame、payload、entry count、retained bytes、每次 poll 的 command 数和 event retention 都有
  硬上限。满载返回 `RESOURCE_EXHAUSTED/BUSY`，不丢弃、不覆盖旧命令、不建立无界队列。
- 关闭顺序是停止 attach/ingress、唤醒或拒绝新 producer、拒绝未开始命令、解决已提交 operation、
  drain active callback/read、释放 frame ownership、关闭 listener、停止 CoroNet managed tasks，
  最后销毁 app/channel/context。managed-task drain 使用显式毫秒超时和 `TURBO_RUN_ONCE` 推进异步
  close；超时返回 `INVALID_STATE`，不得释放仍被外部任务引用的 context。

`事实`：当前 schema 的单 frame 硬上限为 64 KiB，单 status snapshot 上限为 256 KiB，内存 outbox
编译期上限为 4,096 entries/64 MiB；channel entry、retained bytes、payload、poll budget、operation
journal 和 event retention 还必须由部署配置给出非零值并在启动时校验。由于 durable ingress 同时保留
decoded payload 和原始 signed frame，内存预算按下式计算，而不是只乘 payload：

```text
channel_retained_budget >= entry_capacity
                         * (max_signed_frame + max_decoded_payload + entry_metadata)
global_control_budget >= sum(active_session/channel/provider/outbox retained bytes)
```

`目标`：Controller 的每节点 durable outbox 同样设置 entries、bytes 和 retention age 三重上限；达到
上限时拒绝新的相关 mutation 或明确返回 `RESOURCE_EXHAUSTED`，不能把压力转移成无界数据库/内存增长。
provider backpressure 不阻塞 CoroNet loop；owner 每次 poll 只推进配置的 command/completion/start budget。

### 持久化提交、恢复与副作用边界

完整 checkpoint 是恢复和压缩原语，不是每条命令的提交协议。若 owner 先修改内存、reconciler 再
启动 provider，最后异步写 snapshot，节点可能在 Native 副作用发生后、snapshot 落盘前崩溃，重启后
便失去对应 desired state。反过来，若 provider completion 被 consume-on-read API 取走后才写盘，
落盘失败又会丢失唯一完成结果。两者均属于 `HIGH` 一致性错误，不能用重试或日志掩盖。

`事实`：当前实现已经接通以下边界：

- checkpoint 同时保存 resource document、desired/observed、operation、event cursor、replay
  `last_sequence` 和未过期 message ID，避免状态与 replay 分成两套恢复事实；
- 解码严格检查 magic/version/长度/保留位/容量/摘要/身份绑定；所有临时 state 和 replay 都成功导入后
  才替换 owner，任何失败均保持原 owner 不变；
- 恢复时过期 replay cache 可以丢弃，但 `last_sequence` 继续有效；snapshot generation、event cursor
  和 replay generation 的溢出边界 fail closed；
- production checkpoint store 当前复用 WAL 的 32-byte 本机 authentication key 做 HMAC-SHA256；
  该密钥必须由 secure storage 加载且不得进入网络、日志或 checkpoint。错误密钥、内容篡改、损坏或
  binding mismatch 均在 ingress 开放前 fail closed；后续若需密钥域隔离，应以 domain-separated KDF
  派生 checkpoint 子密钥，而不是增加另一份人工配置的长期密钥；
- 文件 store 有 65.9 MiB 的 payload 硬上限（`69,107,968` bytes），独占非阻塞锁；checkpoint
  编码在 owner 线程捕获有界一致快照，文件 I/O 和 WAL compact 只在 persistence worker；目录项 durability
  仍受 TurboUtils 当前没有 directory-fsync 抽象的限制，断电测试必须把这一窗口作为残余风险验证。

生产路径当前使用以下顺序：

```text
verify signed frame and admission
-> append canonical signed intent to bounded WAL
-> fsync/commit WAL record on persistence worker
-> owner atomically commits desired state + operation + replay sequence
-> expose queryable DURABLE_ACCEPTED receipt
-> provider durably accepts operation_id
-> provider performs the side effect
-> provider exposes a retained completion (peek, not consume)
-> append/fsync provider result WAL
-> owner commits observed/operation state and durable index
-> ACK provider completion
-> later persist authenticated checkpoint, then compact WAL at the exact tail
```

只有 `DURABLE_ACCEPTED` 才表示重启后仍可恢复；transport queued、owner accepted、provider running 和
completed 必须是不同 receipt/state，不能共用一个“成功”。WAL record 必须保留原始签名 frame 或由
节点密钥认证的 canonical bytes，不能只保存可由本机任意进程重算 SHA-256 的裸结构。

持久化 worker 是单线程、单槽或小容量有界队列。owner 在一个 mutation 等待 durable commit 时停止
处理后续 mutation，也不得把该 operation 交给 reconciler；状态/事件查询仍可读取上一个 committed
snapshot。queue full 返回 `BUSY`，disk full、lock lost、fsync 或 rename 失败进入显式
`PERSISTENCE_FAULT`，停止新 command/provider start，但不停止既有 Mesh 数据转发。后台重试只能重写
同一 operation/checkpoint，不能创建新 request ID 或扩大权限。

恢复在打开 H2/WS ingress 前完成。checkpoint 损坏、身份不匹配或 WAL 出现断裂/错误 MAC 时启动
失败，禁止退回空状态。`ACCEPTED` operation 可按同一 operation ID 重新投递；`RUNNING` operation
通过同一 operation ID 重新入队，provider 必须自行保证 durable accept/幂等副作用；terminal result
已在 WAL 时不会重启工作。provider API 已使用 `try_peek_completion` + `ack_completion`，ACK 失败会
保留同一 completion。真实 Native/TurboWASM worker 已隔离到认证子进程并受 deadline、输出容量和
process-tree cleanup 约束；worker 内部跨父进程崩溃的 durable journal 与副作用幂等仍是下一阶段边界。

### 节点功能栈与权限

节点功能采用 provider boundary，而不是让 H2/WS message 直接调用函数：

```text
signed function intent
-> management grant ∩ immutable local node policy
-> runtime availability check
-> prestaged artifact/config digest validation
-> bounded provider operation
-> observed state + signed result/audit
```

三类 runtime 权限互不包含：`RUN_BUILTIN`、`RUN_NATIVE`、`RUN_WASM`。`MANAGE` 只允许提交或停止
assignment，不隐含运行权限；获得 `RUN_NATIVE` 也不获得 `RUN_WASM`。Native 必须是本机预注册、
digest 绑定、参数类型化且建议 out-of-process 的 provider，控制消息不能携带任意 executable、宿主
路径或 argv。

`事实`：V1 provider registry 复制并固定 provider descriptor，只接受 builtin 或 Native，WASM
descriptor 在初始化时 fail closed。provider callback 是非阻塞策略接口：`try_start` 必须在返回前复制
要保留的 typed request，临时满载返回 `RESOURCE_EXHAUSTED`；completion 只能引用已由同一 provider
接收的 operation ID。reconciler 容量不得小于 operation journal 容量，同一 function 同时最多一个
in-flight operation。关闭先停止新 start，再调用 provider `close`；ready completion 在 close 后必须
保留到 result WAL、owner apply 和 exact ACK 完成，只在 provider 声明 drained 后把其余未完成 operation
标记为 `INTERRUPTED`。当前 `mesh-agent` 已把 prestaged Native 与 TurboWASM provider 接到独立认证
子进程；production 配置必须提供并精确校验 OS sandbox launcher，直接 spawn 只允许测试。

第三方 WASM deployment 的产品开放仍推后：已有 TurboWASM 子进程并不等于允许任意第三方模块。
只有本机预注册且 digest 绑定的 deployment 能被 provider 选择；本机 policy、`RUN_WASM`、runtime
availability 和 provider ID 必须同时匹配。平台账户/token、seccomp/job/cgroup/AppContainer、
preopen/network capability、持久化 journal、取消/恢复和端到端安全测试全部达标后，才可面向第三方
以显式 feature/capability 开启；加入 Mesh 或获得 `MANAGE` 不会自动启用它。

## 单一事实源

| 状态 | 唯一事实源 | 节点侧派生数据 |
|------|------------|----------------|
| user/group | configured IdP；Controller 保存带 sync generation 的只读快照 | bundle 中已展开 selector |
| device tags/owner | Controller device registry | certificate 与 selector snapshot |
| device enrollment | Controller device registry | signed node certificate |
| trust root | 本机部署配置 | verified issuer view |
| node private keys | 对应节点 secure storage | public certificate/descriptor |
| policy source | Controller policy store | signed compiled policy bundle |
| policy execution | `meshd` immutable snapshot | decision、counter、audit event |
| resource desired state | Controller transactional resource store | agent WAL/checkpoint 中已 durable accept 的本地目标快照 |
| southbound delivery | Controller durable outbox，以 operation ID 去重 | WS send queue、重连 cursor |
| node observed/operation state | agent owner + authenticated WAL/checkpoint | Controller status index、UI cache |
| provider side effect | 对应 builtin/Native provider durable journal 或 OS service manager | reconciler in-flight view、metrics |
| membership | 各 agent self record + SWIM observations | Controller/UI device view |
| `meshd` process state | OS service manager | agent reconcile result |
| audit entry | 产生事件的节点/Controller | index、export、signed checkpoint |

Controller 不能根据 UI cache 反写 device 或 policy；agent 不能独立修改 policy epoch；Mesh
core 不能从日志重建授权状态。

## 密钥与身份层级

### Key hierarchy

| key | 算法/用途 | 生命周期 | 是否分发 |
|-----|-----------|----------|----------|
| offline root | Ed25519 trust anchor | 年级；离线/硬件保护 | 只分发 public root |
| enrollment issuer | Ed25519 签发 node/operator cert | 月级；可轮换/撤销 | public chain |
| machine key | Ed25519 device continuity proof | 安装级；secure storage | public key 给 Controller |
| management key | Ed25519 MMP 端到端签名 | node cert 生命周期 | certificate 中选择性分发 |
| management transport key | X25519 adjacent channel identity | node cert 生命周期 | certificate 中选择性分发 |
| data node key | X25519 端到端数据身份 | 可轮换 node epoch | 只给允许通信的 peer/relay |
| ephemeral handshake key | X25519 每连接临时 ECDH | session 级 | 仅 handshake public key |
| traffic keys | KDF 派生 tx/rx AEAD key | session/path epoch | 永不分发 |

machine key 证明“仍是同一安装实例”，不直接加密业务流量。management 和 data key 分离，
避免 management compromise 自动变成数据面 impersonation。session 建立只交换 public
material；private key、traffic key、deployment token 和 disablement secret 禁止进入
Gossip、日志、状态 API 或 crash report。

当前 P2P identity 和 ephemeral handshake key 已切换为 TurboUtils checked OS CSPRNG；
熵源失败会终止 identity 创建或握手，不再静默留下未初始化 key。Controller、agent 和未来
signer 也必须复用同一 CSPRNG 失败语义，禁止自行增加 time/PID/`rand()` fallback。

当前 DHT join-ring 的 bootstrap 临时路由 ID 已由 endpoint 稳定派生，而非弱随机数
（[`node.c`](../p2p/src/core/node.c#L417)）。该 ID 只用于认证完成前的临时路由定位，不能作为
节点身份、授权主体或证书 binding；控制面必须继续以已认证 public key/node certificate 为准。

production enrollment issuer 必须在独立 signer/HSM 或等价隔离边界内，Controller 只能
提交有审计的 signing request，不能读取 issuer private key。仅攻陷 Controller API、但未
攻陷 signer policy 时，攻击者不能签发任意节点；若 online issuer 本身失陷，系统不能声称
仍安全，必须依靠 issuer revoke、短证书 TTL、节点侧 trusted-signer policy 和可选 quorum
限制影响范围。

### Public-key distribution

裸公钥不是授权事实。可连接描述符必须包含：

```text
mesh_id + managed_node_id + virtual_ip + public_keys + key_epoch +
roles/tags + allowed_scopes + endpoints + issued_at + expires_at +
issuer + certificate_signature
```

Controller 只向策略允许的节点分发 data-plane peer descriptor。relay 只获得完成下一跳
转发所需的 descriptor，不获得端到端 traffic key。MMP agent membership 可以知道节点存在，
但“存在”不自动授予 data-plane public key、路由或连接权限。

Gossip 可以转发完整、已签名 certificate/record，但接收端必须从本机 trust root 验证；
DHT 命中、裸 key、hostname、虚拟 IP 或低 RTT 都不能成为信任依据。

### Session establishment

目标握手流程：

```text
resolve signed peer descriptor
-> validate mesh/node/key epoch and policy visibility
-> authenticated ephemeral X25519 handshake
-> bind origin + destination + protocol + capability + session epoch
-> KDF derives independent tx/rx keys
-> key confirmation
-> enable replay window
-> publish usable path
```

握手失败、证书过期、key epoch 不一致或 capability downgrade 必须 fail closed。不能回退到
未认证 raw selected-pair transport。重连、node key rotation、path security context 重建，
以及配置的 time/byte limit 都会建立新 session epoch；旧 epoch packet 不能进入新 session。

### Rotation 与 revocation

- node rotation request 同时包含 old-key proof 和 new public key；Controller 签发更高
  `node_epoch`，旧 key 在有界 overlap 后失效。
- old key 丢失时必须重新 enrollment，不能只凭 node name 或 virtual IP 恢复身份。
- revoke 是 immutable signed record，包含 node/key epoch、reason code、effective time 和
  authority signature。
- Controller 对在线 agent 使用 targeted push/RPC，MMP Gossip/anti-entropy 负责遗漏补齐。
- 本地收到有效 revoke 后立即停止新 session、删除 peer descriptor，并按 policy
  terminate 或 drain 既有 flow。
- 管理分区期间无法保证全网瞬时撤销；UI 必须显示每个节点确认的 policy/revocation epoch，
  不能只显示“revoked”而隐藏 enforcement lag。

## Grants 与安全策略

### 分层模型

策略不是单一万能规则表，而是四个类型化层次：

1. **Enrollment policy**：谁能注册、是否需要审批、可取得哪些 tags/roles、证书 TTL。
2. **Network grants**：source identity 可以访问哪些 node/service/CIDR、protocol 和 port。
3. **Route grants**：谁能 advertise subnet/exit，谁能通过哪个 route/exit。
4. **Management grants**：谁能 observe、restart、reconcile、发布 policy 或管理 exit。

硬安全 guardrail 位于所有 grant 之前，不能被普通 allow 覆盖：identity/source binding、
anti-replay、metadata/management range、invalid fragment、capability 和 local break-glass policy。

### 决策语义

- production policy 使用 allow-only Grants；无匹配 grant 即 deny。
- deny guardrail 优先于所有 grant，不依赖文件顺序。
- 同类 grant 是集合并集，不使用跨文件 first-match；冲突或歧义在编译期拒绝。
- direction 是单向的；`A -> B` 不隐含 `B -> A`。
- advertise route、use route 和 administer route 是三个独立 capability。
- user/group/tag 只在 Controller 编译时解析；packet 热路径只比较稳定 node ID、prefix、
  protocol、port 和预编译 rule ID。
- domain policy 由受控 DNS resolver 产生带 flow correlation 的派生 decision，不能只靠
  观察 UDP/TCP 53 或 SNI 猜测授权。

### Authoring example

以下 JSON 是目标 authoring schema 示例，不是当前 `mesh_config_t` 输入：

```json
{
  "schema_version": 1,
  "mesh_id": "production",
  "base_epoch": 42,
  "security_profile": "production",
  "groups": {
    "media-operators": ["user:alice@example.com"],
    "network-admins": ["user:netops@example.com"]
  },
  "network_grants": [
    {
      "id": "media-control",
      "src": ["group:media-operators"],
      "dst": ["service:turbomedia-control"],
      "ip": ["tcp:8443"]
    }
  ],
  "route_grants": [
    {
      "id": "use-eu-exit",
      "src": ["tag:managed-client"],
      "via": ["node:eu-exit"],
      "dst": ["cidr:0.0.0.0/0"],
      "capabilities": ["route.use"]
    }
  ],
  "management_grants": [
    {
      "id": "media-observe",
      "src": ["group:media-operators"],
      "target": ["tag:media-node"],
      "capabilities": ["mesh.observe", "mesh.diagnostics"]
    }
  ],
  "tests": [
    {
      "name": "media operators reach control only",
      "src": "user:alice@example.com",
      "accept": ["service:turbomedia-control:tcp:8443"],
      "deny": ["service:turbomedia-control:tcp:22"]
    }
  ]
}
```

所有 selector 必须解析为至少一个对象，除非规则显式声明 `allow_empty = true`。未知字段、
未知 capability、重复 rule ID、非法 CIDR/port、循环 group、无 owner tag 和空 production
policy 都是编译错误。

### Compile and publish transaction

```text
parse external format
-> normalize typed document
-> resolve identity/group/tag snapshot
-> apply immutable guardrails
-> compile network/route/management tables
-> static analysis and policy tests
-> calculate canonical hash and create PREPARED candidate
-> isolated signer signs candidate hash + proposed next epoch
-> compare-and-swap base epoch
-> atomically install signed bundle + new current epoch + audit diff
-> distribute desired state
-> agents verify and stage
-> activate at not_before/epoch
-> report applied/rejected status
```

signing 不能发生在持有数据库锁的事务内。若 compare-and-swap 发现 base epoch 已变化，
PREPARED candidate 和其签名不成为 current，调用方必须重新 diff/compile；签名不能套用到
其他 epoch 或 payload。Controller database transaction 是 policy source、epoch 和 audit diff
的唯一提交点。任何节点拒绝 bundle 都不会让 Controller 悄悄改写 bundle；UI 显示 partial
rollout，并允许发布新的更高 epoch 修复或回滚。回滚是重新发布旧语义内容的新 epoch，
不倒退 epoch。

### Existing policy compatibility

当前 `mesh_packet_policy_allows()` 在完全无规则或当前 direction 无规则时保持 allow；配置了
当前 direction 后，无匹配规则才 deny（[`mesh.c`](src/mesh.c#L1076)）；公开配置仍是
有顺序的 rule array（[`turbo_mesh.h`](include/turbo_mesh.h#L101)），并有方向/端口回归测试
（[`test_mesh_paths.c`](tests/test_mesh_paths.c#L1818)）。目标迁移不能静默改变旧用户：

- `security_profile = compat` 保留当前 `mesh_config_t`、first-match 和 permissive empty 行为。
- `security_profile = production` 要求有效 signed compiled bundle，并默认 deny。
- 每个 profile 只允许一个 policy 事实源：compat 使用本机静态配置；production 使用 signed
  bundle，本机只保留 trust root、不可放宽的 guardrail 和 break-glass 设置。production
  同时配置静态 packet/peer/route allow 与 signed bundle 时启动失败，不做隐式合并。
- Controller compiler 可以把 Grants 编译为内部 snapshot，但不能依赖旧数组顺序表达
  guardrail。
- production bundle 先以 observe-only 计算 shadow decision，再显式切 active。
- 旧 API 保持不变；新 snapshot/decision API 采用 additive capability 和版本化 opaque handle。

## Controller 产品接口

### Authentication 与 RBAC

- 人类用户通过外部 OIDC/OAuth2/SAML IdP 登录；Controller 不保存用户密码。
- CI 使用短期 workload credential，不使用永久管理员 API key。
- API authorization 使用独立 product roles：viewer、device-admin、network-admin、auditor、
  owner；它们再映射到 management capabilities。
- 所有 mutation 必须携带 actor、request ID、idempotency key 和 expected/base epoch。
- owner/trust operation 要求 step-up authentication；MMP/1 仍不提供远程 trust-root 修改。

### Resource API

目标资源边界：

| resource | read | mutation |
|----------|------|----------|
| `/v1/meshes/{mesh}/devices` | list/detail/status/epochs | approve、expire、revoke、retag |
| `/v1/meshes/{mesh}/network` | IPv4/IPv6 prefix、DNS suffix、IPAM 状态 | 更新网络参数、保留地址 |
| `/v1/meshes/{mesh}/dns` | A/AAAA/PTR/alias 记录与 rollout | validate、publish、remove alias |
| `/v1/meshes/{mesh}/policy` | source/compiled/diff/status | validate、publish、rollback |
| `/v1/meshes/{mesh}/routes` | advertised/approved/active | approve/revoke advertise/use |
| `/v1/meshes/{mesh}/services` | registry/health | publish policy intent |
| `/v1/meshes/{mesh}/releases` | manifest/content digest、distribution/retention 状态 | publish、withdraw、pin/unpin |
| `/v1/meshes/{mesh}/functions` | assignment/runtime/provider/observed state | apply、stop、delete、reconcile |
| `/v1/meshes/{mesh}/operations` | command/result | restart、reconcile、diagnostics |
| `/v1/meshes/{mesh}/audit` | filter/page/export status | configure authorized export |

mutation 使用 `If-Match`/base epoch 防止并发覆盖；重复 idempotency key 返回相同结果。API
返回 stable error code、field path、current epoch 和 correlation ID，不依赖日志文本表达失败。
Controller 只向 agent 发送类型化 MMP command，永不拼装 shell/argv。

### CLI surface

以下列表是产品能力示例；规范性的 resource/verb 命名、`turbo_cmd` 扩展、Controller API 映射、
operation/watch、文件删除和兼容迁移以
[`MESHCTL_PRIMITIVES_DESIGN.md`](MESHCTL_PRIMITIVES_DESIGN.md) 为准。

```text
meshctl devices list
meshctl devices approve <device>
meshctl devices revoke <device> --reason <reason-code>
meshctl network show
meshctl network set-prefix --ipv4 <cidr> --ipv6 <cidr>
meshctl dns assign <device> --name <name> [--ipv4 auto] [--ipv6 auto]
meshctl dns records
meshctl policy validate <file>
meshctl policy test <file>
meshctl policy diff <file>
meshctl policy apply <file> --base-epoch <epoch>
meshctl routes list
meshctl exit approve <node>
meshctl exit grant-use <selector> --node <node>
meshctl releases publish <manifest> --selector <selector>
meshctl releases withdraw <release> --base-epoch <epoch>
meshctl functions apply <spec> --selector <selector>
meshctl functions stop <function> --base-epoch <epoch>
meshctl audit tail --actor <id> --action <action>
meshctl diagnose <node> --profile network-basic
```

CLI 默认显示 plan/diff，高风险操作要求显式确认或 CI 的 `--non-interactive` + expected epoch。
secret、private key 和 token 不出现在命令行参数、process list 或 shell history；登录 token
通过 OS credential store 或受限 stdin/file descriptor 传递。

### Device view

Device 页面至少展示：

- stable device ID、managed node ID、owner、tags、虚拟 IP。
- 主名称、别名、IPv4/IPv6 lease、地址和 DNS snapshot epoch。
- enrollment/liveness/service/policy/path 五个独立状态。
- certificate expiry、node key epoch、last rotation 和 revoke status。
- client/agent/meshd 版本与 platform。
- direct/relay path、relay identity、exit/subnet capabilities。
- applied policy/revocation epoch 与 Controller current epoch 的 lag。
- last seen、last signed LEFT、last command 和可验证离线原因。

UI 不显示“online”来替代 policy/security health，也不把 probe timeout 表述为某个用户关闭
节点。

## 虚拟网络、IPAM 与 MagicDNS

### 当前兼容边界

当前 `mesh_config_t` 已提供本机静态 `magic_dns_domain` 和 `magic_dns_records`，
`mesh_resolve_magic_dns()` / `mesh_reverse_magic_dns()` 可做进程内正反向查询；这层兼容行为继续
保留。它目前不是 DNS server，也不会配置操作系统 resolver；记录使用 16 字节 IPv4 字符串，
反向查询依赖 IPv4 parser，因此不能宣称支持 IPv6、AAAA 或双栈 IPAM
（[`turbo_mesh.h`](include/turbo_mesh.h#L92)、[`mesh.c`](src/mesh.c#L4616)）。

### 目标资源模型

Controller 将 Mesh 信任域与逻辑 Network 分开建模：一个 Mesh 可以包含多个相互隔离的
Network；每个 Network 独立拥有地址池、membership、route、DNS 和 policy。完整的
`network_uid`、共享 underlay、数据面隔离、重叠 CIDR、删除与迁移契约见
[`MESH_MULTI_NETWORK_DESIGN.md`](MESH_MULTI_NETWORK_DESIGN.md)。

```text
Network {
  network_uid, mesh_id, generation, lifecycle,
  ipv4_prefix?, ipv6_prefix?, dns_suffix,
  reserved_ranges, dns_service_addresses,
  address_epoch, membership_epoch, route_epoch, dns_epoch
}

AddressLease {
  lease_id, network_uid, managed_node_id, node_key_epoch,
  family, binary_address, state, issued_at, expires_at?
}

DnsRecord {
  record_id, network_uid, owner_node_id?, canonical_name, type, value,
  ttl, record_epoch, not_after?, aliases?, service_id?
}
```

network prefix、lease 和 DNS record 的唯一写入事实源是 Controller database transaction。
agent/`meshd` 只安装验签后的 immutable snapshot；本地 DNS table、路由和 UI 列表都是派生
视图，不能经 Gossip 各自推进。节点 enrollment 可在同一 Controller 事务中原子分配主名称、
IPv4/IPv6 lease 和证书 binding；其中任一步失败都不发布半配置节点。

地址租约必须绑定 `(mesh_id, network_uid, managed_node_id, node_key_epoch)`。节点名、A/AAAA 地址、低延迟
路径和 endpoint 都不是认证身份；连接最终仍验证 node certificate/public key。节点撤销或重新
enrollment 时，旧 lease/record 进入明确的 revoked/quarantine 状态，不能被另一个同名节点
立即继承。

### 名称解析数据流

每个节点运行本地权威 stub resolver，平台层只为该 Mesh suffix 安装 split-DNS/search domain：

```text
application query db.prod.mesh
-> OS split-DNS routes suffix to local mesh resolver
-> resolver reads current verified DNS snapshot
-> returns A/AAAA with bounded TTL
-> application connects virtual address
-> data plane independently authenticates destination node identity
```

DNS service address由 network 资源显式保留。可使用每节点本地拦截的 Mesh anycast 地址，
但不得和 node lease、exit route 或业务 subnet 重叠。默认只接管受管 suffix；不全局劫持 DNS，
也不使用 `.local`，以免与 mDNS 语义冲突。full-tunnel/exit profile 的公网 DNS 模式仍遵循
平台文档的独立 leak/kill-switch 约束，不能把 MagicDNS 当作公网 resolver。

Controller 通过 targeted push/MMP desired state 发布签名 snapshot 或受基线 epoch 约束的
delta；Gossip 只负责补齐已签名记录，不决定冲突。节点原子切换完整 snapshot，并保留一个
已验证的 rollback snapshot。签名、mesh ID、epoch、有效期或地址族校验失败时拒绝整次更新；
Controller 暂时不可用时，未过期 snapshot 继续解析，过期后新查询返回明确失败，不回退到
未经授权的公共 DNS。

首版 DNS record 支持 A、AAAA、PTR 和 CNAME-like alias；SRV/TXT 只在 TurboMedia 等业务
确有服务发现需求时加入。canonical node name 必须在 Mesh 内唯一、规范化且不可用 display
name 冒充；重复名称、地址冲突、prefix 缩小导致活跃 lease 越界、同一地址族多 owner 都在
publish 前 fail fast。

### 双栈兼容迁移

IPv6 不能通过把现有 `char virtual_ip[16]` 就地扩容实现，因为这会破坏公开结构 ABI。迁移采用
additive v2 类型：`address_family + 16-byte binary address + prefix`，新增 v2 record/snapshot
getter；旧 IPv4 API 继续返回原行为。内部路由、packet parser、policy CIDR、TUN 配置、PTR
生成和审计字段全部支持地址族后，才允许 Controller 发布 IPv6 network capability。未声明
双栈 capability 的节点不接收 IPv6 lease/route，不能静默降级为 IPv4 同名记录。

### 安全与可观测性

- DNS snapshot 只含 public descriptor，不含 private/session key、token 或用户凭据。
- resolver 对单节点/来源设置 QPS、并发、record count、name length 和 response size 上限。
- audit 记录 record/lease mutation、actor、前后 hash、epoch 和 rollout；不记录完整 DNS body。
- 指标包含 snapshot age、签名失败、A/AAAA/PTR hit/miss、stale refusal、冲突和 rollout lag。
- 验证覆盖 A/AAAA/PTR、重名/重址、撤销、epoch 回放、离线 TTL、split-DNS、不泄漏公网 query、
  IPv4-only 节点与双栈节点协商，以及 DNS 结果与握手 node identity 不一致时 fail closed。

## 审计模型

### Event classes

| class | producer | 示例 |
|-------|----------|------|
| configuration | Controller | policy diff、route approval、tag change |
| identity | Controller/agent | enrollment、approval、rotation、revocation |
| management | agent | restart/reconcile/diagnostics result |
| flow | `meshd` | flow start/end、bytes、rule/path/exit epoch |
| security | agent/`meshd` | replay、spoof、route injection、downgrade、sink failure |

统一 event envelope：

```text
schema_version + event_id + event_class + event_type + producer_sequence +
wall_time + monotonic_time? + producer_node + actor + target +
request/command/flow_id + policy_epoch + action + reason_code +
before_hash? + after_hash? + canonical_details + previous_event_hash + event_hash
```

正文禁止包含 private/session key、token、payload、完整 DNS body 或凭据。flow audit 默认是
metadata/aggregate；PCAP 是独立、显式授权、有时限和字节上限的诊断操作。

普通 flow event 不逐条做非对称签名；producer 对 event hash chain 的周期 checkpoint 签名，
在保持篡改检测能力的同时避免把签名操作放进 packet 热路径。

### Integrity 与 export

- producer 本地 append-only segment 使用 hash chain。
- segment checkpoint 由 management key 签名并通过 MMP 发布 audit anchor。
- Controller 验证 chain continuity，写入独立 append-only storage。
- export worker 使用有界 queue、重试和 dead-letter 状态；不能阻塞 packet owner loop。
- `best-effort` 与 `required` audit mode 是显式 deployment policy，不能静默互换。
- required spool 达上限时只拒绝新 flow，并产生本地安全告警；不能无限增长磁盘。

本地 chain 只能检测已有 segment 被修改，不能证明整段存储未被本机管理员删除；合规场景
必须配置外部 checkpoint/storage。

## Availability 与分区语义

| 故障 | 用户可见行为 |
|------|--------------|
| Controller 暂时不可用 | 既有 flow 和未过期 policy 继续；新 enrollment/policy mutation 失败 |
| MMP 分区 | 节点显示 stale/lag；不自动停止健康数据面 |
| policy 过期 | 停止新授权动作；按 profile drain 或拒绝新 flow，不采用旧 policy fallback |
| revoke 尚未确认 | UI 显示 pending enforcement 和未确认节点集合 |
| agent 离线、`meshd` 在线 | 数据面可继续，管理状态 unknown/stale |
| `meshd` 离线、agent 在线 | 可查询原因并执行受权 restart/reconcile |
| audit sink 中断 | 按显式 best-effort/required 模式处理并告警 |

Controller 高可用只保护产品 API 和事实源；不通过多 Controller 各自递增 policy epoch。
HA 实现必须使用单一事务事实源或明确 leader/consensus，MMP Gossip 不能替代 Controller
database consistency。

## 模块边界

目标内部模块保持小接口和 opaque ownership：

| module | 职责 | 不负责 |
|--------|------|--------|
| identity verifier | certificate、binding、expiry、revocation | OIDC、UI、database |
| policy parser adapter | JSON/TOML 到 typed document | 授权 decision |
| policy compiler | selector snapshot 到 compiled tables/tests | network I/O、持久化 |
| policy store | current/staged immutable bundle | packet evaluation |
| policy evaluator | packet/route/management decision | 日志格式、Controller API |
| MMP adapter | signed bundle/command transport | policy semantic merge |
| outbound sync adapter | agent 发起的 mTLS H2/RFC 8441 session、HELLO/cursor/reconnect | desired/observed 事实源、provider 执行、隐式协议降级 |
| Iris control adapter | H1/H2 WebSocket frame、mTLS、MMP admission | replay commit、desired state、provider 调用 |
| Iris status adapter | mTLS H1/H2 generation page 与 cursor event 查询 | Controller 汇总、持久化、signed audit artifact |
| bounded control channel | callback 到 owner 的 payload ownership transfer | 业务状态、重试、持久化 |
| control domain owner | replay、intent、desired/observed、operation/event | socket 生命周期、Controller database |
| function policy | grant/local policy/runtime availability/provider ID 求交 | provider 生命周期、远程 shell |
| function reconciler | 有界 operation、provider strategy、backpressure、completion、shutdown drain | 任意动态加载、宿主路径/argv、网络授权扩大 |
| FlowMQ meshd adapter | `MeshNodeIPC/1`、ROUTER/DEALER mTLS、exact identity、有界 ownership transfer、route fencing、result ACK/reconnect | desired 事实源、直接修改 Mesh 状态、把 delivery 当 durable commit |
| 后续 observation/telemetry adapter | 独立容量、snapshot/gap 或 sampling 语义；须按独立 FlowMQ public API 另行设计 | command/result、唯一 audit copy、packet/file/media bytes |
| 后续 worker dispatcher | durable claim、隔离 identity/credit/lease、route fencing、durable settlement | Grant 扩权、artifact bytes、volatile side-effect fallback |
| audit sink adapter | bounded event export | packet allow/deny decision |

policy compiler 和 evaluator 共享版本化 typed schema，不共享可变 map。平台、storage、HTTP
和 crypto 通过薄 ops/adapter 注入；不使用全局 service locator。所有 create 有对应 destroy，
compile/apply 返回结构化 Result，snapshot 所有权与 owner-loop 约束必须写入 API 文档。

## 错误语义

| code | 用户含义 |
|------|----------|
| INVALID_DOCUMENT | schema、类型或字段格式错误 |
| UNKNOWN_SELECTOR | user/group/tag/node/service 不存在 |
| EMPTY_SELECTOR | selector 意外解析为空 |
| POLICY_TEST_FAILED | 内置 policy test 与期望不符 |
| EPOCH_CONFLICT | base epoch 已过期，需重新 diff |
| APPROVAL_REQUIRED | device 尚未批准 |
| CERTIFICATE_EXPIRED | node/operator certificate 过期 |
| REVOKED | device/key 已撤销 |
| PERMISSION_DENIED | product role 或 Mesh capability 不满足 |
| RUNTIME_UNAVAILABLE | 已识别 runtime 未在本节点启用；不能自动换用另一 runtime |
| RESOURCE_EXHAUSTED | frame、queue、retained bytes、operation 或 event 容量达到硬上限 |
| CURSOR_CONFLICT | event cursor 已落后 retention，必须重新取得完整 snapshot |
| UNKNOWN_COMMIT | 连接在提交边界断开；先按 request ID 查询，禁止盲重试 |
| PROVIDER_UNAVAILABLE | 本地 provider/worker/`meshd` IPC 暂不可用；保留同 operation ID 等待 reconcile |
| FENCED | `meshd` incarnation、operation binding 或执行 fencing token 已过期 |
| SHUTTING_DOWN | 本地 adapter 已停止 admission；不得把未开始操作报告为成功 |
| PARTIAL_ROLLOUT | bundle 已发布但部分节点拒绝/未确认 |
| STALE_ENFORCEMENT | 节点 policy/revoke epoch 落后 |
| AUDIT_UNAVAILABLE | required audit 无法安全接受新 flow/action |
| CONTROLLER_UNAVAILABLE | 事实源不可达；不自动切换到本地写入 |

错误必须携带 operation、stage、target、current/expected epoch 和 correlation ID。UI 可以翻译
文案，但 stable code 是自动化和测试契约。

## 迁移与兼容性

### 影响

- 现有 `mesh_config_t` 和静态测试继续保留，默认属于 compat profile。
- production policy 引入新 signed bundle、policy epoch、decision reason 和 status surface。
- agent 需要 secure storage、enrollment certificate、revocation cache 和 applied-epoch journal。
- Controller 是新部署单元，但不进入数据路径；数据面仍可在 Controller 短时不可用时运行。
- user/group/OIDC/HTTP/database 类型不会进入 Mesh public header。
- 内部 MMP `CONTROL_FRAME (0x60)` 是 additive experimental kind；旧节点不会获得该
  capability，公开前必须增加 feature negotiation、版本兼容矩阵与 wire golden vectors。
- H1/H2/WS 与 control core 之间只传 transport-neutral typed envelope；更换 HTTP adapter 不得
  改变 desired/observed、幂等、权限或错误语义。
- `meshd` 本地 IPC 是可选 `FlowMQ::FlowMQ` adapter，Mesh control core public header 不暴露 FlowMQ
  type。production profile 只使用显式 loopback TLS 1.3/mTLS，要求双方证书验证、exact FlowMQ identity 和
  typed Mesh authorization。独立 FlowMQ 已提供 ROUTER/BIND 与 CONNECT 双向 verifier，adapter 强制
  current/next fingerprint exact map；独立 server/client leaf、真实 overlap/old-pin-removal、双向 EKU、
  进程边界往返和 listener restart 重认证已覆盖，显式 client config 禁用 session cache。远程 H2
  agent runtime 已实现 client leaf reload、certificate/HELLO binding 和在线 session fencing；
  `mesh-agent` 已把独立 client leaf 和 exact meshd identity/pin 配置接入 Network provider。生产
  签发/平台 keystore、FlowMQ 本地通道无停机自动换证、发布级 service-manager 与审计继续按
  [`FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md`](FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md) 执行，是剩余 production gate；
  不得自动降级到 Pipe/plain transport。

### 实施阶段

1. **P0 事实基线（已完成）**：permissive-empty、ordered first-match、peer CIDR/node-id/
   protocol-major admission、learned-route rejection，以及 local egress 的目的 CIDR、认证源
   CIDR 和源地址防冒充回归均已固化。所有 array/count 配置对也会在负数 count 或正数
   count 配 NULL array 时 fail fast，避免安全策略因配置不完整退回空策略。
2. **P1 identity core（核心组件与服务入口已实现，产品接线未完成）**：certificate lifecycle、current/next、
   revoke、identity registry、agent outbound H2 typed sync、Controller durable outbox/session 和在线
   fencing 已有组件测试。剩余 machine enrollment/continuity、平台 keystore、公开 capability negotiation、
   `mesh-agent`/`mesh-controller` 发布二进制已可构建；剩余 machine enrollment/continuity、平台
   keystore、service-manager、Controller 数据库和主动 observation/audit 通道。完成前保持
   internal/experimental。
3. **P2 read-only inventory**：Controller/CLI 展示 device 五维状态、key/policy epoch、path、
   address lease 和 DNS epoch。
4. **P3 network/IPAM/MagicDNS**：先接入 IPv4 signed snapshot 与 split-DNS，再以 additive v2
   API 引入 IPv6 A/AAAA/PTR；静态 MagicDNS 保持 compat。
5. **P4 policy compiler**：typed Grants、selector resolution、static analysis、policy tests 和
   shadow decision；不改变 packet action。
6. **P5 production enforcement**：显式 production profile、atomic snapshot、default deny、
   signed rollout/rollback 和 lag 状态。
7. **P6 audit closure**：configuration/identity/management/flow/security event、external sink、
   canary-secret 和 spool failure tests。
8. **P7 route/exit product**：advertise/use/admin 三权分离、quorum、kill-switch 和多出口状态。
9. **P8 UI/GitOps**：approval、policy diff/test、audit search、API tokens/workload identity。
10. **P9 node function providers 与 meshd IPC（执行边界已完成，生产部署仍未完成）**：当前已有 typed
    document、provider registry、bounded reconcile/backpressure、signed-intent/result WAL、authenticated
    checkpoint/compact、queryable durable receipt、provider completion peek/apply/ack、shutdown drain 与
    restart reconcile。独立 FlowMQ ROUTER/DEALER adapter、client/server runtime 和 prestaged
    builtin/Native provider 已有同进程真实 mTLS 测试；CONNECT/ROUTER 对称 certificate-to-identity hook、
    Mesh 强制 profile、`meshd` 默认关闭的严格配置、`mesh-agent` Network provider 接线和 declarative
    Network APPLY/DELETE/重启 restore 已完成组件验证；
    远程 agent runtime、证书 lifecycle、Controller outbox/session/fencing 也已实现。derived observation、sampled
    telemetry 与 durable release-transfer worker 按独立
    FlowMQ 当时公开 API 另行设计。prestaged Native 和 TurboWASM out-of-process worker 已实现 digest
    binding、bounded I/O、timeout 和 process-tree cleanup；`RUN_NATIVE`/`RUN_WASM` 与管理权限分离并默认关闭。
11. **P10 third-party WASM（production rollout 推后）**：已有 authenticated TurboWASM child worker；
    product Grant authority、preopen/network capability policy、低权限 OS sandbox profile、取消/恢复、
    审计和跨平台安全回归全部满足后才对第三方开放 `RUN_WASM`。

每阶段通过 feature/capability 和 profile 显式启用。不能从 production 自动回退到 compat；
回滚通过新 epoch 发布已验证的旧语义 bundle。

部署层回滚遵循阶段边界：P1-P3 可停用 Controller/agent 新 feature 并保留现有 compat 配置；
P4 production enforcement 启用后，只能用更高 epoch 的签名 bundle 回滚策略。若要卸载 agent
或退回 compat，必须由本机管理员显式迁移配置、撤销 production enrollment 并验证不会把
default-deny 静默变成 permissive；不能由远程失败路径自动完成。

## 验证范围

### Identity 与 key

- private/traffic key 从不出现在 wire capture、日志、status、crash dump 和 audit export。
- new device pending/approve/reject、single-use token replay、old/new key proof 和 lost-key reenroll。
- expiry、revoke、issuer rotation、node epoch、partition/heal 和 selective descriptor distribution。
- 仅 Controller API 被攻陷而隔离 signer policy 未被攻陷时，不能注入有效 node descriptor；
  issuer compromise 按明确的高风险恢复流程测试。
- replay window、session epoch、path rebuild 和 relay 不可读取端到端 payload。

### Policy

- JSON schema、unknown field、循环 group、empty selector、duplicate ID 和容量上限。
- default deny、direction、protocol/port、CIDR、service、via、advertise/use/admin separation。
- guardrail 始终优先；rule reordering 不改变 Grants 语义。
- policy unit tests、shadow/active decision diff、staged rollout、partial failure 和 rollback epoch。
- compat profile 保持现有测试结果；production 缺 policy 启动失败。

### Controller 与 API

- OIDC role mapping、step-up、API idempotency、If-Match/base epoch 和 concurrent mutation。
- Controller restart/HA leader change 不重复 epoch、command 或 audit event。
- Controller outage 不影响既有数据转发；新 enrollment/mutation 明确失败。
- device view 不混淆 enrollment、liveness、service、policy 和 path 状态。

### Control transport 与 owner core

- H1 RFC 6455 和 H2 RFC 8441 走同一路由；plaintext、无 client certificate、错误证书 binding、
  text frame、超长 frame、坏签名、错误 target 和过期消息全部 fail closed。
- 在 queue entry、retained bytes、payload、operation 或 event 任一容量达到上限时返回稳定错误，
  不提交 replay，不推进 desired epoch；释放容量后原 request 可以安全重试。
- 同一 request ID/同一业务 intent 返回原 operation；相同 message ID 重放拒绝；断开时通过 event
  cursor 续取，cursor 过旧要求 full snapshot。
- 对每种 intent 注入 enqueue 前后、desired submit 前后、replay commit 前后、ACK 前后崩溃，验证
  不会出现已确认但未记录的状态，也不会因 retry 重复执行。
- shutdown 覆盖 active callback、queue full producer、queued unstarted command、pending owner、
  listener close 和 CoroNet managed-task drain；ASan/TSan 下无 UAF、double-free 或 retained payload。
- `meshd` IPC 使用真实 FlowMQ ROUTER/DEALER mTLS 覆盖 HELLO、COMMAND、ACCEPTED、RESULT、ACK_RESULT、
  QUERY/STATUS、DRAIN，验证 frame/item/byte HWM、borrowed callback copy、operation dedupe、epoch
  fencing、双方 crash/restart、断线 unknown-commit 查询和 exact result ACK。
- `已覆盖`：loopback-only bind、独立 server/client certificate、SAN、CA、exact HELLO identity、双向
  EKU 角色错配、真实 rotation overlap、old pin 移除后的新连接拒绝和无 session-resumption 的 restart
  重认证；仍需存量 old-leaf session 主动 fencing、生产吊销和跨 node 冒充测试。
  未授权本地进程不能仅凭
  知道 endpoint port 就连接 privileged `meshd`，安全失败不能触发 Pipe/plain fallback。
- 现有组件测试覆盖 ingress、本地 state machine、真实 mTLS H1 status/event/receipt 拉取、权限拒绝、
  精确 Native provider admission、provider backpressure、APPLY/DELETE completion、signed-intent/result
  WAL、authenticated checkpoint/compact、错误密钥/篡改、provider completion 的 WAL-before-ACK、stop
  drain、checkpoint/index mismatch 拒绝、checkpoint atomic-replace 失败后保留 WAL 和 restart recovery；
  产品验收仍须增加 Controller 汇总、WAL 各系统调用点
  fault injection、FlowMQ `meshd` IPC 和真实
  out-of-process provider 故障集成测试。

### Audit

- actor/target/before-after/policy epoch/reason/correlation 可查询且完整。
- duplicate、乱序、clock skew、segment rotation、checkpoint、collector outage 和 disk full。
- 日志/状态测试植入 canary secret，断言所有 sink 不包含 secret/payload/session key。
- audit 开关前后测量 packet path p50/p95/p99、CPU、内存和 dropped-event counter。

### 跨区验收

- eu/bj/sh/local enrollment、批准、rotation、revoke 和 partition/heal。
- 只向允许通信的节点下发 descriptor；relay 无业务 plaintext。
- policy 发布显示每节点 applied epoch；离线节点恢复后先收敛 revoke/policy 再接收新 flow。
- eu 作为 management relay 不自动成为 exit；exit advertise/use 分别批准。
- 停止 `meshd` 后 agent 仍可查询并恢复；远程不能停止 agent 自身。

## 产品完成条件

只有同时满足以下条件，才能从“Mesh library”称为“可管理的安全网络产品”：

- 用户无需手工交换 key、编辑 peer 列表或逐台 SSH。
- private key 永不离开设备，public descriptor 有授权签名、scope、epoch、expiry 和 revoke。
- production 无有效 policy 时 default deny，compat 行为不会被静默带入 production。
- policy 可以 validate、test、diff、原子发布、查看 lag 并用新 epoch 回滚。
- subnet/exit 的 advertise、use 和 administer 权限相互独立。
- configuration 与 flow audit 可关联 actor、rule、policy/path epoch 和稳定 reason。
- Controller 故障不成为数据面瓶颈，管理分区不会伪造全局同步成功。
- 所有高风险状态都能在 UI/API/CLI 中区分事实、检测结果和未知状态。

## 一手资料

- [RFC 6455 — The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455)：HTTP/1.1
  WebSocket framing、close 和安全要求。
- [RFC 8441 — Bootstrapping WebSockets with HTTP/2](https://www.rfc-editor.org/rfc/rfc8441)：
  HTTP/2 extended CONNECT 与 WebSocket 协商边界。
- [Tailscale control and data planes](https://tailscale.com/docs/concepts/control-data-planes)：
  集中协调与节点本地数据面的产品边界参考。
- [Tailscale node keys](https://tailscale.com/docs/concepts/node-keys)：device/node key 分层、
  public-key distribution 和 rotation 参考。
- [Tailscale Tailnet Lock](https://tailscale.com/docs/features/tailnet-lock)：节点侧验证受信
  signer 对 node key 的授权参考。
- [Tailscale access control](https://tailscale.com/docs/features/access-control)：声明式、
  direction-aware、device-local enforcement 参考。
- [Tailscale configuration audit logging](https://tailscale.com/docs/features/logging/audit-logging)
  与 [network flow logs](https://tailscale.com/docs/features/logging/network-flow-logs)：配置审计
  与不记录 payload 的 flow metadata 参考。

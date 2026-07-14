# Mesh 业务网络平台设计

## 文档状态

本文件定义 Mesh 作为通用业务网络底座的目标架构、边界与迁移顺序。
它不宣称目标能力已经实现；当前实现与验证状态仍以
[`MESH_STATUS.md`](MESH_STATUS.md) 为准，现有协议细节以
[`MESH_DESIGN.md`](MESH_DESIGN.md) 为准。

## 决策摘要

Mesh 是业务连接的统一事实源，但不是业务协议实现。

- 现有 IP 业务默认通过 TUN 接入，不要求业务链接 TurboP2P。
- 需要明确 datagram、stream、截止时间或背压语义的嵌入式业务，使用后续增加的原生 flow 接口。
- TurboMedia 继续拥有采集、编解码、RTP/RTCP、复用与媒体时钟；Mesh 只提供可验证的网络路径。
- `meshd` 拥有 TUN、OS 路由、权限和服务生命周期；`mesh` 库拥有身份、策略、路径和转发状态。
- Exit node 是显式、可撤销的部署 profile；`0.0.0.0/0` 路由本身不授予出口权限。
- 路径切换只有在传输语义兼容时才能自动发生。datagram 不得静默降级为可靠字节流。
- 所有数据路径必须绑定已认证节点身份并提供机密性、完整性和重放保护。

这个方向复用当前已经存在的 `TUNNEL_MODE_PACKET`、`mesh_send_packet()`、
`on_packet_received`、ICE selected-pair 和 P2P 控制连接，不再创建第二套 TUN
或第二套 socket 后端。

## 背景与证据

当前仓库已经具备以下基础：

- `mesh_vpn` 和 `meshd` 已实现 `TUN -> mesh` 与 `mesh -> TUN` 的双向桥接。
- `mesh_send_packet()` 已按虚拟 IP、直连、学习路由和固定路由选择下一跳。
- 直接认证的 peer 可通过 `TurboNet::Ice` selected pair 发送原始 IP 包。
- selected pair 不可用时，当前实现会回退到 `p2p_send()` 的可靠 stream。
- `TurboNet::CoroNet` 已提供 stream、datagram、scatter-gather 和 arena send buffer，
  因此 Mesh 不应新增平台 socket 抽象。
- TurboMedia 已分离 Core、Codec、Muxer、Demuxer、Transport、Device 和 WebRTC
  目标，可作为 Mesh 上层消费者。

这些事实说明 TUN 路线已经可用于通用 IP 兼容，但当前 fallback、安全封装、
MTU、QoS 和服务发现还不足以形成通用业务平台。

## 目标与非目标

### 目标

- 让 HTTP、数据库、RPC、文件、游戏、设备和媒体等 IP 业务无需专用适配即可互通。
- 让低延迟或高吞吐业务能够显式选择传输语义，而不是猜测当前路径能力。
- 统一节点身份、路径状态、策略、服务发现和诊断事实源。
- 保持现有 `TurboP2P::P2P`、`TurboP2P::Mesh` 与 TUN 用户行为兼容。
- 所有队列、路由、服务记录和重放窗口都有明确容量与失效规则。

### 非目标

- Mesh 不解析媒体帧、HTTP、数据库或其他业务协议。
- Mesh 不替代 TurboMedia 的 RTP/RTCP、WebRTC、codec 或拥塞算法。
- Mesh 不为不同语义的 transport 提供隐式 fallback。
- Mesh core 不安装 OS 路由、修改防火墙或管理系统服务。
- 第一阶段不把控制器、计费、用户目录或业务编排塞进 `mesh_network_t`。

## 候选方案

| 方案 | 优点 | 主要问题 | 结论 |
|------|------|----------|------|
| 只有 TUN | 所有 IP 应用零改动 | 无法表达截止时间、可靠性和队列策略 | 保留为默认兼容入口 |
| 只有原生 SDK | 可精确控制性能和语义 | 每个业务都要适配，平台耦合高 | 不作为默认入口 |
| 每个业务自建 ICE/连接 | 业务自治 | 重复 NAT 穿透、身份和策略，状态冲突 | 除协议强制场景外不采用 |
| TUN + 原生 flow 双入口 | 兼容现有应用，并为高性能业务提供显式语义 | 需要统一路径管理和安全封装 | 采用 |

WebRTC 是协议强制的例外。浏览器互通时由 TurboMedia WebRTC 会话拥有其 ICE；
Mesh 可提供身份、发现和信令可达性，但不在 WebRTC ICE 外再套一层 Mesh ICE。
非浏览器 RTP/RTSP 或普通 UDP/TCP 默认走 TUN。

## 总体架构

```text
┌──────────────────────────────────────────────────────────────┐
│ 业务层                                                       │
│ TurboMedia │ HTTP/RPC │ DB │ 文件 │ 游戏 │ 设备 │ 自定义协议 │
└───────────────┬───────────────────────────────┬──────────────┘
                │ 标准 IP socket                │ 原生 flow
                ▼                               ▼
┌───────────────────────────┐   ┌──────────────────────────────┐
│ OS 路由 + TUN packet plane│   │ Mesh stream/datagram plane  │
└───────────────┬───────────┘   └──────────────┬───────────────┘
                └───────────────┬──────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ Mesh data plane                                              │
│ 安全封装 │ MTU │ 有界队列 │ traffic class │ 转发 │ path send │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ Mesh control plane                                           │
│ 身份 │ peer │ capability │ policy │ route │ path │ service   │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ TurboNet                                                     │
│ Ice selected pair / TURN │ CoroNet datagram │ CoroNet stream│
└──────────────────────────────────────────────────────────────┘
```

## 分层职责

### 1. 运行与平台层：`meshd` + `tunnel`

`meshd` 是每台主机的唯一 privileged owner：

- 创建和销毁 TUN。
- 安装虚拟网段路由、DNS/search domain、必要的 NAT 和防火墙规则。
- 读取配置、启动 Mesh、导出状态、处理系统信号。
- 启动完成后按平台能力降低权限；私钥与配置文件保持最小权限。
- OS 配置失败时回滚本次已应用的副作用，不能留下半配置路由。

`tunnel` 在此模式只做 packet bridge。Proxy session、FakeDNS 和轻量 TCP/IP
stack 不进入 Mesh packet 热路径。

### 2. Mesh control plane

控制面只维护连接决策需要的事实：

- 节点身份和认证 peer。
- capability 协商与协议版本。
- 直连、relay、固定路由和本地 egress 可达性。
- 编译后的不可变 policy snapshot。
- 服务记录及其 TTL、版本和签名状态。
- path 状态、最近错误和可用传输语义。

控制消息走已认证可靠通道。路由控制消息在缺少端到端 origin
authentication 和 replay protection 时继续 fail closed。

### 3. Mesh data plane

数据面接收两类输入：

- packet：来自 TUN 的完整 IP 包。
- flow：来自原生 stream/datagram API 的业务 payload。

二者共享身份、策略、路径和安全事实源，但不共享会改变语义的发送队列。
packet、realtime datagram、interactive stream 和 bulk stream 使用独立有界队列。

### 4. 业务适配层

标准 IP 业务不需要适配层。只有需要使用原生 flow 的库才提供薄 adapter，
adapter 只做地址/错误/所有权映射，不把业务状态放进 Mesh。

TurboMedia adapter 应位于 TurboMedia 或独立 integration target，依赖方向为：

```text
TurboMedia P2P adapter -> TurboMedia components + TurboP2P::Mesh
```

`TurboP2P::Mesh` 不依赖 TurboMedia，也不在公开头文件暴露媒体类型。

## 单一事实源

| 状态 | 唯一 owner | 派生视图 |
|------|------------|----------|
| 节点身份 | P2P authenticated peer/session | peer info、日志、服务记录主体 |
| 本地策略 | `mesh_network_t` immutable policy snapshot | peer flags、route eligibility、诊断 |
| 路由 | route manager，按 direct/learned/pinned/local-egress 分类 | 下一跳快照、状态 JSON |
| 路径 | path manager | active path、RTT、MTU、capability |
| 服务 | signed service registry | MagicDNS、resolve cache |
| TUN/OS 副作用 | `meshd` platform runtime | status JSON |
| 媒体 track/frame | TurboMedia | RTP packet、统计 |

缓存只从上述事实源重建或失效，不允许 peer、route、daemon 各自推进同一状态。

## Path contract

每条可用路径必须发布能力快照，而不是仅报告“connected”：

- path kind：direct ICE、TURN datagram、relay stream。
- payload kind：packet、datagram、stream。
- reliability 和 ordering。
- authenticated 和 encrypted。
- effective MTU。
- 当前 RTT、loss、queued bytes 和最近错误。
- path epoch；切换路径或重建安全会话时递增。

发送请求声明最低需求：

- payload kind。
- traffic class。
- 是否允许可靠、有序传输。
- 是否允许 relay。
- deadline；零表示没有截止时间。
- 最大 payload 或期望 MTU。

选择器只可选择满足所有最低需求的路径。没有匹配路径时返回明确错误；
它不能把 realtime datagram 转成 stream，也不能忽略 encryption requirement。

当前 `mesh_send_to_peer()` 的 stream fallback 可以继续服务兼容 packet/bulk 流量，
但 realtime 规则必须配置成 datagram-required。路径变化通过事件和状态快照暴露，
不得只写日志。

## 动态最优路径选择

可以动态选择路径，但“最短”定义为满足安全、policy 和 transport 语义后的最低综合
cost，不等于最少 hop。选择分为两层：route manager 选择 destination 的 next hop，
path manager 再选择到该 next hop 的 direct ICE、TURN 或 relay transport。二者共享
不可变 path/route snapshot，但不重复维护连接状态。

### 当前边界与候选算法

当前 learned route 每个 destination 只保存一个 next hop，收到更少 hop 的公告才替换；
发送顺序是 pinned policy、direct peer、learned route。该行为简单可预测，但不能：

- 保留 eu/bj/sh 多个同目的候选。
- 在相同 hop 下按 RTT、loss、queue 或稳定性选择。
- 在当前路径恶化但尚未断开时切换。
- 用迟滞防止两个相近路径反复抖动。

候选方案：

| 方案 | 控制面成本 | 环路/收敛 | 结论 |
|------|------------|-----------|------|
| 继续单路 hop-count | 最低 | 只能粗粒度择路 | 保留为兼容基线 |
| 全量 link-state + Dijkstra | topology flood；重算约 `O(E log V)` | 全局视图，复杂度较高 | 规模证据出现后再评估 |
| 增强 distance-vector | 只传播选中 route；增量 `O(K)` | 需要 sequence/feasibility | 第一阶段采用 |
| 逐包 ECMP | 数据面复杂、易乱序 | 对 TCP/QUIC/RTP 不友好 | 第一阶段不采用 |

第一阶段采用受 [RFC 8966 Babel](https://datatracker.ietf.org/doc/html/rfc8966) 启发的
loop-avoiding distance-vector，但不宣称 wire-compatible Babel。若要宣称兼容，必须完整
实现并通过独立 interoperability 测试，不能只借用部分术语。

### 优化问题定义

路径选择本质上是带硬约束、多个目标、随时间变化的在线优化问题，不是单一 `min(RTT)`。
对 flow `f` 在时刻 `t`，先从候选路径集合 `P(f,t)` 构造可行域：

```text
F(f,t) = { p in P(f,t) |
           identity/authentication valid
           and policy permits origin/destination/exit
           and route is finite, feasible and fresh
           and transport semantics satisfy flow requirements
           and effective_mtu >= payload_requirement
           and capacity/resource limits are not exhausted }
```

若 `F(f,t)` 为空，返回明确 `path unavailable`，不能通过给安全失败一个较高 penalty 后
继续发送。安全、授权、地域、费用上限、审计模式和 datagram/stream 语义都是 constraint；
只有性能偏好才进入 objective。

在可行域内采用分层目标，而不是把不同量纲无界相加：

```text
p* = lexicographic_argmin p in F(f,t) (
       SLA_violation(p),
       trust_preference(p),
       normalized_QoE_cost(p),
       congestion_cost(p),
       switching_cost(current, p),
       deterministic_tie_break(p))
```

- `SLA_violation` 优先保证 deadline、loss、jitter 和最低吞吐门槛；均满足时才比较后续目标。
- trust tier 只能在 policy 已允许的集合中排序，不能让未授权 relay/exit 参与 Pareto 比较。
- QoE 指标按 profile 声明的 budget 归一化、截断为有界 fixed-point；unknown 按 profile
  明确设为 ineligible 或保守上界，不能默认零成本。
- switching cost 表达连接迁移、乱序、重放窗口和拥塞控制重启成本，是迟滞的优化表达。
- 最后使用稳定 candidate/node ID 决定相等分数，保证不同运行次数可复验。

不同 traffic class 的本地目标不同：

| Profile | Hard constraints | 主要优化目标 |
|---------|------------------|--------------|
| control | authenticated、reliable、保留容量 | 稳定性、可达性、低切换率 |
| realtime | datagram、deadline、MTU、最低带宽 | loss/jitter/latency，然后切换成本 |
| interactive | 语义兼容、MTU | SRTT/RTTVAR、queue delay、稳定性 |
| bulk | reliable、最低带宽、背压 | bottleneck throughput、拥塞与费用 |
| exit | permitted exit、地域/审计/安全 profile | SLA、信任偏好、延迟和运营费用 |

分布式 route protocol 与本地优化器需要分清：route announcement 只能传播满足代数约束的
有界 additive metric，以保持 feasibility 和收敛；MTU、bottleneck bandwidth、trust tier
和 transport kind 等非可加属性作为 capability/constraint 单独传播。本地 selector 可在
多个 finite/feasible route 中做 lexicographic/Pareto 选择，但不能把不可加量伪装成链路
加和后仍宣称“全局最短”。

第一阶段每个 flow 只选一条路径，因此枚举有界候选集即可，时间 `O(K)`，不需要通用
数学规划器。若未来同时给大量 flow 分配多条路径并约束共享链路容量，问题会升级为
multi-commodity traffic engineering；应作为独立阶段，以 profiling、拓扑规模和业务收益
证明必要性，不能提前塞进 packet plane。

优化器是反馈控制而非一次求解：周期采样、更新 immutable snapshot、重新评估候选，
并通过平滑、minimum dwell、switch quota 和 make-before-break 抑制测量噪声。验证时保存
eu/bj/sh/local 的 metric trace，离线回放比较当前策略、hop-count 基线和“事后最优”路径的
SLA violation、objective cost、切换次数与故障恢复时间；没有实测数据前不声称权重最优。

### 状态模型与单一事实源

route manager 对每个 `(origin node ID, destination prefix)` 维护有界候选集：

```text
route candidate
  origin + prefix
  next-hop authenticated node ID
  origin sequence
  advertised metric + local link cost = total metric
  instantaneous metric + smoothed metric
  hop count + capability/security flags
  last update + expiry + feasible state

selected route snapshot
  candidate ID + route epoch + selection reason
```

- origin sequence 只能由 destination origin 增加，使用定义明确的 wrap-safe serial
  arithmetic；中间节点原样传播。
- feasibility distance 按 origin/prefix 保存。候选只有在 sequence 更新，或同 sequence
  下 advertised metric 满足 feasibility condition 时才可参与选择。
- retraction 使用 infinite metric，并保留一个有界 hold/expiry 周期，防止旧公告立即复活。
- hop count 继续有硬上限并作为诊断/tie-breaker，但不再是唯一 cost。
- 每 destination 的候选数 `K`、总 destination 数、公告大小和过期时间都有配置上限。
- pinned route 仍属于 operator intent，优先于动态候选；pinned next hop 不可用时继续
  fail closed，不自动改写为动态路径。

默认路由可能由多个 exit origin 发布。每个 `(exit node ID, 0.0.0.0/0)` 是独立 source，
只有显式进入 permitted exit set 且满足身份、地域、费用、审计和安全 profile 的 origin
才能参与动态选择；网络 metric 不能把未授权出口变成“最佳出口”。

### Link metric

所有 hard requirements 先过滤，再计算 cost：

- authenticated/encrypted 与 secure-envelope capability。
- payload kind、reliability/ordering、MTU 和 deadline。
- peer/packet/exit policy 与 route freshness/feasibility。
- path ready 且 next hop 仍为同一个 authenticated identity。

对可用候选使用有界、正值、可加的 fixed-point metric：

```text
link_cost = transport_base
          + weighted_srtt
          + weighted_rttvar
          + weighted_loss
          + weighted_queue_delay
          + instability_penalty

route_metric = saturating_add(link_cost, neighbour_advertised_metric)
```

- RTT probe 使用 monotonic clock；SRTT/RTTVAR 可按
  [RFC 6298](https://datatracker.ietf.org/doc/html/rfc6298) 的平滑形式更新。
- loss 来自带 sequence 的低频 authenticated probe history，不能只依据应用层空闲期间
  “没有收到包”。
- queue delay 从有界 queued bytes 与 pacing rate 推导；无法计算时标为 unknown，不能
  偷偷当作零。
- bandwidth 是路径 bottleneck，不是简单可加量；第一阶段作为最低 capability/eligibility，
  不直接混入 additive route metric。
- transport base、权重、最大 penalty 和 infinity 都命名、可配置并做 checked/saturating
  arithmetic；任何负值、NaN、溢出或越界公告直接拒绝。

第一阶段只发布一个通用 network metric。traffic class 可以在本地 path selector 选择
满足需求的 transport，但不为 realtime/bulk 各自传播一套未经验证的分布式 route。
如果未来需要 class-specific multihop routing，应把 class/topology ID 纳入独立 route
实例和 capability，分别验证环路与收敛。

### 测量来源

每个直接 neighbour/path 由 Mesh owner loop 驱动低频 probe/ack，得到 directional RTT、
loss、freshness 和 effective MTU；应用流量统计只补充观察，不作为唯一存活证据。probe
在 secure envelope 内认证、限速、带 replay protection，攻击者不能通过伪造 ICMP 或
回显 timestamp 降低自己的 cost。

当前 TurboNet::Ice public API 可读取 state 和 selected pair endpoint，但没有 RTT/loss
snapshot。因此第一阶段可由 Mesh 测量 selected path；若要让 ICE 统一拥有 candidate-pair
质量，应另行设计 additive、只读、版本化的 Ice metrics API，并在修改 TurboNet public
API 前单独审批。Mesh 不读取 Ice 私有结构，也不复制其 candidate 状态机。

probe、metric 更新、candidate expiry 和 route selection 都在 CoroNet owner loop 定时器
中执行。跨线程配置通过 `coro_post()` 投递，不增加 route 锁；shutdown 先停止 probe 和
triggered update，再清理 candidate/snapshot，不能让 timer 持有已销毁 peer/ICE agent。

### 选择、迟滞与切换

选择器只从 finite、feasible、fresh 且满足 hard requirements 的候选中选最低 metric。
sequence 只判断 feasibility/freshness，不作为“越新越优”的分数，避免 sequence 传播
期间产生抖动。

正常优化切换遵循双重迟滞：候选的 instantaneous metric 和 smoothed metric 都优于当前
路径，并持续通过可配置观察窗口后才切换；还要满足 minimum dwell time 和 switch-rate
quota。当前路径 hard-fail、身份失效或不再满足 MTU/transport/security 时立即切换到最佳
feasible alternate，不等待优化迟滞。

切换采用 make-before-break：

1. 建立并认证候选 path，确认 MTU 与 capability。
2. 原子发布新的 selected snapshot 和递增 route/path epoch。
3. 新 flow 使用新路径；已有 flow 保持 sticky，直到结束或旧路径 hard-fail。
4. 有界 drain 后释放旧 path；失败则保留旧 snapshot 或报告 path unavailable。

TUN flow key 默认使用 direction + 五元组；ICMP/无端口协议使用稳定 packet tuple。flow
cache 有容量、idle TTL 和 eviction 语义。不能按 packet 重新评分，否则会造成乱序、
重放窗口误判和拥塞反馈振荡。realtime datagram 可在 hard failure 时切 epoch 换路；接收端
按 epoch/sequence 处理有界乱序，不能把旧路径包注入新 epoch。

### 安全与错误语义

authenticated route update 仍可能来自已受控或故障节点，因此：

- origin、sequence、metric、expiry、capability 和 prefix 必须进入认证范围并防 replay。
- 每一跳只接受已认证 neighbour，限制 metric 改变量、更新频率、prefix 数和 sequence
  request，防止 metric poisoning 与 control-plane DoS。
- Sybil/未知 identity 不进入候选表；exit/relay trust tier 是 hard policy，不是可被低 RTT
  抵消的 penalty。
- 下一跳不得把自己的 identity/virtual IP 作为 origin 路径中的循环依赖；feasibility、
  split horizon/retraction 和 hop limit 都必须有故障注入测试。
- 当前候选全部不可行时返回 `path unavailable`。不得选 infinite/unfeasible route，
  不得绕过 pinned 或安全要求，也不得回退到本地公网。

metric 不可信或 probe 状态 unknown 时选择稳定的已验证路径或 fail closed，具体由 profile
显式声明。它不能静默赋予 unknown 最优 cost。

### 性能与可观测性

每个受影响 destination 的 candidate 更新和选择为 `O(K)`，空间为 `O(D*K)`；`D` 和 `K`
均有硬上限。packet/flow send 只读取 selected snapshot，保持均摊 `O(1)`，不在热路径
排序、分配、复制字符串、写日志或执行浮点复杂函数。triggered updates 合并并限速，周期
full update 有大小上限。

状态必须显示所有候选的 origin/next hop、instant/smoothed metric、SRTT/RTTVAR、loss、
queue、expiry、feasible/eligible 状态，以及 selected candidate、epoch、switch reason、
hysteresis suppression 和 hard-fail count。热路径只累计计数，切换事件在状态消费边界记录
一次。

实现前先以 observe-only 计算 metric，但保持现有 pinned/direct/learned 顺序；对 eu/bj/sh/
local 记录“现选路径”和“算法建议路径”。只有收敛、环路、抖动与性能数据达到门槛后，
才通过显式 opt-in 启用动态选择。将其设为默认会改变用户可见路由行为，必须另行审批。

## TUN packet plane

### 数据流

1. OS 根据虚拟网段路由把包写入 TUN。
2. `tunnel` packet callback 把完整 IP 包交给 `mesh_send_packet()`。
3. policy evaluator 检查方向、源/目的 CIDR、协议和端口。
4. route manager 返回固定、直接或学习到的下一跳。
5. path manager 选择满足该 packet class 的路径。
6. data plane 加安全 envelope 并发送。
7. 对端完成认证、重放、长度和 policy 检查后把 IP 包写回 TUN。

### MTU

当前 IPv4 Mesh profile 使用可配置的保守 MTU；初始默认建议为 1200，
但最终值由 underlay、TURN 和安全 envelope 开销验证决定。平台启动时应确保：

```text
TUN MTU <= selected path MTU - mesh envelope overhead
```

在 PMTU 可用前，超限包 fail fast 并增加可诊断计数；不在 Mesh 热路径实现
另一套透明 IP 分片。接收端仍可把合法的独立 IP fragment 交给 OS 重组。

### Traffic class

Mesh 不识别“视频”或“数据库”，只识别通用 traffic class：

| Class | 语义 | 排队策略 |
|-------|------|----------|
| control | 身份、path、route、policy | 小型保留队列，不被数据饿死 |
| realtime | 有截止时间的 datagram | 队列满或过期时丢弃旧包 |
| interactive | RPC、终端、小请求 | 有界低延迟队列 |
| bulk | 文件、备份、大响应 | 吞吐优先，有界背压 |
| background | 可延迟同步 | 最低权重 |

TUN 流量通过 DSCP 与可配置的五元组规则映射 class。TurboMedia 可设置 DSCP，
也可由 `meshd` 按 RTP/RTCP 端口规则分类。未匹配流量进入 interactive，
该默认值属于部署策略而不是硬编码协议语义。

## Exit node profile

Exit node 让受策略允许的 Mesh 节点通过一个远端节点访问非 Mesh 网段或公网。
它是 `meshd` 的显式部署 profile，不是 route manager 看到默认路由后的隐式行为。
第一版只支持 IPv4；IPv6 必须在路由、源地址验证、防火墙和无 NAT 转发语义均有
独立验证后再启用。

### 角色与数据流

生产拓扑应分离 bootstrap/relay 与 exit 职责。`eu` 可以继续作为 bootstrap/relay，
`bj` 或 `sh` 按部署策略成为 exit；控制节点不因可达而自动获得出口权限。

```text
client application
  -> client OS route/TUN
  -> mesh policy + fixed default route
  -> authenticated and encrypted Mesh path
  -> exit identity/source/destination policy
  -> exit TUN in isolated network namespace
  -> namespace route + nftables SNAT/MASQUERADE
  -> physical uplink -> Internet

Internet return packet
  -> namespace conntrack/NAT
  -> exit TUN
  -> authenticated Mesh route to client
  -> client TUN -> application
```

出口准入必须同时满足四个条件，任何一项缺失都 fail closed：

1. incoming peer 通过稳定节点身份认证并命中 node allowlist。
2. IP 包源地址等于该 authenticated peer 的 Mesh virtual IP，不能由声明字段替代认证事实。
3. 源地址命中 `local_egress_allow_cidrs`，目的地址命中 `local_egress_cidrs`。
4. `packet_policy` 的 `local-egress` 方向显式允许协议、目的 CIDR 和端口。

客户端使用 authoritative pinned route，例如 `0.0.0.0/0 -> exit virtual IP`。
固定出口不可用时发送返回明确错误，不得回退到本地物理默认路由或其他未授权节点。
第一阶段不做自动多出口 failover；后续只能通过签名 capability、健康状态和原子 route
epoch 切换实现，不能在数据包发送失败后临时猜测另一个出口。

### OS 隔离与 NAT 边界

Linux 首选为每个 exit 实例创建独立 network namespace，并把 TUN 与 Mesh egress
处理放入该 namespace。namespace 通过专用 veth/uplink 接入宿主机；IP forwarding、
conntrack、NAT 和 forward policy 尽量只作用于该 namespace，避免修改宿主机全局
forwarding，也避免与 Docker 管理的防火墙链共享所有权。

`meshd` 使用专属、带 instance ID 的 nftables table/chain，规则集原子提交：

- forward 默认拒绝，仅允许 authenticated Mesh 源 CIDR 到配置目的 CIDR。
- SNAT/MASQUERADE 只匹配 Mesh virtual source CIDR 和配置的 egress interface。
- 返回方向只允许 conntrack `established,related`。
- 默认不发布端口、不做 DNAT，也不接受公网主动入站。
- 禁止 flush 全局规则、修改 Docker chains 或要求停止 docker-compose。

Mesh core 不拥有 namespace、nftables、route 或 sysctl。建议增加仅供 daemon 使用的
内部 platform adapter，接口只表达生命周期事务：

```text
preflight -> stage -> commit -> query -> rollback
```

Linux adapter 记录本次实例实际创建的对象与逆操作；Windows/macOS 后端可以保持
`unsupported`，直到各自具备同等回滚和 kill-switch 能力。首版用 enum 和清晰分支
表达 `none`/`masquerade`，不为尚不存在的多种 NAT 实现引入插件或复杂工厂。

### 客户端默认路由、控制面旁路与 DNS

安装 Mesh 默认路由前，`meshd` 必须从当前 underlay 事实计算并提交更具体的 bypass：

- bootstrap、当前 peer、STUN 和 TURN endpoint。
- 维持 Mesh 所需的 DNS resolver endpoint；若 endpoint 使用名称，必须先解析并冻结
  本次事务所用地址，TTL 变化通过下一次事务更新。
- 平台控制/诊断端点中明确声明为 out-of-band 的地址。

这些 bypass 先于默认路由生效，且由同一事务回滚；否则 Mesh 控制连接会递归进入
自己的 TUN，形成不可恢复的黑洞。endpoint 变化时先安装新 bypass，再迁移连接，
最后移除旧 bypass。

DNS 行为必须显式选择：

- `mesh` 模式：把 DNS 请求通过 TUN 发往策略允许的 exit/trusted resolver。
- `underlay` 模式：仅允许配置的 underlay resolver，并明确这是可观察的泄漏边界。
- fail-closed profile 禁止物理接口上未授权的 UDP/TCP 53 和 TCP 853；DoH endpoint
  仍按普通目的地址 policy 处理，不能仅靠端口规则宣称“无 DNS 泄漏”。

客户端 kill-switch 与默认路由属于同一 platform transaction。Mesh path 丢失时保留
阻断规则并让发送失败；只有显式、成功的 `down` 事务才恢复启动前的 route、DNS 和
firewall snapshot。进程异常退出由服务管理器 cleanup hook 或下次启动时按 instance ID
reconcile，不以“进程没了”作为开放物理出口的理由。

### 状态归属与生命周期

| 状态 | owner | 失败后的可接受状态 |
|------|-------|--------------------|
| 身份、route、egress policy | Mesh core immutable snapshot | 保留上一有效 snapshot 或拒绝流量 |
| OS desired state | 已验证配置 | 不直接代表已生效 |
| OS applied state/journal | `meshd` platform runtime | 可按 instance ID 查询和回滚 |
| NAT/conntrack | namespace kernel | 派生且可丢弃，不作为业务事实源 |
| exit readiness | `meshd` 聚合快照 | 任一安全或 OS 条件不满足即 false |

启动状态机固定为：

```text
STOPPED -> PREFLIGHT -> OS_STAGED -> MESH_READY
        -> ROUTES_COMMITTED -> RUNNING
        -> DRAINING -> ROLLED_BACK -> STOPPED
```

- preflight 校验权限、接口冲突、CIDR、身份、nftables 和资源配额。
- stage 创建 namespace/TUN/规则但尚不提交客户端默认路由，也不对外发布 exit ready。
- Mesh 身份认证和安全 path ready 后才 commit route/NAT 并发布 readiness。
- 任一步失败都执行逆序幂等 rollback；rollback 失败进入可诊断的 `cleanup-required`，
  不得报告 ready。
- exit shutdown 先停止新准入，再有界 drain，撤销 NAT/forward，最后关闭 Mesh/TUN
  并删除 namespace；客户端 graceful down 则以一个事务恢复原 route/DNS/firewall。

`meshd` 的 TUN callback 必须检查并传播 `mesh_send_packet()` 的结果。当前忽略返回值
会让出口丢包只表现为统计缺失，不能满足 fail-fast 和可观测性要求。

### 安全发布门槛

现有 local-egress policy 足以做受控实验，但不能据此宣称 production-safe exit。
生产 profile 必须等待以下门槛全部满足：

- 密码学随机数失败或短读能向上传播，不能继续使用部分初始化 key/nonce。
- 采用经审查的标准握手/KDF，不以简化的“Noise-like”流程代替协议验证。
- data envelope 的 AEAD associated data 绑定 origin、destination、session/path epoch、
  sequence、payload kind 和必要转发头。
- receive path 有有界滑动 replay window，并测试重复、乱序、counter wrap 和重连旧包。
- HELLO node ID 与 P2P public key 缺失或不一致时 fail closed。
- direct ICE、TURN 和 relay 使用相同端到端数据 envelope；raw selected-pair IP 不进入
  production profile。
- route/exit capability 具有 origin authentication、版本、expiry 和 replay protection。

在这些门槛完成前只能启用明确命名的 `lab-exit`：关闭 ICE raw data path，使用固定
identity allowlist 和加密 stream path，运行在 namespace 内，限制源/目的 CIDR、带宽、
包速率、并发 flow、conntrack、队列字节和 DNS QPS，并在状态接口持续标记
`security_profile: lab`。lab profile 不允许静默升级为 production。

### 分层过滤与安全审计

出口必须过滤和审计，但两者不能混成逐包日志或自制 DPI。过滤决定是否允许流量；
审计记录“谁、按哪条策略、为何被允许或拒绝”的有界事实。两者共享 policy decision，
日志文本不是策略事实源。

过滤顺序固定，并为每一步分配稳定 reason code：

1. **包结构校验**：只接受已启用 IP 版本，验证最小/实际 header 长度、total length、
   协议字段和 checksum 边界，拒绝 malformed/truncated packet。
2. **分片边界**：在 Mesh policy 尚未实现有界重组或可靠 conntrack 关联前，exit 默认
   拒绝 IPv4 fragment。非首片没有可信 L4 port，不能把 payload 前四字节误当端口。
3. **身份与 anti-spoof**：把 authenticated node ID/public-key fingerprint 映射到唯一
   virtual source IP；任何源不一致直接拒绝。
4. **目的地址防护**：`public-internet` profile 默认拒绝 loopback、link-local、
   multicast、broadcast、Mesh control/virtual ranges、宿主/namespace management 网段和
   cloud metadata endpoint。访问 RFC1918/CGNAT 网段必须使用显式 `subnet-router` policy，
   不能借公网 exit 隐式访问内网。
5. **L3/L4 policy**：按 direction、CIDR、protocol、port 和稳定 rule ID 做 first-match；
   exit 方向必须至少有规则，禁止沿用“该方向无规则即 allow”的兼容行为。
6. **stateful platform filter**：nftables 只允许合法 `new` 和 `established,related`，拒绝
   conntrack invalid、非配置 egress interface 与公网主动入站。
7. **资源策略**：在 NAT 前应用每 identity 的 flow、pps、bandwidth、DNS 和 queue 配额。

目标 policy evaluator 不再只返回 boolean，而是产生内部、不可变 decision：

```text
action + reason_code + rule_id + policy_epoch + peer_identity + direction
```

该 decision 同时驱动 drop/allow、计数器和审计聚合，避免 dataplane、日志和 status
分别推断不同原因。它先作为 Mesh 内部结构，不扩大 public ABI；需要对外订阅审计事件时
再以版本化 snapshot/callback 单独审查。

默认审计单位是 flow 和状态迁移，不是 packet：

- flow start/end：peer identity、虚拟源、目的地址/端口、协议、rule ID、policy/path epoch、
  start/end time、packets、bytes、termination reason。
- deny aggregate：按 identity、rule/reason、目的 prefix 和时间窗口聚合 count/bytes；
  首次高危事件可立即告警，后续同类事件 rate-limit。
- security event：identity mismatch、replay、route injection、capability downgrade、
  kill-switch/rollback 失败和 audit sink failure。
- control event：profile、policy epoch、route、DNS mode、bypass 和 platform transaction 变化。

每个 event 至少有 event/schema version、wall + monotonic time、instance ID、node/peer ID、
policy epoch、rule ID、action、reason 和 correlation/flow ID。禁止记录 private/session key、
认证 token、完整 payload、完整 DNS body 或应用凭据。对外部 collector 可按配置对目的 IP
做 prefix truncation 或 keyed pseudonymization；本地取证所需原值必须有独立权限和留存依据。

当前逐包 `TLOG_DEBUG` 拒绝日志不能作为审计实现：高流量攻击会造成 CPU、磁盘和隐私
风险。packet owner loop 只更新无阻塞、有界 counter/flow state，周期性把摘要投递给异步
audit sink；单次 packet 不同步 flush、不做 DNS reverse lookup，也不调用远端 collector。

audit sink 与普通运行日志分离，目录最小权限、大小/时间轮转、磁盘配额和 retention 都需
配置。若要求防篡改，可对事件做 hash chain，并把周期 checkpoint 签名后发送到独立远端；
只有本地 hash chain 而没有外部锚点，不能证明管理员未删除整段日志。

审计背压必须显式选择：

- `best-effort`：sink 不可用时继续按 policy 转发，累计丢失计数并告警。
- `required`：先写有界持久 spool；spool 达硬上限后拒绝**新** flow，已有 flow 按配置
  drain/terminate，不能阻塞 owner loop 或无限占用磁盘。

`required` 会改变可用性，必须是部署者显式选择且进行故障演练；任何模式都不能在
审计失败时静默切换。安全相关 ERROR 在消费边界记录一次，packet deny 只做聚合指标。

深度检测作为可选、隔离能力，不进入 Mesh core：

- DNS domain policy 应放在受控 resolver，并将 domain decision 与 flow ID 关联；仅看
  UDP/TCP 53 无法覆盖 DoH/DoT。
- TLS/QUIC 默认保持端到端，不做透明 MITM。SNI 也不是稳定、完整的授权事实。
- 若合规确需 IDS，使用成熟引擎在 namespace mirror/sidecar 上消费有界副本；默认
  out-of-band 检测，镜像队列满时丢审计副本并计数，不拖死 packet plane。
- inline IDS 是单独的高安全 profile，必须定义超时、引擎故障时 fail-open/fail-closed、
  证书/隐私责任和性能基线；不能以“临时技巧”直接上线。
- PCAP/payload capture 默认关闭；诊断时必须显式限定 identity/CIDR/port、持续时间和
  最大字节数，记录启停审计事件，加密保存并自动删除。capture 自身失败不得扩大范围。
- eBPF 可用于 Linux 客户端的进程归因和低成本 telemetry，但它是平台派生证据，不能
  替代跨平台 node identity、Mesh policy 或 nftables 最终 enforcement。

过滤/审计专项验证至少覆盖：fragment/overlap/truncation、source spoof、特殊目的网段、
rule ordering/default deny、conntrack invalid、rate limit、flow table/spool 满、collector
中断、重复事件、日志脱敏、轮转/留存、hash checkpoint，以及审计开启前后的 p50/p95/p99
延迟、CPU 和内存。测试 payload 中必须植入 canary secret，并断言所有日志与状态文件
均不包含该 secret。

### 配置映射与兼容性

已有 `route_rules`、`local_egress_cidrs`、`local_egress_allow_cidrs`、`packet_policy`
和 peer/node allowlist 继续作为 route 与授权的唯一配置事实源。新增 profile 只控制
OS 平台副作用，不复制 CIDR 或 policy：

```yaml
platform:
  profile: lab-exit       # disabled | client-full-tunnel | lab-exit | exit
  isolation: network-namespace
  instance_id: sh-exit-1
  egress_interface: eth0
  nat_mode: masquerade
  manage_os_routes: true
  fail_closed: true
```

字段名和 schema 仍是目标设计，不是已承诺的公开接口。实际加入配置前需要单独审查：
旧配置缺少 `platform` 时必须等价于 `disabled`，不创建 namespace、不修改默认路由、
DNS、forwarding 或 firewall。`exit` 必须通过生产安全门槛；否则配置验证直接失败，
不能自动降级为 `lab-exit`。

### 资源、指标与验证

所有可增长资源都要配置硬上限：每 identity 的 packets/s、bytes/s、并发 flow，实例
总 queue bytes、conntrack entries、DNS QPS 和 egress bandwidth。超限按 policy drop 或
backpressure，并记录 identity、阶段和原因，不逐包写 INFO 日志。

状态与指标至少暴露：exit readiness/reason、platform transaction state、namespace 和
rule instance ID、active clients、每 identity 流量/拒绝、NAT/conntrack usage、DNS mode、
bypass endpoints、route epoch、rollback/cleanup error，以及 physical-interface leak test
结果。不得输出私钥、session key、完整 DNS payload 或业务 payload。

验证采用由小到大的顺序：

1. fake platform adapter 验证每个 stage 的失败注入、逆序 rollback 和重复 up/down。
2. namespace 集成测试验证 source spoof、目的 policy、NAT return path、默认拒绝和配额。
3. 客户端验证 bootstrap 递归、DNS leak、exit 丢失 kill-switch、MTU/DF 和异常退出恢复。
4. eu/bj/sh/local 跨区测试：eu 只做 bootstrap/relay，bj/sh 分别做显式 exit，local
   读取受控 HTTP/DNS 数据；记录 selected path、RTT、bytes 和 exit identity。
5. 与 Docker 并存测试确认 Docker containers/chains 不被停止、flush 或改写。

验收条件是：未授权源无法使用出口；exit 丢失时无物理接口泄漏；控制面不递归；
多次 up/down 后 OS snapshot 完整恢复；Docker 行为不变；所有失败都有稳定错误和状态，
而不是仅凭“能访问公网”判断完成。

## 原生 flow plane

原生接口是 additive API，不替代 `mesh_send_packet()`。目标 public surface 采用
opaque `mesh_flow_t`，并保持职责小于十个操作：

| 操作 | 语义 |
|------|------|
| open | 根据 peer/service 和 flow requirements 创建 flow |
| send | 发送一个 datagram 或一段 stream 数据，返回 accepted/backpressure/error |
| receive callback | 在 Mesh owner loop 交付只读 buffer view |
| query | 返回不可变 path/queue snapshot |
| close | 幂等停止新发送并完成或取消 pending I/O |
| destroy | 仅在 close completion 后释放 owner handle |

datagram send 以一次调用对应一个消息边界；stream send 不承诺保持调用边界。
接收 buffer 只在 callback 期间有效，除非调用方显式 retain。跨线程调用通过
`coro_post()` 投递到 owner loop，不允许业务线程直接操作 ICE agent。

CoroNet 的 `turbo_datagram`、`turbo_stream` 和 arena buffer 是 transport 实现，
不会直接暴露到 Mesh ABI。

## 安全数据面

### 必要属性

- 发送节点身份和接收节点身份绑定。
- payload 机密性与完整性。
- 单调 sequence 与滑动 replay window。
- path/session epoch，重连后旧包不可进入新会话。
- destination 和必要的转发元数据得到认证。
- relay 只能读取路由需要的最小 header，不能读取业务 payload。

### 建立方式

复用项目已有认证密钥和成熟密码库，通过有版本的 key agreement/KDF 建立
独立 data-plane keys。不能直接复用 control-plane traffic key，也不能把 ICE
ufrag/password 当作业务加密密钥。

安全 envelope 作为新 capability 发布；只有双方协商成功后才能发送业务数据。
旧的 selected-pair raw IP capability 仅保留兼容/受控测试用途，不能作为通用业务
平台的安全完成条件。

多跳转发在端到端 origin authentication、destination binding 和 replay protection
完成前继续关闭高风险操作，包括 routed ICE control 和 relayed local egress。

## 服务发现

现有 MagicDNS 静态记录继续兼容。目标服务注册表在 DHT 中发布签名、带 TTL 的
不可变版本记录：

- service name 和 namespace。
- protocol：TCP、UDP 或 Mesh flow。
- virtual IP、port 和 node identity。
- optional labels 和健康状态摘要。
- record version、expiry 和 signature。

解析结果是只读快照。冲突记录按明确的 namespace policy 返回多个 endpoint，
不使用“最后写入获胜”覆盖其他节点。过期记录从 cache 失效，不能自动续租；
publisher 是续租的唯一 owner。

MagicDNS 是 service registry 的 DNS 视图，不是独立事实源。DNS server/search
domain 由 `meshd` 安装，Mesh core 只提供解析快照。

## 生命周期与线程模型

- 一个 `mesh_network_t` 由一个 CoroNet context 线程拥有。
- ICE agent、path manager、route manager、policy swap 和 flow callback 都在该线程运行。
- 外部线程只能通过线程安全 command/post 入口请求操作。
- callback 内允许请求 close，但 destroy 必须等当前 callback 返回。
- shutdown 顺序固定为：停止接入新业务、关闭 flow、停止 path work、关闭 ICE、
  清空 peer/route/service 派生状态、停止 Mesh、关闭 TUN、恢复 OS 配置。
- `meshd` 是 OS 状态的 owner；Mesh core shutdown 不直接修改 OS 路由。

## 错误与失败语义

| 条件 | 行为 |
|------|------|
| 身份或 capability 不匹配 | 拒绝 path/flow，记录安全诊断 |
| 无满足需求的路径 | 返回 `path unavailable`，不改变语义 fallback |
| realtime 队列满 | 丢弃过期/最旧 realtime 包并计数，不阻塞 control |
| bulk 队列满 | 返回 backpressure，由调用方重试或暂停生产 |
| payload 超过 effective MTU | 返回 `message too large`，不透明切片 |
| policy 更新无效 | 保持旧 snapshot，返回验证错误 |
| policy 在流量中撤销权限 | 新包立即拒绝；已进入 underlay 的包由对端当前 policy 再检查 |
| 路由消失 | 失效派生 path；fixed no-fallback route 立即失败 |
| callback 失败 | 在消费边界记录一次并按 flow policy close/drop |
| TUN/OS 配置中途失败 | `meshd` 回滚本次副作用并拒绝进入 ready |

## 可观测性

每个状态快照需要稳定版本号，至少包含：

- node identity、protocol/capability 和 policy epoch。
- peer authentication state。
- route source、next hop、expiry 和选择原因。
- path kind、state、epoch、RTT、loss、effective MTU 和 last error。
- 各 traffic class 的 queued bytes、drops、deadline drops 和 backpressure 次数。
- security replay drops、authentication failures 和 key epoch。
- TUN packets/bytes/errors。
- service record count、expiry 和 signature rejection。

热路径只累计指标，不逐包写 INFO 日志。一次失败只在实际消费或转换错误的边界记录。

## TurboMedia 接入

### 默认路径

TurboMedia 继续使用普通 socket 连接对端虚拟 IP：

```text
capture -> codec -> RTP/RTCP -> UDP socket -> TUN -> Mesh -> remote TUN -> UDP socket
```

TurboMedia 拥有 frame、clock、RTP packetization、jitter、codec 和媒体统计。
Mesh 拥有 peer identity、path、MTU、queue 和 packet delivery。

部署要求：

- RTP/RTCP 端口或 DSCP 映射为 realtime。
- media profile 要求 datagram-capable path；不允许 stream fallback。
- RTP packet size 小于 Mesh effective MTU。
- 使用 SRTP/DTLS/TLS，直到 Mesh secure data plane 成为强制能力；即使后者完成，
  协议要求的端到端媒体安全仍保留。

### 原生优化路径

只有 profiling 证明 TUN/kernel crossing 是显著瓶颈后，TurboMedia 才增加 Mesh
datagram adapter。adapter 仍传输完整 RTP/RTCP packet，不传裸 codec frame，
从而保持录制、转发、jitter 和协议边界在 TurboMedia。

浏览器 WebRTC 保持 TurboMedia WebRTC 自己的 ICE/DTLS/SRTP session，不使用
Mesh TUN 承载浏览器 candidate；Mesh 可用于信令服务发现和受策略保护的控制 API。

## 配置边界

目标配置仍由 `meshd` 统一加载和验证，优先级为命令行、环境变量、配置文件、
默认值。配置按职责分组：

- identity：密钥引用和协议版本。
- network：virtual prefix、TUN、MTU、bootstrap 和 STUN/TURN。
- policy：peer、packet、service、subnet 和 exit actions。
- path：允许的 path kinds 与 fallback policy。
- qos：traffic-class mapping、queue limits 和 pacing limits。
- services：本地发布记录。
- platform：显式 profile、OS 隔离、NAT、默认路由、DNS 和 fail-closed 生命周期。
- audit：flow/deny/security event、sink、背压模式、spool 上限、脱敏和 retention。
- observability：status、metrics 和诊断输出。

配置更新先在旁路构建完整 snapshot，验证成功后投递 owner loop 原子替换。
TUN 地址、virtual prefix 和 identity key 属于 restart-required；policy、QoS、
service publication 和部分 path preference 可热更新。热更新失败不修改当前状态。

## 兼容性与协议演进

- 现有 `mesh_send_packet()`、callbacks、route rules 和 MagicDNS API 保持行为。
- 新 flow API、path snapshot 和 service API 只做加法式扩展。
- 新 wire behavior 必须有 capability bit；未知 bit 被忽略，缺失 bit 表示不可用。
- secure data envelope 需要新的 capability 和 protocol minor；若旧 peer 无法安全接收，
  发送端 fail closed，不回退到 raw selected-pair payload。
- 只有不兼容 wire framing 或身份语义变化才提升 protocol major。
- 配置新增字段必须有默认值，且不改变旧配置的现有结果。

## 分阶段迁移

### 阶段 0：冻结事实与基线

- 保持现有 public API 和 wire behavior。
- 固化两节点/三节点 TUN、direct ICE、relay、policy 和 shutdown 回归。
- 为当前 stream fallback、MTU、queue 和 raw selected-pair path 增加明确诊断。

### 阶段 1：内部 path manager 与语义化选择

- 把散落的 direct/route/fallback 判断收敛为内部 path snapshot 和 selector。
- 默认结果与当前实现相同。
- 增加 datagram-required policy 后，仅显式使用该策略的流量改变行为。
- 增加有界 route candidate、metric probe 和 observe-only optimizer；保存 trace 并离线
  比较现行路径与建议路径，不改变 forwarding。
- feasibility、迟滞、flow stickiness 和故障切换验证达标后，再通过显式 opt-in 启用
  dynamic selection；默认行为变更另行审批。

### 阶段 2：安全数据 envelope

- 加入 capability、key epoch、AEAD 和 replay window。
- selected-pair 和 relay 共享同一端到端身份事实源。
- 新能力双端可用前不承载通用业务生产流量。

### 阶段 3：有界 QoS 与 MTU

- 引入 traffic class、有界队列、deadline drop、bulk backpressure 和 MTU snapshot。
- `meshd` 提供五元组/DSCP 分类与可诊断配置。

### 阶段 4：服务发现与 DNS 视图

- 增加签名 service record、TTL、冲突语义和 resolve snapshot。
- `meshd` 在支持平台提供 DNS listener/search domain 集成。

### 阶段 5：原生 flow 与业务 adapter

- 发布 additive stream/datagram flow API。
- 在独立 target 中实现 TurboMedia adapter，并以 profiling 决定是否启用。

### Exit profile 独立迁移轨

- E0：用现有 local-egress policy 和人工 namespace/NAT 完成 `lab-exit` 基线；不修改
  public API，不宣称 production safe。
- E1：实现 Linux internal platform transaction、状态查询、失败注入和幂等 rollback；
  旧配置默认 `disabled`。
- E2：实现 client full-tunnel 的 underlay bypass、DNS policy 和 kill-switch，验证异常退出
  后恢复；此时仍只允许 lab profile。
- E3：安全 envelope、replay、identity fail-closed 和 route authentication 全部达标后，
  才开放 production `exit` profile。
- E4：在已有单出口行为稳定后增加显式多出口 policy、健康快照和原子 epoch 切换。

E1/E2 可以和安全数据面并行开发，但 E3 是生产发布硬依赖。每个阶段都能通过停用
profile 和 platform rollback 恢复启动前 OS 状态，不改变 Mesh virtual IP 数据格式。

每个阶段都通过独立 capability/config 开关启用。回滚只关闭新能力，TUN packet
compatibility path 保持可用；不要求迁移用户数据格式。

## 验证范围

### 单元与状态机

- path requirements 与 capability matrix。
- route candidate feasibility、origin sequence serial arithmetic、retraction、expiry 和
  deterministic tie-break。
- lexicographic constraint/objective、unknown metric、Pareto dominance、迟滞、minimum
  dwell、switch quota 和 flow stickiness。
- policy snapshot 原子替换及失败保持旧状态。
- route source 隔离、TTL、fixed no-fallback。
- secure envelope authentication、sequence wrap、replay window 和 epoch rollover。
- queue limits、deadline drop、公平调度和 backpressure。
- service record signature、TTL、冲突与 cache invalidation。

### 两节点集成

- TCP/UDP/ICMP 经 TUN 双向通信。
- host、server-reflexive 和 TURN path。
- direct path 中断、NAT rebinding 和 peer restart。
- datagram-required 流量在只剩 stream 时明确失败。
- MTU 边界、DF 包、独立 IP fragment 和超限错误。
- shutdown 时 pending receive/send、callback close 和重复 close。

### 多节点与安全

- relay route 收敛、过期和 peer churn。
- diamond/ring topology 下同 hop 候选、metric 交叉、partition/heal、hard failure 与
  stale update；任何阶段都无 forwarding loop。
- metric poisoning、虚假低 cost、sequence replay/wrap、update flood 和候选表配额被拒绝。
- relay 无法读取端到端业务 payload。
- origin spoof、route injection、replay 和 capability downgrade 被拒绝。
- subnet/exit-node 双向 policy 与 local-egress fail-closed。

### 业务验证

- TurboMedia G.711 RTP/RTCP 基线，随后按可用构建扩展 Opus/H.264。
- HTTP/TLS、RPC、数据库连接和大文件传输。
- realtime 与 bulk 并发时 control plane 不被饿死。
- TUN 与原生 adapter 的延迟、CPU、内存和 copy 数对比；没有 profiling 证据时
  保持 TUN 默认路径。

### 平台验证

- Windows WinTun、Linux `/dev/net/tun`、macOS utun。
- TUN 创建失败、路由冲突、权限不足和进程异常退出后的 OS 状态恢复。
- Debug/Release、ASan/UBSan，以及 CoroNet shutdown regression。

## 完成条件

Mesh 可以被称为通用业务网络底座，需要同时满足：

- TUN、原生 flow 和 service discovery 共享一致身份、policy、route 与 path 事实源。
- dynamic selector 只在满足 hard constraints 的 finite/feasible route 中优化，并通过
  trace replay 证明 SLA、抖动和恢复时间不劣于 hop-count 兼容基线。
- 任何自动 fallback 都保持调用方声明的 transport 和 security 语义。
- direct 与 relay 数据都有端到端身份绑定、加密、完整性和重放保护。
- 队列和缓存有上限，MTU 和 backpressure 对调用方可见。
- daemon 能安全管理并回滚 OS 副作用。
- full-tunnel/exit 能证明控制面不递归、无 DNS/物理接口泄漏，且不修改其他系统
  （包括 Docker）拥有的 firewall 状态。
- 两节点、多节点、NAT、故障、业务和平台矩阵具有可重复测试结果。
- 当前 beta 状态文档更新为对应实测结果，而不是仅依据设计宣称完成。

## 一手资料

- [RFC 8966: The Babel Routing Protocol](https://datatracker.ietf.org/doc/html/rfc8966)：
  loop-avoiding distance-vector、feasibility、sequenced route、alternate route 与 hysteresis。
- [RFC 6298: Computing TCP's Retransmission Timer](https://datatracker.ietf.org/doc/html/rfc6298)：
  SRTT/RTTVAR 的平滑计算参考；Mesh 仅复用估计形式，不复用 TCP RTO 语义。
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)：握手状态、密钥派生、
  AEAD、nonce 与 transport cipher state 的协议依据。
- [WireGuard Protocol](https://www.wireguard.com/protocol/)：已部署 Mesh VPN 对 Noise IK、
  key confirmation、AEAD authenticated data 与 replay 防护的组合参考。
- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)：ChaCha20-Poly1305 AEAD 定义与
  测试向量。
- [nftables Atomic Rule Replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)：
  用单次事务替换专属规则，避免中间半配置状态。
- [Linux Kernel IP sysctl](https://docs.kernel.org/networking/ip-sysctl.html)：forwarding 与
  PMTU 相关内核语义。

# Mesh / M3 产品愿景、销售叙事与商业化路线图

## 文档用途

本文供销售、产品与研发统一对外口径和交付优先级。它回答五个问题：

1. 我们为谁解决什么问题？
2. 客户为什么现在需要它？
3. 今天可以演示和试点什么？
4. 哪些能力还不能作为生产承诺？
5. 怎样从技术预览走到可售产品？

文中使用三类标记：

- `事实`：来自当前代码、测试或可重复 smoke。
- `目标`：产品应向客户提供的稳定结果，不代表今天已经具备。
- `门槛`：进入下一销售阶段前必须通过的验收条件。

代码现状以本文件的“证据与验证”快照及相关设计文档为准。网络控制面目标架构见
[`MESH_PRODUCT_CONTROL_PLANE.md`](../MESH_PRODUCT_CONTROL_PLANE.md)。

## 1. 一句话愿景

**一套软件定义安全 Mesh，通过策略统一控制节点、网络、数据流和边缘执行。**

Mesh / M3 不是“任意网络上的文件分发工具”，而是一套面向多站点、弱网络和私有部署环境的
**软件定义安全 Mesh（software-defined secure mesh）**。Controller 声明身份、节点角色、连接、
路由、路径、服务和数据流策略，agent/meshd 在节点本地验证并执行签名意图；业务数据不经过
Controller。文件、对象和流只是数据面 workload，不是产品边界。

节点身份、准入、访问策略、路由和审计定义统一安全边界。传输方式可随拓扑、traffic class 和业务
类型变化，但不能绕过 Mesh 身份、策略或内容校验。节点功能栈按 builtin、Native 和 WASM 分别授权；
首期只接预注册 builtin 和显式启用的 Native provider，第三方 WASM 执行推后。任何执行能力都不能
反向获得未授权的网络、存储或宿主权限。

商业化有两个入口：

- **M3 轻量对象服务**：面向个人开发者、小团队和中小企业，用一台自有节点和本地磁盘起步，提供
  私有、内容可验证、成本边界清楚的对象服务。单机或局域网使用无需先部署 Tailscale、ZeroTier、
  NetBird、FRP 或集中转发服务。
- **私有软件分发**：面向多站点企业，证明网络和数据策略产生了可量化结果。对外结果可概括为
  “**一次发布，安全送达每个站点**”。

M3 不是只能充当分发底座的内部组件。单节点档位解决“先以低成本拥有私有对象服务”，分布式档位
再增加 Raft 元数据、副本、repair 和 Mesh 多站点能力。目标体验是“从一台机器开始，容量增长时添加
store，不改应用接口和对象身份”；文件同步和实时/点播流继续作为上层 workload。

在同一安全 Mesh 上，产品从低成本文件发布和推送起步，逐步形成可承载文件、对象、磁盘镜像、点播
视频和实时流的私有边缘交付平面。不同 workload 共享身份、路径、QoS、审计和内容校验，但各自保留
正确的状态与错误语义；不能用一个“万能文件传输”接口掩盖对象、实时流和可写块设备之间的差异。

客户通过统一的 `meshctl` 声明和观察节点、Mesh 与数据行为：管理身份和节点角色，发布并回滚网络
策略，控制路由、路径、出口、服务、traffic class 和 QoS，发布、镜像、拉取和删除受管文件，检查
对象与流，并在授权节点上提交和查询受控任务。`meshctl` 是操作入口，不是新的事实源；Controller policy、
release manifest、对象元数据和执行 journal 仍分别由各自领域服务持有。

## 2. 今天怎样销售

当前销售阶段是 **技术预览与设计伙伴试点**，不是 GA 产品。

可以承诺：

- 演示虚拟 IP、直连/中继、固定路由、packet policy、peer admission、健康状态和诊断等独立网络能力。
- 演示单节点 M3 的 SigV4 请求、对象 PUT/GET/HEAD/DELETE、Range、列表、持久化重启恢复和内容校验。
- 在受控环境中演示版本化发布包（release）的发布、骨干到边缘镜像、按名拉取和文件下载。
- 在显式配置发布私钥和可信公钥时，验证发布包签名、清单摘要（digest）
  和逐对象内容标识（CID）。
- 演示签名请求、对象 Range 下载、Raft 元数据、跨进程 store 副本和 repair/GC 等独立能力。
- 与客户共同定义真实拓扑、容量、安全和运维门槛，形成产品化设计伙伴项目。

不能承诺：

- 不能称为 GA、开箱即用的生产 CDN 或 AWS S3 的直接替代品。
- 不能把 M3 Starter 描述为 SMB/NFS NAS 的透明替代或现有共享目录的即插即用加速器；当前契约是
  S3-shaped 对象 API，文件挂载、目录语义和 NAS 协议兼容尚未产品化。
- 不能把 M3 的“低成本”解释为已经公布固定价格或经过客户 TCO 验证；当前依据是可从单节点、本地
  磁盘和自有网络起步，实际成本必须按容量、副本、带宽、备份和运维计算。
- 不能把单节点 M3 描述为高可用；节点或磁盘故障会中断服务，必须另行定义备份和恢复责任。
- 不能承诺 10+ 节点规模、复杂 NAT、持续 churn 或跨地域故障下的生产 SLO。
- 不能在未固定可信公钥时宣称内容具有发布者真实性；CID 只证明内容与清单一致。
- 不能把当前 release smoke 描述为 L1 overlay、Raft 和多副本 store 已组合验证的产品闭环。
- 不能把本机静态配置和当前 `meshctl` 描述为已经完成集中式 Controller、签名策略下发与全网收敛的
  生产 SDN 控制面。
- 不能把 demo 密钥、命令行私钥或明文 HTTP 用于生产部署。

销售目标不是提前包装成熟度，而是找到有明确分发成本、愿意共同验证生产门槛的设计伙伴。

## 3. 理想客户

| 客户类型 | 典型场景 | 购买信号 | 首要价值 |
|----------|----------|----------|----------|
| 个人开发者与家庭实验室 | 私有项目资产、构建产物、模型或媒体对象 | 不想承担公有云最低消费和出口费用 | 一台节点起步、数据留在本地 |
| NAS 与自建存储用户 | 本地对象、照片、媒体和备份供多设备访问 | 远程路径依赖第三方组网、反向代理或集中转发 | 局域网直接使用，逐步接入原生安全 Mesh |
| 小团队与中小企业 | 应用对象、内部制品、共享媒体和边缘数据 | 预算敏感、缺少专职存储团队、已有闲置服务器 | 低门槛私有对象服务 |
| 多园区企业 | 总部向工厂、门店、实验室发布软件 | 3 个以上站点、跨公网、重复下载 | 一次发布，当地拉取 |
| 设备与固件团队 | 批量交付固件、模型和离线安装包 | 文件大、版本多、升级窗口短 | 版本化交付与完整性校验 |
| 私有云与受监管组织 | 内容必须留在自有网络 | 不接受公共 SaaS、需要审计 | 私有部署与自主信任根 |
| 边缘媒体团队 | 多站点分发直播或点播片段 | 回源带宽高、站点网络不稳定 | 边缘缓存与多源拉取 |
| 平台与网络团队 | 统一管理边缘节点、路径、出口和服务 | 逐机改配置、策略漂移、缺少流量可见性 | 声明式网络意图与本地执行 |

优先寻找以下机会：

- 客户希望在现有节点和磁盘上部署私有对象服务，并能接受从单节点、明确备份责任开始。
- 客户的 NAS 或自建存储在本地可用，但远程访问经常落到集中 relay、FRP server 或其他单点转发，
  希望区分本地直连流量与确实需要中继的流量。
- 当前对象容量和请求量不大，但公有云固定成本、出口费用、隐私或账户复杂度不合适。
- 客户已经维护多个 rsync、HTTP、S3 或文件服务器镜像。
- 同一软件包被每个站点反复从中心下载，出口带宽和交付时间可量化。
- 发布失败主要由跨站网络、人工操作或版本不一致造成。
- 客户要求内容签名、下载审计、私有部署或离线边缘交付。
- 客户愿意从 3 个站点、单一内容类型和明确成功指标开始试点。

## 4. 客户价值

### 4.1 用策略定义网络行为

管理员声明“谁可以加入、谁能访问什么、数据走哪类路径、节点承担什么角色”，Controller 将意图
编译为签名、版本化的策略快照，节点在本地执行。策略支持 validate、test、diff、分阶段发布和以
新 epoch 回滚；Controller 暂时不可用时，已建立的数据流不依赖其转发。

### 4.2 小规模也值得部署

M3 的轻量档位不要求客户先建立三节点集群。个人或小团队可以从单 gateway、本地持久化 namespace
和文件系统 CAS 起步，按实际数据量使用已有存储；单机和局域网客户端不需要先配置第三方 Mesh、
反向代理或集中转发。需要跨公网访问时，仍必须配置经过认证和加密的连接；长期目标是由原生 Mesh
按策略优先选择授权直连路径，只有直连不可用或策略禁止时才使用中继。需要容错时，再选择分布式
档位。低成本来自较小的起步拓扑、私有部署和可配置副本，不来自牺牲认证、内容校验或错误语义。

容量增长不应迫使客户更换产品或重写应用。M3 的目标扩容单位是 store：新增磁盘可由新的 store
数据目录承载，新增机器可作为 Mesh store 加入；bucket/key、对象 CID 和客户端 API 保持不变。
元数据 voter 与数据 store 分离扩展，Controller 和 Raft quorum 不转发对象 bytes。扩容、drain、
repair 和再平衡仍必须通过已提交 placement 与 durable receipt 保护，不能因为采用 P2P 数据面就绕过
一致性和副本要求。

### 4.3 一次发布，当地交付

发布方只管理一个版本化 release。骨干保存权威内容，边缘节点按需镜像，消费者从当地节点拉取。
客户减少重复回源、手工同步和站点间版本漂移。

面向操作者可以提供“推送到节点/节点组”的命令，但其安全实现是 **push intent, pull data**：Controller
只下发目标 release、目标节点标签、截止时间和策略 epoch，节点从授权来源拉取、验签、原子切换并
报告 applied/rejected 状态。文件 bytes 不经过 Controller；离线节点恢复后按同一意图收敛，重复执行
保持幂等。这样既保留推送体验，又避免集中推送器成为带宽、可用性和凭证瓶颈。

### 4.4 内容可验证

`目标`：每个生产 release 必须绑定发布者签名；拉取端必须从受信渠道获得公钥并强制验签。
清单 digest 和逐对象 CID 用于发现篡改或损坏，不能替代发布者身份验证。

### 4.5 网络变化不改变发布流程

节点身份和策略属于安全 Mesh，不属于某一种传输。系统可在 Mesh 直连、中继及适合业务的数据协议
之间选择合规路径；路径变化时，客户不应重新设计内容地址、版本命名、可信发布者或下载工具。
找不到满足身份、策略和加密要求的路径时必须明确失败，不能自动降级到不受控传输。

### 4.6 一个安全 Mesh，多种数据服务

Mesh CDN 是交付平面，不是另一套对象事实源。它把“内容应出现在哪些节点、允许从哪里取、优先走
什么路径、可以占用多少带宽”编译为节点本地策略；release manifest、M3 namespace、视频 live edge
和未来块设备 journal 仍由各自领域拥有。

| 数据服务 | 客户结果 | 复用的 Mesh 能力 | 独立语义 | 当前成熟度 |
|----------|----------|------------------|----------|------------|
| 低成本文件发布/推送 | 一次选择目标节点组，文件在本地可验证落地并可审计撤回 | 身份、目标标签、直连/中继、多源、bulk QoS、审计 | release 版本、签名、原子切换、撤回、删除和回滚 | release 组件技术预览；策略推送与删除收敛未闭环 |
| 灵活私有 Mesh CDN | 节点可按策略成为 origin、cache 或 edge，就近服务文件、对象和媒体 | source selection、路径策略、缓存位置、流量类别和故障切换 | placement、TTL、驱逐、回源与一致性 | 两级 mirror、Range、多源和 failover 已分别验证；未形成统一 CDN |
| 点播与视频流 | 点播就近 Range/HLS，直播在弱网下保持有界延迟并可切源 | path/QoS、KCP、可靠流、中继、边缘服务发现 | playlist、时间轴、live edge、FEC、丢帧与 ABR | 组件和多进程 demo 已有；播放器/SLO/组合验证不足 |
| 不可变磁盘镜像分发 | VM/设备镜像按块校验、断点续传并在边缘复用 | 内容寻址、多源块拉取、Range、release 签名 | 镜像版本、分区元数据和整体激活 | 可复用组件，尚无磁盘镜像产品流程 |
| 可写远程块设备 | 在授权节点挂载远程 volume | 身份、低时延路径、QoS、审计 | 扇区写入顺序、flush/FUA、discard、fencing、快照和崩溃一致性 | 未实现，仅作为远期独立产品研究 |

低成本来自自有或通用节点、当地缓存、相同内容只跨慢链路传输一次、授权直连和按需扩展，不来自
省略签名、副本或流量保护。没有客户基线前，销售应表达“减少集中回源和重复传输的机会”，不能承诺
固定带宽节省比例或单位成本。

## 5. 销售演示故事

### 5.1 M3 轻量对象服务

面向个人和中小企业使用 10 分钟主线：

1. **启动**：指定一个存储目录启动单节点 M3，展示没有外部数据库或公有云账户前置。
2. **写入**：使用 SigV4 客户端上传小对象和多 chunk 对象。
3. **读取**：演示 GET、HEAD、列表和 Range，并核对 ETag/CID 与返回内容。
4. **恢复**：重启 gateway，展示 namespace 和对象仍可读取。
5. **拒绝错误**：使用未签名、篡改或过期请求，展示明确的 403/校验失败。

当前演示必须称为 **单节点技术预览**。它证明轻量部署与核心对象闭环，不证明磁盘冗余、高可用、
完整 S3 兼容、多租户隔离或生产备份恢复。

### 5.2 软件定义 Mesh 与分发

P0 目标演示应使用 15 分钟、单一主线，展示安全网络和数据交付是同一个产品：

1. **定义意图**：通过 `meshctl` 登记骨干、边缘和消费者角色，验证并发布本次 release 所需策略。
2. **发布**：将包含深层路径的三个文件打包为版本化 release，并用 Ed25519 私钥签名。
3. **直连交付**：展示发现结果和已认证直连路径，将 release 镜像到当地边缘。
4. **路径切换**：阻断直连，展示系统经授权中继继续同一 release，而不改变 ID、签名或审计链。
5. **拉取验证**：消费者从边缘按名称下载，验证清单 digest、发布者签名和逐对象 CID。
6. **改变行为**：修改路径或访问策略，展示节点收到新 epoch 后本地生效，并能看到应用状态与原因。
7. **撤回并删除**：撤回 release，展示在线节点停止服务并删除受管副本，离线节点保持 pending。
8. **拒绝越权与篡改**：让未授权节点请求内容并修改对象或签名侧车，展示请求明确失败且不写入
   可信结果。

演示结束时只强调客户结果：节点可信、策略生效、多路径可达、一次发布、边缘交付、篡改可见。
Raft、KCP、CoroNet、CAS 等实现细节用于回答技术尽调，不作为销售主叙事。

当前只能演示上述步骤中的 release 组件流程：download/mirror smoke 使用本机 HTTP 网关；节点入网、
Mesh 策略、直连/中继、Raft、多副本 store 与 release 的共同跨层闭环仍属于 P0 门槛。

## 6. 产品组合

| 产品方向 | 客户结果 | 当前成熟度 | 销售优先级 |
|----------|----------|------------|------------|
| 软件定义安全 Mesh | 用签名策略统一定义节点、连接、路由、路径、服务和数据流行为 | beta，尚缺产品 Controller 和规模验证 | P0 产品底座 |
| M3 Starter | 用单节点和现有磁盘获得私有对象服务 | 技术预览，单节点核心闭环已验证 | P0 独立入口 |
| 低成本文件发布/推送 | 软件、固件和配置一次选择目标节点组，安全送达、撤回并报告结果 | release 组件技术预览；desired-state 推送和删除收敛未实现 | P0 |
| M3 Cluster | 保持同一对象接口，通过增加 store 扩展容量、副本和站点 | 开发预览，组件与 smoke 已验证 | P1 |
| 灵活私有 Mesh CDN | 按策略组合 origin、cache、edge 和多源路径，减少集中回源 | 两级分发、Range、多源与 failover 分别为 demo/组件级 | P1 |
| P2P 文件同步 | 多源增量同步与断点续传 | 组件级能力 | P2 |
| 点播与实时视频流 | 点播就近读取，直播支持弱网传输、HLS 输出和切源 | demo 级 | P2 |
| 不可变磁盘镜像分发 | 大型镜像按块验证、断点续传和边缘复用 | 底层组件可复用，尚无产品流程 | P2 评估 |
| 可写远程块设备 | 经安全 Mesh 挂载有一致性与 fencing 的远程 volume | 未实现 | 远期研究 |
| 节点功能栈 | 在显式授权节点运行 builtin、预注册 Native/WASM | 权限/availability/精确 deployment 已分离；Native 与 TurboWASM 隔离 child、超时/输出上限和 durable result 已有组件测试；production OS sandbox/审计及产品 rollout 未闭环 | P2 |

### 6.1 私有软件分发网络：首个可售产品

核心工作流：

```text
发布者 -> 骨干网关 -> 当地边缘 -> 消费者
   |          |            |          |
 签名      权威内容       完整镜像     验签与 CID 校验
```

`事实`：当前 release 工具已经支持 pack、publish、mirror、pull、深层路径、文件端点、清单 digest、
可选 Ed25519 签名和逐对象 CID 校验。

`目标`：生产 profile 不允许无签名 release；签名侧车缺失、未知或已吊销公钥、清单不一致和对象
CID 不匹配都必须 fail-closed。

#### 6.1.1 低成本文件推送

“推送”是一条管理命令，不是一条中央 bytes 通道。目标工作流是：操作者提交 release 与目标 selector，
Controller 持久化签名 desired assignment，在线 agent 立即收到通知，目标节点从最合适的授权来源
拉取并验签，最后报告 applied/rejected 和本地版本。离线节点通过重连后的 reconcile 补齐，不要求
操作者逐台重发。

每次 assignment 必须包含 release ID/digest、目标 selector 的解析结果或稳定快照、策略 epoch、截止
时间、并发/带宽上限和失败策略。Controller 只拥有交付意图和汇总状态；release manifest 是内容事实
源，节点本地安装状态是执行事实。部分节点失败不能把整批操作标记为成功，也不能触发无签名或物理
IP 直连 fallback。

成本优势来自节点间复用、当地 edge、断点续传和受控并发。总部不需要为每个节点重复发送完整文件，
Controller 也不承担内容出口。当前 `publish/mirror/pull` 已验证内容流程，但 selector、assignment、
agent reconcile、批量进度和取消尚未形成产品闭环。

#### 6.1.2 文件撤回、删除与物理回收

Mesh 中的“删除文件”不是向当前在线节点广播一次 `rm`，而是一个版本化、可重放、可审计的 desired
state。否则离线节点会永久漏删，旧 edge/cache 仍可能继续提供内容，CAS 共享块还可能被其他 release
引用。产品必须区分四种动作：

| 动作 | 用户结果 | 状态变化 | 是否立即删除 bytes |
|------|----------|----------|--------------------|
| `withdraw` | 不再把 release 分配给新节点 | 关闭发布和新的 assignment | 否 |
| `revoke` | 已收敛节点拒绝新读取和下载 | 提交更高 epoch 的访问 tombstone | 否 |
| `uninstall` | 目标节点删除该 release 的受管落地文件 | agent 收敛到 absent 并报告结果 | 删除 materialized copy |
| `purge` | 回收已无合法引用的 CAS 内容 | retention/grace/hold 检查后由 GC sweep | 是，但只删除无引用块 |

操作者通过 `meshctl release withdraw|revoke|uninstall|purge` 提交带 request ID 的签名意图。删除记录至少
绑定 tenant、release ID/digest、目标 selector 的稳定快照、单调 epoch、模式、retention deadline、
发起者和理由。Controller 保存 desired deletion 和节点汇总状态；release tombstone 决定发布可见性；
agent 本地 journal 是执行事实。重复命令必须幂等，同一 request ID 参数不同必须拒绝。

执行顺序是：

```text
commit signed tombstone
  -> gateway/edge 拒绝新的 manifest 和文件读取
  -> online agent 原子切离 active release
  -> 只在受管 version directory 内删除 materialized files
  -> agent report applied/rejected/pending
  -> retention/grace/hold 到期且全局引用为零
  -> M3 GC 回收无引用 CAS chunks
```

节点删除路径必须来自已验证 manifest，并限制在 agent 管理的 version directory；拒绝绝对路径、`..`、
symlink/reparse-point 穿越和管理根以外的目标。先切换 active pointer，再清理旧 version directory，避免
逐文件删除时向用户暴露半个 release。文件被占用或权限不足时报告 `rejected`/`pending` 和具体路径，
不能把部分删除记为成功，也不能触碰用户自行复制到非受管目录的文件。

若运维确需删除不属于 release 的节点文件，使用独立的受控命令，而不是把任意 shell 暴露为文件 API：

```text
meshctl node file delete --selector <nodes> \
  --managed-root <policy-defined-root> \
  --relative-path <path> [--expected-cid <cid>]
```

Controller 把 selector 固化为目标快照并提交签名 command；目标 agent 通过 durable command journal 幂等
执行。`managed-root` 必须由更高权限策略预先授予，路径只能相对该根，`expected-cid` 不匹配则 fail-fast，
从而避免排队期间路径内容变化后误删。递归删除必须转换为有界、可预演的 manifest，设置文件数/bytes
上限，不接受 shell glob。该命令可由预部署签名 WASM task 承载，但沙箱只得到显式 preopen root 和
unlink 能力，不获得任意宿主文件、网络或提权权限；需要更高 OS 权限时使用独立最小权限 worker。

离线节点的 tombstone 必须保留到该节点确认 `absent`，或节点身份被明确退役并超过离线保留策略；节点
重连时先应用最新 epoch，不能因本地仍有旧 manifest 而恢复服务。只有全部目标节点 applied，或剩余
节点被明确排除后，任务才能报告 scoped complete。系统无法保证删除用户导出的副本、不可控备份或已
失去管理权的节点，销售和审计结果必须明确这个边界。

`revoke` 提交后停止签发新的短期读取 capability。在线节点收到新 epoch 后立即拒绝；失联节点最多在
既有 capability 的硬 TTL 内继续接受旧授权，因此产品必须配置并公开 maximum revocation window。
如果某个服务允许无过期的离线授权，就不能宣称全网即时撤权，只能报告该节点尚未收敛。

M3 对象删除通过已提交 tombstone 先移除 namespace 可见性。物理 CAS blob 只有在不再被任何 release、
对象版本、snapshot、clone、pending transaction、read pin 或 legal hold 引用，且 grace period 到期后
才能删除。内容寻址意味着多个文件可共享同一块；删除一个文件绝不能直接按 CID 删除共享 bytes。
`purge` 是不可逆管理操作，必须支持 dry-run，显示仍存引用、离线节点、预计回收 bytes 和阻塞原因。
release 引用和独立对象 API 引用必须进入同一 committed reference view；若对象由外部 bucket/key 或
另一 release 共同拥有，删除 release 只移除自身引用，不能擅自 tombstone 该对象版本。

`目标`：恢复使用更高 epoch 的新签名 assignment，而不是删除 tombstone 或倒退 epoch；紧急撤权优先
保证新访问 fail-closed，物理擦除异步完成。当前 release 工具和 M3 DELETE/GC 只提供部分组件，尚无
Controller deletion intent、agent uninstall journal、离线收敛、引用审计和端到端 purge 测试。

#### 6.1.3 灵活私有 Mesh CDN

传统两级“骨干到边缘”只是 Mesh CDN 的一个 profile。目标模型中，origin、cache、edge 和 relay 是
节点在特定租户、内容类型和策略 epoch 下承担的角色，不是永久固定拓扑。同一 release、对象或媒体
segment 可以有多个授权来源；接收节点按身份、内容可用性、路径成本、健康、容量和 traffic class
选择来源，并把结果在策略允许时留作当地缓存。

Controller 管理内容 placement intent、cache 容量/TTL、允许来源、路径和带宽；节点负责本地驱逐、
拉取、校验和服务。缓存不是新的内容事实源：release 仍由签名 manifest 定义，M3 对象仍由已提交
namespace/manifest 定义。缓存 miss、源故障或路径切换不能改变内容身份和信任链。

`事实`：两级 mirror、Range/206、多源块拉取、媒体 playlist、live 多节点和跨网关 failover 已分别
存在测试或 smoke。`边界`：当前没有统一 CDN placement controller、缓存目录/驱逐协议、动态 source
selection 闭环、全链路身份绑定或长期负载数据，因此只能称为灵活 Mesh CDN 的组件基础。

#### 6.1.4 点播与实时视频

视频不是“更大的文件”。点播适合由 M3 保存不可变媒体对象和索引，经当地 edge 提供 Range/HLS，
并从多个授权源补齐缺失片段。直播则要求独立的时间轴、live edge、有界缓冲、丢帧/跳帧、FEC、切源
和端到端时延语义；不能用文件完整交付的重试策略无限等待旧 segment。

`事实`：当前已有媒体分段索引、ABR playlist、Range pull、多源读取、KCP adapter、live window、FEC、
HLS 输出和跨网关源切换组件及 smoke。`目标`：把 ingest、Mesh 传输、edge window、HLS 输出、QoS、
观测和故障切换组合为可重复部署的私有视频分发 profile，并以启动时间、端到端时延、卡顿率、丢帧、
恢复时间和带宽成本验收。

### 6.2 M3：低成本独立服务与共享底座

当前网关是 **S3-shaped API 子集**，不是完整 S3 兼容实现。已覆盖 SigV4 header 认证、对象
PUT/GET/HEAD/DELETE、Range、ListBuckets 和 ListObjects，以及 release/HLS 专用路由。

> **对外价值主张（目标）**：一台机器即可开始，增加磁盘或机器即可扩展；应用继续使用同一对象
> 接口，数据节点通过安全 Mesh 协作。

M3 面向不同预算提供两个清晰档位：

| 档位 | 目标客户 | 最小形态 | 提供 | 不提供 |
|------|----------|----------|------|--------|
| M3 Starter | 个人、小团队、中小企业 | 单 gateway + 本地持久化 namespace + 文件系统 CAS | 私有对象 API、SigV4、Range、列表、内容校验、重启恢复 | 节点/磁盘高可用、跨 failure domain 副本、自动故障恢复 |
| M3 Cluster | 多站点与高可用场景 | 三 metadata voter + 至少两个 store 副本 | 线性一致 namespace、副本 placement、receipt、repair/GC 和 Mesh 数据面 | 完整 AWS S3 管理面、拜占庭容错、无限容量或零运维 |

M3 Starter 的成本优势来自部署结构，而不是价格口号：单节点即可启动，不要求外部对象服务或外部
数据库，bytes 存在本地不可变 CAS，namespace 本地持久化。客户仍需承担硬件、磁盘、备份、电力、
网络和运维成本；没有真实客户账单、同容量对照和长期运行数据前，不宣称具体节省比例。

M3 Starter 的首个体验目标是“一个服务、一个数据目录即可在单机或局域网开始使用”。这条路径不
依赖 Tailscale、ZeroTier、NetBird 或 FRP。它不等于公网零配置：跨 NAT、跨站点或移动访问仍需要
明确的身份、加密、路由和可达性方案；原生 Mesh 完成产品化前，不把远程直连或吞吐提升作为承诺。

Starter 与 Cluster 必须使用明确 profile。Starter 不得用本地 fallback 掩盖分布式配置错误；Cluster
达不到最小 durable replica 或 metadata quorum 时必须拒绝写入。未来若支持档位迁移，需要单独定义
数据校验、切换顺序、失败回滚和恢复测试，不能只靠复制目录完成升级。

进入“S3 兼容”销售口径前，必须完成并验证明确的 operation matrix，至少包括 bucket CRUD、
ListObjectsV2、multipart、对象键编码、query canonicalization、条件请求和 TurboHTTP S3 client
conformance。未实现能力必须返回明确错误，不能伪成功。

#### 6.2.1 从单机到多个磁盘和机器

**产品目标**：从一台机器、一个数据目录开始；容量或可用性需求增长时，通过增加 store 扩展到多个
磁盘、机器和站点，不改变对象 API、bucket/key 或内容身份，也不要求把全部数据搬回中心服务。

这条扩展路径来自四个架构边界，而不只是“使用了 P2P”：

1. **元数据与 bytes 分离**：Raft 只复制 namespace、manifest 和 placement；对象 bytes 存在 store
   的不可变 CAS，metadata voter 数量不必随每块磁盘同步增长。
2. **内容寻址与幂等复制**：chunk 由 CID 标识，新增 store 可以复制、校验并返回 durable receipt，
   不需要依赖可变文件路径判断内容是否相同。
3. **显式 placement 与 repair**：新写入可选择有容量且符合 failure domain 的 store；存量对象通过
   repair/rebalance 形成新 placement，提交成功后才能移除旧副本。
4. **Mesh-native 数据路径**：gateway、store 和 repair worker 通过已认证 Mesh 路径直接交换 bulk
   data；Controller 发布意图，Raft 提交元数据，两者都不成为所有对象 bytes 的集中转发点。

| 成长阶段 | 目标部署形态 | 保持不变 | 当前边界 |
|----------|--------------|----------|----------|
| 单机起步 | 一个 gateway、本地 namespace、一个 CAS 数据目录 | 对象 API、bucket/key、CID | 技术预览已验证；非高可用 |
| 单机加盘 | 同一机器增加独立 store 数据目录，将新副本放到新磁盘 | 对象 API 与内容身份 | 尚无一键 add/drain、磁盘故障域和自动再平衡产品流程 |
| 多机扩容 | 三 metadata voter，加多个经 Mesh 认证的 store | namespace 与对象 manifest | 已有静态多 store 组件和双 store smoke；动态成员与迁移未产品化 |
| 多站点扩展 | store 分布在不同 failure domain，按策略选择路径和副本 | 签名、CID、审计和访问策略 | 属于 M3 Cluster 目标，尚无 10+ 节点和长期 churn 验证 |

`事实`：当前 `m3_gateway_main` 可静态登记多个 `--store-peer`，并配置 target replicas 和 minimum
durable replicas；现有跨进程 smoke 覆盖一个 gateway 与两个 store。`边界`：这证明数据面组件可组合，
不证明在线扩容已经完成。当前仍缺 `meshctl store add/drain/remove`、容量发现、placement 预演、存量
对象再平衡、Starter 到 Cluster 的验证式迁移、滚动升级和扩容中故障恢复。

低成本的依据是可以从单节点和已有磁盘开始、按需增加 store、让 metadata 与 data 独立扩展，并在
策略允许时使用点到点数据路径；不是“不需要副本、quorum、备份或运维”。销售只有在记录硬件、有效
容量、副本放大、网络、能耗和人工成本后，才能比较单位可用 TiB 成本。

#### 6.2.2 S3、Ceph 与 M3 的关系

“S3 vs Ceph”不是同一层级的比较。S3 既指 AWS 托管对象服务，也常指以 bucket/key、HTTP 和 SigV4
为核心的对象 API；Ceph 是一套分布式存储平台，在同一 RADOS 底座上分别提供 RGW 对象网关、CephFS
文件系统和 RBD 块设备。选型必须先确认客户需要对象、文件还是块语义。

| 方案 | 主要接口与语义 | 适合场景 | 部署与运维形态 | 与 M3 的关系 |
|------|----------------|----------|----------------|-------------|
| AWS S3 / 完整 S3 兼容对象服务 | bucket/key、HTTP API、整对象写入与读取 | 应用对象、备份、制品、媒体和数据湖 | AWS 托管，或由兼容产品提供私有集群 | M3 采用 S3-shaped 入口，但当前不是完整替代 |
| Ceph RGW | 在 Ceph RADOS 上提供 S3/Swift 对象 API | 已有 Ceph 集群的私有云和大规模对象服务 | 除 RGW 外还需维护 MON、MGR、OSD 等 Ceph 组件 | 对象接口方向最接近 M3 Cluster；成熟度、规模和协议覆盖明显领先当前 M3 |
| CephFS | 共享目录、文件、rename、权限等 POSIX 文件语义，由 MDS 管理元数据 | 多主机共享文件、构建目录、用户目录和需要文件语义的应用 | Ceph 集群加 CephFS metadata server 与客户端挂载 | 不是 M3 当前目标；对象 key 不能等同 POSIX 文件系统 |
| Ceph RBD | 可挂载的分布式块设备 | 虚拟机磁盘、容器卷和需要块语义的数据库 | Ceph 集群加块客户端或虚拟化集成 | 不与 M3 对象 API 竞争，M3 不提供块设备 |
| M3 Starter | 单节点 S3-shaped 对象 API、本地 namespace 与不可变 CAS | 个人、小团队和中小企业从一台机器开始的私有对象服务 | 一个服务、一个数据目录；备份和可用性由客户负责 | 以低起步门槛切入，不提供 Ceph 的分布式文件或块能力 |
| M3 Cluster（目标） | 对象 API、Raft namespace、多 store 副本、repair 与原生 Mesh 数据面 | 私有边缘对象、跨站镜像和受策略控制的数据交付 | 目标形态更窄，强调安全 Mesh、边缘路径和统一审计 | 不做通用 Ceph 替代；差异化在网络、数据流和边缘行为的一体控制 |

销售选择规则：

- 客户需要应用通过 HTTP/S3 API 存取对象，且重视单机起步、私有部署或后续边缘分发时，评估 M3。
- 客户需要透明共享目录、原地随机写、文件锁、rename 或既有 POSIX 应用时，选择 CephFS、NFS/SMB
  或其他成熟文件系统；不要用对象 API 模拟后宣称等价。
- 客户需要虚拟机卷或数据库块设备时，选择 Ceph RBD 或成熟块存储。
- 客户已经有 Ceph 运维团队并需要统一承载对象、文件和块存储时，Ceph 通常更合适。M3 只有在
  安全 Mesh、跨站内容交付或节点/数据流策略产生独立价值时才有进入机会。
- 客户需要完整私有 S3 生态、已验证的大规模容量和成熟运维工具时，优先评估 Ceph RGW 等成熟产品；
  当前 M3 只能作为技术预览参与同条件验证。

M3 不应为了追赶 CephFS 或 RBD，把 POSIX、块设备或多套元数据语义塞入对象核心。未来如有明确客户
需求，应以独立、版本化的文件或块适配层评估，并定义 rename、锁、缓存一致性、故障恢复和迁移边界；
对象 namespace、manifest 和 CAS 仍保持单一事实源。当前也没有 M3 与 Ceph RGW/CephFS/RBD 的产品级
adapter 或兼容性 smoke，不能把潜在共存描述为现成集成。

官方资料：

- [Amazon S3 API Reference](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html)
- [Ceph Architecture](https://docs.ceph.com/en/latest/architecture/)
- [Ceph Object Gateway](https://docs.ceph.com/en/latest/radosgw/)
- [Ceph File System](https://docs.ceph.com/en/latest/cephfs/)
- [Ceph Block Device](https://docs.ceph.com/en/latest/rbd/)

#### 6.2.3 磁盘镜像与可写块设备边界

不可变磁盘镜像和可写远程块设备是两种产品。前者可以把镜像视为版本化、内容寻址的大对象：按块
校验、多源拉取、断点续传，完整验证后再原子激活，适合 VM template、设备镜像和离线恢复介质。
它可以复用 release、M3、Range 和多源块拉取，但仍需补镜像格式、分区元数据、稀疏区、激活/回滚和
boot 验证，当前不能宣称已经支持磁盘镜像产品。

可写远程块设备必须拥有独立的 volume 事实源和协议边界，至少定义 sector 范围、写入顺序、flush/
FUA、discard、单写者或多写者、lease/fencing token、快照、崩溃恢复、缓存一致性和路径中断语义。
这些状态不能由 M3 不可变对象 namespace 隐式推进，也不能因为底层已有“block puller”就称为块设备。

目标方案采用“不可变 Hash 数据块 + COW Merkle 映射 + Raft root commit”：Hash 块简化内容校验、去重、
副本和快照，但写入准确性仍由对齐的 volume 协议、durable receipt、写序列、幂等请求、单写者 fencing
和 `FLUSH`/`FUA` 契约共同保证。完整 V1 状态机、失败语义和验证门槛见
[`M3_VOLUME_DESIGN.md`](../M3_VOLUME_DESIGN.md)。

若进入验证阶段，应优先通过成熟 OS 块接口或协议适配层接入，先验证只读镜像和单写者低时延场景，
再决定是否扩展；不为追求产品列表而自创未经验证的块协议。跨公网高时延路径默认不适合数据库等
同步写 workload，必须以 flush 延迟、IOPS、P99、断线恢复和数据一致性测试决定适用范围。

### 6.3 软件定义 Mesh：平台底座

当前 L1 已具备虚拟 IP overlay、DHT、直连/中继、路由策略、ACL、出口节点和静态 MagicDNS。
它不是 P0 分发之外的可选插件，也不只是 VPN 连接层，而是统一安全和行为执行边界。目标 Controller
发布身份、network grant、route grant、path/QoS、service 和 management intent，节点以不可变
snapshot 本地执行，数据流不经过 Controller。

目标产品允许一个安全 Mesh 信任域包含多个隔离的逻辑 Network：共享 Noise/P2P underlay、ICE 和
物理连接，但分别维护 membership、地址池、路由、DNS、packet policy、epoch 和审计。节点可加入
多个 Network，加入两侧也不会自动获得跨网转发权限；external subnet 仍是某个 Network 上的显式
route。稳定 legacy API 仍只有一个 `network_id`/虚拟地址域；实验性 V2 已能在一个
Noise/P2P underlay 上建立多个 userspace IPv4 Network，以签名 membership 和 `network_uid` frame
隔离重叠地址，并能独立更新/删除；另已支持 bounded、确定性、role-gated 的单跳 terminal
subnet-router/exit route；canonical `TCN1` 可用 digest 绑定 route body，bounded reconciler 能原子应用。
该 route 只把 packet 交给授权 gateway callback，不等于安全普通多跳或完整 OS 网关。
Network-scoped DHT/普通多跳、OS attach、deployable Controller 分发和 agent durable 闭环尚未完成。
完整架构与迁移门槛见
[`MESH_MULTI_NETWORK_DESIGN.md`](../MESH_MULTI_NETWORK_DESIGN.md)，当前不能作为成熟企业组网承诺。

这属于控制面/数据面分离的 SDN 模型，但不是由中央 Controller 逐流下发 OpenFlow 规则。产品化仍
依赖生产身份体系、策略编译与签名发布、agent/meshd reconcile、服务化部署和 10+ 节点规模/churn
验证；达到这些门槛前，不单独销售为成熟企业组网产品。

### 6.4 软件定义的控制面、数据面与执行面

```text
操作者 / CI / GitOps
          |
    meshctl / API
          |
Product Controller
身份、角色、网络/路由/管理 Grants、服务、QoS、期望状态、审计
          |
签名、版本化 bundle / MMP command
          |
mesh-agent + meshd + 可选 execution worker
本地验证、原子应用、状态回报、策略执行
          |
Mesh data plane
TUN packet / stream / datagram / file / object / media flow
```

软件定义对象不只包括配置文件，而是三类可验证行为：

- **节点行为**：enroll、approve、revoke、角色/capability、服务状态、升级、reconcile 和 compute 启停。
- **Mesh 行为**：peer 可见性、route/exit/subnet、path 约束、DNS/service discovery、访问策略和故障语义。
- **数据流行为**：traffic class、transport 要求、是否允许中继、QoS、队列/带宽上限、源选择、
  边缘镜像、副本/repair 和 flow audit。

Controller 保存意图和策略 epoch；节点保存已验证的执行 snapshot。Controller 故障不能成为现有数据
流的转发依赖，节点也不能在分区期间自行扩大权限。策略更新以完整 snapshot 原子替换，失败保留上一
个有效 epoch 并报告原因，不能形成半应用状态。

`事实（2026-08-13）`：内部控制骨架已增加 transport-neutral resource/intent/observation/
operation/event/receipt、MMP signed control frame、Iris `/v1/control` H1/H2 WebSocket 入站、
有界 SPSC channel、单 owner desired/observed state、删除 tombstone、request 幂等、generation
一致的有界分页 snapshot、event cursor、mTLS H1/H2 status/events/durable-receipt 查询和 agent
listener/shutdown 生命周期，以及精确 provider ID admission 和有界 function reconciler。网络
callback 只做认证、校验和有界入队，不能直接修改节点、网络或功能状态。

`边界`：H2/WS 是控制接口适配器，不是事实源，也不是功能原语本身。当前 Controller 到 agent 的
WS 入站命令和 agent 端 H1/H2 状态/事件/receipt 拉取均有内部实现；H1 与禁止 fallback 的真实 H2
mTLS loopback client 均已测试；逐命令
signed-intent/result WAL、authenticated checkpoint/compact、provider completion peek/apply/ACK 和
restart recovery 已接入 agent。生产方案改为 agent 主动建立 mTLS H2/RFC 8441 session，使 NAT 后
节点无需开放入站端口；当前节点 listener 只作为内部验证/诊断适配器。`meshd` 本地 IPC 已选择
独立 `FlowMQ::FlowMQ` ROUTER/DEALER over CoroNet TLS/mTLS loopback + `MeshNodeIPC/1`。transport-neutral canonical codec、
显式 Mesh/provider scope、bounded copied-frame channel、single-owner result retention、Network executor、
client/server runtime 和可注入 reconciler 的 prestaged builtin/Native provider 已完成同进程真实 mTLS
组件测试。FlowMQ ROUTER v4/CONNECT v3 已实现双向 certificate-to-identity verifier，Mesh adapter 强制
TLS 1.3-only、current/next fingerprint exact map 和非零 policy generation；测试覆盖独立
server/client current/next leaf、正常双向传输、client/server 任一侧未映射或 old-pin 证书拒绝、双向
EKU 错配、真实 overlap、listener restart 重认证与使用不同端证书的进程边界 typed mTLS 往返。显式
client TLS config 禁用 session cache。远程控制路径已经组合 durable agent WAL、H2-only outbound
client、typed HELLO/CLAIM/COMMAND/RECEIPT、Controller durable outbox/session 和证书 identity
registry；在线 session 绑定 durable generation、实际 TLS leaf digest 和 identity-policy generation，
换证、重连或 policy reload 会 fence 旧 session。生产证书签发/私钥安全存储、FlowMQ 本地通道自动
换证、发布级 service-manager 和审计仍按
[`FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md`](../FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md) 作为剩余发布门槛。当前 adapter 拒绝
CoroNet Pipe，不能作为 TLS fallback。digest-pinned Native/TurboWASM child process、bounded I/O、
timeout 和 process-tree cleanup 已有实现；仍缺正式 Controller 应用/数据库、发布级 agent service、
production OS sandbox profile 和完整 observation/audit 汇总。checkpoint
文件 I/O 禁止阻塞 CoroNet 事件循环。因此
“通过 H2/WS 下发命令、收集状态”和
“通过节点定义功能/网络”已有明确协议边界和部分
可运行路径，但尚未形成可售闭环。详细所有权、权限、失败与迁移语义见
[`MESH_PRODUCT_CONTROL_PLANE.md`](../MESH_PRODUCT_CONTROL_PLANE.md)。

后续本地能力优先复用独立 FlowMQ 的公开能力，而不是继续增加私有 socket。P1 command/result 已固定为
ROUTER/DEALER；可重建状态、采样 telemetry、release transfer 与 Native worker 必须使用独立容量和安全域，
并按届时公开 API 重新设计，不能依赖旧 TurboFlow facade。FlowMQ 不承载唯一 audit、文件块、媒体帧或
packet payload，也不替代 agent WAL、权限判断和 durable worker claim；这些后续 channel 尚未实现，
不能列为现有产品能力。

### 6.5 安全 Mesh 与多传输模型

产品契约分为三层，不能把“多种传输方式”理解为多个彼此独立的网络：

```text
文件 release、对象、流、审计
              |
统一的安全 Mesh 契约
节点身份、准入、策略、路由、服务发现、审计
              |
多种路径与数据协议
Mesh 直连 / Mesh 中继 / ICE 选路
可靠块流 / CoroNet TCP/TLS / KCP / Mesh 虚拟 IP 上的 HTTP/S3
```

统一契约必须满足：

- 节点身份、准入和访问策略只有一个主事实源；transport 不得各自维护另一套授权状态。
- 每条连接都能绑定已认证的 Mesh peer 和策略判定；无法绑定时 fail-closed。
- release ID、CID、发布者签名、审计标识和错误语义不随传输切换而改变。
- 路径选择可以考虑可达性、延迟、丢包、带宽和流量类型，但不得静默降低认证、加密或完整性要求。
- 文件和对象优先使用可靠、有序且支持 Range/断点续传的数据通道；实时流可在策略允许时使用 KCP，
  但仍服从同一 Mesh 身份与访问策略。

`事实`：仓库分别具备 TurboP2P 直连/中继、ICE 信号与检查、CoroNet TCP/TLS、KCP、可靠块流、
HTTP/S3-shaped gateway 等组件。`边界`：这些组件尚未全部接入统一的 transport 选择、身份绑定和
产品级跨层 smoke，因此当前只能按已验证路径演示，不能宣称完整的自动多传输产品已经就绪。

### 6.6 `meshctl`：网络、数据与执行的统一入口

产品形态只提供一个面向操作者的控制入口，按领域分组：

| 领域 | `meshctl` 目标操作 | 状态事实源 |
|------|--------------------|------------|
| 节点 | enroll/approve/revoke、角色、capability、服务状态、reconcile、升级与诊断 | Controller inventory 与 OS service manager |
| Mesh 网络 | peer、route、path、exit/subnet、DNS/service、policy、health 与 policy epoch | Mesh 身份、Controller policy 与节点执行 snapshot |
| 数据流 | traffic class、transport 约束、QoS、队列/带宽、源选择和 flow audit | signed flow policy 与节点有界运行状态 |
| 文件与 release | pack、publish、mirror、pull、verify、withdraw、revoke、uninstall、purge、受管节点文件删除、版本、镜像策略和审计查询 | release manifest、tombstone、desired assignment 与节点执行 journal |
| 对象与流服务 | 对象查询、Range/副本状态、repair、流服务与 QoS 查询 | M3 元数据、不可变对象与流状态 |
| 节点执行 | deployment 查询、signed run、status、cancel、result 与审计 | 目标节点 durable command journal |

`事实`：当前 `meshctl` 已覆盖网络启动、配置检查、status、health、DHT、peer、route、policy、
admission、诊断和 ping。release 的 pack/publish/mirror/pull 当前位于独立的
`mesh_stream_media_main` 示例 CLI；对象、流和节点执行也尚未形成稳定的 `meshctl` 命令面。

`目标`：`meshctl` 通过类型化 Controller API 提交期望状态，支持 validate、test、diff、apply、查看
每节点 applied epoch 和以新 epoch rollback。它只编排各领域公开 API，不复制状态，也不让文件或
执行命令绕过 Mesh 身份、策略、审计和配额。命令失败必须指出失败领域和阶段；禁止在网络不可验证
时把操作降级为直接访问物理端点，也不提供通用远程 shell。

### 6.7 节点 WASM 沙箱

节点执行是安全 Mesh 的可选能力，不是所有节点的默认职责。只有显式登记的计算节点可以声明执行
能力；relay、exit、DNS、gateway 和普通边缘节点不会因加入 Mesh 自动获得 WASM 依赖或执行权限。

`事实`：当前 execution plane 已具备 prestaged deployment registry、模块 SHA-256 digest 绑定、
TurboRuntime raw WASM runner、真实 guest test、capability 求交、内存/栈/deadline/host-call/I/O
配额，以及本地 durable journal、去重、重启恢复和签名结果等 E1/E2 组件。`mesh-agent` 的实际
Native/TurboWASM Provider 已在启动 child 前持久化稳定 claim；terminal ACK 丢失可返回原结果，
未决 `RUNNING` 在重启时进入 `FAILED_INDETERMINATE` 且不重跑。新 control core 另行定义
了 `RUN_BUILTIN`、`RUN_NATIVE`、`RUN_WASM` 权限，以及与权限正交的 runtime availability；默认
policy 不允许 Native 或 WASM，且 WASM unavailable 时即使 grant 含 `RUN_WASM` 也会拒绝。

新 control core 还实现了固定 function document、有界持有的 reconciliation document，以及只接受
精确注册 builtin/Native provider ID 的非阻塞 reconciler。它既用 fake Native provider 验证
APPLY/DELETE、背压、completion、observed state 和 shutdown interrupt，也已通过独立
`FlowMQ::FlowMQ` ROUTER/DEALER mTLS provider adapter 完成真实 reconciler -> IPC runtime -> test
executor -> RESULT -> exact ACK 组件闭环；控制消息不能携带路径、argv、动态库名或 executable bytes。

`边界`：第三方 WASM 节点执行明确推后。真实 Grant authority、公开 MMP feature rollout、受管
低权限 service account、Windows restricted token/AppContainer、Linux namespace/cgroup/seccomp、网络限制和
完整审计闭环尚未完成。E3 之前不能把内部签名 intent 路径作为稳定第三方网络执行接口，E6 之前
不能宣称多租户生产隔离或“生产级
WASM 沙箱”。当前已有真实 out-of-process Native/TurboWASM worker，但只能执行精确预部署且 digest
匹配的 artifact；raw WASM 固定为 `core|utils|app`，HTTP/file preopen 必须等 immutable manifest 与
artifact digest 共同绑定后再开放。权限位或组件测试均不等于可以执行任意本机程序。

目标安全契约：

- 只运行本机 registry 中预部署且 digest 匹配的 WASM；网络请求不能携带宿主路径、任意 URL 或代码。
- signed grant、本机 host policy 和 manifest capability 取交集，只能缩小权限，不能扩大权限。
- guest 不获得 shell、任意 argv、raw socket、管理密钥、物理 endpoint 或未授权文件路径。
- CPU、内存、deadline、host call、输入、输出、并发和队列均有硬上限；超限明确失败。
- package/input/output 可由 M3 按不可变 digest 提供，但对象可用不代表获得执行授权。
- 命令 ID、授权、部署 digest、结果、资源用量和审计记录可关联；重试和重启保持最多一次执行。

## 7. 与 Tailscale、ZeroTier、NetBird、FRP 的关系

### 7.1 是竞品和参照，不是当前传输后端

Tailscale、ZeroTier 和 NetBird 都在安全 Mesh 网络层管理设备身份、地址、连接、路由和访问策略，
因此与原生 Mesh 在这一层直接竞争。FRP 是把 NAT 或防火墙后的服务经代理暴露出去的反向代理工具，
不提供同等的 Mesh 身份、全网策略和节点行为模型。Mesh / M3 的差异化目标，是把软件定义的节点、
网络与数据流行为，以及文件、对象、流和可选 WASM 执行纳入同一策略与审计模型，而不是把上述产品
包装成自己的 transport backend。

```text
                         网络与控制范围                 上层数据/执行范围
Tailscale                身份化 WireGuard 网络          通用 IP 承载
ZeroTier                 可编程虚拟网络                通用 IP/L2-L3 承载
NetBird                  身份、策略与 WireGuard 网络     通用 IP 承载
FRP                      反向代理、隧道与服务暴露        经 frps 转发或访客点对点连接
Mesh / M3                节点、路径、服务与数据流意图    release、对象、流、repair、可选 WASM
```

当前仓库没有 Tailscale、ZeroTier、NetBird 或 FRP 的适配器、身份映射、策略同步、部署配置或产品级
兼容性 smoke。release CLI 接受普通 `host:port` 并通过 HTTP 访问端点，只能说明它可以使用可路由
IP，不能据此宣称“支持第三方 Mesh 或 FRP”。

### 7.2 竞合矩阵

| 产品 | 主要产品契约 | 部署取向 | 与原生 Mesh 的关系 | Mesh / M3 应学习或区分之处 |
|------|--------------|----------|----------------------|----------------------------|
| Tailscale | WireGuard 身份化私网、直连/NAT traversal、DERP/peer relay、MagicDNS、subnet router、exit node 和访问控制 | 托管协调服务；客户可部署 relay | 安全组网直接竞品 | 身份与策略体验成熟；Mesh / M3 以统一定义节点、数据流、内容和执行行为区分 |
| ZeroTier | 可编程虚拟二/三层网络、controller、managed routes 和 flow rules | ZeroTier Central 或自托管 controller | 虚拟网络与路由直接竞品 | 网络抽象和可编程性成熟；Mesh / M3 强调统一数据交付语义和边缘内容事实源 |
| NetBird | WireGuard 零信任 overlay、identity/access、management、signal、relay、routes 和 DNS | Cloud 或自托管 | 身份、策略和控制面直接竞品 | 云与自托管控制面成熟；Mesh / M3 强调私有数据面及节点、内容、流和执行的一体策略 |
| FRP | TCP/UDP、HTTP(S) 等反向代理、隧道和服务暴露 | 自托管 frps；流量可经集中 server 转发，也支持访客点对点模式 | 远程暴露服务的替代路径，不是完整 Mesh 竞品 | 配置和部署相对直接；Mesh / M3 目标是把可达性、身份、路径策略、数据语义和审计统一起来 |
| Mesh / M3 | 软件定义安全 Mesh，加 release、内容寻址对象、边缘镜像、流、repair 和可选 WASM | 私有部署目标；当前仍是 beta/demo | 本产品 | 组合方向有差异，但身份、Controller、规模和运维成熟度尚未达到上述产品水平 |

矩阵描述的是产品边界，不是性能排名。没有同拓扑、同负载和同故障模型的基准数据时，销售不得
宣称原生 Mesh 比 Tailscale、ZeroTier、NetBird 或 FRP 更快、更安全或更可靠。可以验证的假设是：
当现有 NAS 路径实际经过集中 relay 或单点 frps 时，吞吐上限和时延会受到该转发节点及其上下行链路
约束；原生 Mesh 只有在建立授权直连并通过同条件测量后，才能宣称减少中继流量或改善性能。

### 7.3 销售应答

客户已经使用 Tailscale、ZeroTier、NetBird 或 FRP 时，必须明确当前边界：

> M3 Starter 在单机或局域网内不依赖第三方组网或反向代理。Mesh / M3 当前没有经过验证的第三方
> Mesh 或 FRP 集成；双方可以在 IP 层共存，但身份、策略、路由、故障切换和端到端安全仍需专项
> 验证，不能作为现成支持承诺。设计伙伴试点以原生安全 Mesh 闭环为准。

客户只需要远程访问、设备互联或 subnet routing 时，成熟组网产品通常是当前更合适的选择。
Mesh / M3 不应以“更好的 VPN”进入首轮销售，而应从“用一个策略面统一网络、数据流、内容交付和
边缘节点行为”切入。

对 NAS 场景的销售叙事应是“本地先用、按需联网、直连优先”，而不是“替换一个隧道工具”。先让
客户把适合对象访问和分发的数据放入一台机器或一个局域网内的 M3 服务；再由原生 Mesh 管理远程
身份、路径和流量策略。中继是直连不可用或策略要求时的受控路径，不应成为所有数据的默认中心
瓶颈。现有 SMB/NFS 目录的透明远程挂载不属于当前承诺。

客户已经使用对象存储或制品库时，先确认其是否解决跨站镜像、断网边缘、发布者信任和统一审计。
如果现有方案已经满足这些要求，就没有必要引入 Mesh / M3。

### 7.4 产品策略

1. **先交付 M3 Starter**：把已验证的单节点对象闭环产品化，为个人和中小企业提供低成本入口；
   不要求客户先部署完整 Mesh 集群。
2. **并行完成最小软件定义闭环**：P0 把身份、版本化策略、节点本地执行、直连/中继和 release 交付
   作为同一产品验收，不能让分发绕开安全 Mesh。
3. **再扩展数据行为**：在同一控制模型上增加 traffic class、QoS、服务、对象、文件同步和流，
   不为每种传输或 workload 建立控制孤岛。
4. **再开放受控执行**：只在完成网络授权、独立低权限 worker、持久化 journal 和审计闭环后，
   通过 `meshctl` 向显式登记的计算节点开放 WASM 任务。
5. **最后评估第三方互操作**：只有明确客户需求后，才设计版本化 adapter，并单独验证身份映射、
   策略一致性、路由冲突、故障语义和安全边界；在此之前不列为支持能力。
6. **成熟后再单卖组网**：完成 10+ 节点、NAT/churn、控制面、服务化和长期运行验证后，才单独进入
   企业组网市场。

内容层的 release ID、CID、签名和审计不依赖具体传输，但传输必须依赖安全 Mesh 提供的身份与策略。
这是“内容语义可跨传输”与“可以跨第三方 Mesh 部署”之间的关键区别。

### 7.5 官方资料（2026-08-05 核对）

- [Tailscale 产品与网络概念](https://tailscale.com/docs/concepts/what-is-tailscale)
- [Tailscale 直连、peer relay 与 DERP 连接类型](https://tailscale.com/docs/reference/connection-types)
- [ZeroTier 协议与虚拟网络](https://docs.zerotier.com/protocol/)
- [ZeroTier 自托管 network controller](https://docs.zerotier.com/controller/)
- [NetBird 与传统 VPN 的官方比较](https://github.com/netbirdio/docs/blob/main/src/pages/about-netbird/netbird-vs-traditional-vpn.mdx)
- [NetBird 自托管服务配置](https://github.com/netbirdio/docs/blob/main/src/pages/selfhosted/maintenance/configuration-files.mdx)
- [FRP 项目与功能说明](https://github.com/fatedier/frp)

## 8. 商业化路线图

### P0-A：M3 Starter

**目标**：让个人或中小企业在一台自有节点上，以明确的容量和备份责任获得可安装、可升级、可恢复
的私有对象服务；单机或局域网起步不要求先配置第三方 Mesh、反向代理或集中转发。

交付范围：

- 将单节点 gateway 从 example 提升为稳定服务入口，提供一份最小配置、数据目录、健康检查和
  systemd/Windows 服务安装方式。
- 提供“一个服务、一个数据目录”的本机和局域网快速起步路径；公网监听默认关闭，远程接入必须
  显式配置认证、TLS 和允许的网络边界。
- 移除 demo credential；提供本地初始化、credential 安全存储、轮换和撤销，默认启用 TLS。
- 保持 S3-shaped 边界清楚，发布已实现 operation matrix；未支持操作返回明确错误。
- 完成流式上传/下载、对象键编码、容量上限、磁盘空间预检、并发/带宽限制和安全停机。
- 提供可验证的 backup/restore、升级/回滚、数据目录迁移和损坏扫描流程。
- 通过 `meshctl object` 或文档化的标准 S3 client 完成 put/get/head/list/range/delete 与诊断。
- 提供容量、请求数、读写 bytes、延迟、错误、磁盘占用和完整性失败指标。

退出门槛：

- 新用户可按单份文档完成安装、创建 credential、写入首个对象、Range 读取和删除；记录实际步骤、
  时间、内存、空闲 CPU 与磁盘开销。
- 正常重启、异常终止后重启、备份恢复和升级回滚均保持 namespace 与对象可验证。
- 未签名、错误密钥、篡改、过期、超限和磁盘空间不足全部 fail-closed，不返回伪成功。
- 明确显示“单节点、非高可用”状态；健康检查不能把本地可读误报为已有远端副本。
- 在至少三种代表性小规模容量/请求负载下记录总资源成本；没有对照数据前不宣传节省百分比。

### P0-B：软件定义 Mesh 设计伙伴试点

**目标**：在受控的三站点软件定义安全 Mesh 中，通过统一 `meshctl` 发布最小网络意图，并交付
可安装、可审计、强制验签、能通过直连/中继路径运行的软件分发试点。

交付范围：

- 将 release CLI 和 gateway/store 从 example 提升为有稳定配置和生命周期的产品入口。
- 建立 `meshctl` 领域命令框架，先收口 node、network、flow 与 release 操作；保持现有命令兼容，
  并调用各领域公开 API，不复制网络或内容状态。
- 为 release 增加目标节点/标签 selector、desired assignment、agent reconcile、批量状态、取消和重试；
  Controller 只推送签名意图，目标节点从授权来源拉取并验签，不经 Controller 传输文件 bytes。
- 增加签名 deletion tombstone 及 withdraw/revoke/uninstall/purge；在线节点停止服务并删除受管版本，
  离线节点重连后继续收敛，CAS 只在引用归零、retention/grace 到期且无 hold 时物理回收。
- 提供 `meshctl node file delete` 受控命令：只接受策略定义的 managed root、相对路径和可选 expected CID，
  通过节点 durable journal 执行；不开放任意 shell、绝对路径或无界递归删除。
- 强制发布者签名和拉取验签；私钥改由 OS credential store 或受限 stdin/FD 提供。
- 建立每租户可信公钥、轮换和吊销事实源；禁止自动回退到无签名模式。
- 以 release manifest 为发布事实源，版本列表、verify、stats 和审计从已提交状态派生。
- 建立生产节点身份、准入和版本化策略事实源；支持 validate、diff、apply、applied epoch 查询和
  以新 epoch 回滚，并把 release、gateway 与 store 连接绑定到已认证 Mesh peer。
- 至少定义 control、interactive、bulk 三类数据流意图，约束访问、是否允许中继、队列和带宽；节点
  本地执行，Controller 不转发业务数据。
- 固化 transport 契约和选路诊断；至少验证 Mesh 直连与 Mesh 中继两类路径，禁止不安全自动降级。
- 增加租户、release 数、对象大小、并发和带宽配额。
- 提供 TLS、健康检查、结构化诊断、安装包及 systemd/Windows 服务入口。
- 建立原生安全 Mesh 跨层闭环：三站点 + 三 voter Raft + 至少两个 store 副本 + release 发布、
  镜像与拉取。

退出门槛：

- 三站点在原生 Mesh 身份和策略生效的前提下，持续通过发布、镜像、拉取和重启恢复。
- 网络意图发布后，每个节点报告明确的 applied/rejected epoch；部分失败不伪装为全网成功，回滚不
  倒退 epoch。
- 直连与强制中继路径均通过同一 release 流程；路径切换不改变 release ID、发布者信任、审计记录
  或失败语义。
- control、interactive、bulk 流量按各自访问和路径约束执行；超出队列/带宽上限时按策略拒绝或背压，
  不静默借用未授权路径。
- 未知节点、被撤销节点和策略禁止的跨站访问全部 fail-closed，且留下可关联审计记录。
- leader、单 store、边缘进程故障时，不返回未验证内容，不产生双重发布事实。
- 缺失签名、未知/吊销公钥、篡改清单、篡改对象和重放请求全部 fail-closed。
- 发布、删除、密钥变更和下载产生可关联的审计记录。
- 一次 release assignment 对每个目标节点给出 applied/rejected/pending 与失败阶段；离线节点恢复后
  自动收敛，重复 assignment 不重复安装或绕过验签。
- release 删除对每个目标节点给出 applied/rejected/pending；撤回后旧 epoch 不能恢复服务，purge
  dry-run 能列出仍存引用和阻塞原因，GC 不删除共享或仍被引用的 CID。
- managed-root 外路径、遍历路径、symlink/reparse-point 穿越、CID precondition 失败和超配额递归删除
  全部被拒绝；节点部分失败不会被汇总为成功。
- Windows 与 Linux 的安装、升级、回滚和数据保留步骤可重复执行。

### P1：软件定义边缘数据平台

**目标**：把 M3 Starter 和 Mesh 试点扩展为 M3 Cluster、多租户对象与软件定义网络平台。

交付范围：

- 完成 S3 operation matrix、TurboHTTP S3 conformance、multipart 与流式请求体。
- 完成多租户 ACL、容量/带宽配额、生命周期、事件和用量聚合。
- 建立三 metadata voter、至少两个跨 failure domain store 副本、leader-routed linearizable read、
  durable receipt、repair/GC、故障注入和 Starter 到 Cluster 的验证式迁移流程。
- 通过 `meshctl store` 完成 discover、plan、add、drain、remove 和 status；扩容计划必须显示新增容量、
  failure domain、预计迁移 bytes、replica debt 和带宽上限，执行中断后可恢复或安全回滚。
- 新 store 加入后，新写入按最新 placement policy 分配；存量对象只通过有界 repair/rebalance 迁移，
  新 placement 提交并满足最小 durable replicas 前不得删除旧副本。
- 建立 Mesh CDN placement profile：按节点标签、内容类型、容量、TTL、路径和 traffic class 声明
  origin/cache/edge 角色；提供有界缓存、驱逐、预热、source selection、回源失败和内容校验诊断。
- 按 [`MESH_PRODUCT_CONTROL_PLANE.md`](../MESH_PRODUCT_CONTROL_PLANE.md) 推进身份、IPAM、
  MagicDNS、策略编译、签名发布、节点期望状态、审计和控制台。
- 将 path preference、traffic class、QoS、service discovery、exit/subnet role 和 flow audit
  纳入同一版本化 intent 模型，并由节点原子执行 immutable snapshot。
- 建立 P50/P95/P99、origin offload、replica debt、repair、错误率和审计完整性指标。
- 验证 10+ 节点、不同 NAT、持续 churn、分区恢复和容量压力。

退出门槛：先定义目标客户 SLO 和容量模型，再以长期运行、故障注入和升级回滚结果决定是否 GA。

### P2：增量产品线

- 文件同步：补齐冲突解决、版本历史、权限和恢复语义。
- 视频分发：组合点播 Range/HLS、多源 edge cache、实时 ingest、KCP/FEC、live window、源切换、
  DVR/回看和播放器兼容性，以端到端视频指标而不是文件吞吐验收。
- 不可变磁盘镜像：定义镜像 manifest、稀疏区、分区元数据、按块校验、断点续传、原子激活和回滚；
  只复用文件/对象数据面，不宣称为可写 block volume。
- 节点执行：完成 E3-E6，包括 MMP feature 协商、真实 Grant authority、独立低权限 OS worker、
  command journal、命令审计、撤销、进程树清理和故障恢复，再由 `meshctl` 开放 signed run。

### 远期研究：可写块设备

只做需求和技术验证，不作为 P0-P2 销售承诺。先选择成熟 OS/协议适配边界，定义 flush/FUA、fencing、
快照、崩溃一致性和断线恢复测试；只有单写者正确性、故障恢复、目标时延和数据完整性均通过，才决定
是否建立独立 volume 产品线。不能让该研究改变 M3 不可变对象的状态归属或延迟近期文件/CDN 路线。

## 9. 试点成功指标

每个设计伙伴项目在启动前记录基线，并共同确认目标值：

| 指标 | 说明 |
|------|------|
| 首次可用时间 | 从安装开始到首个已认证对象 PUT/GET 成功的步骤数与耗时 |
| M3 资源成本 | 按可用容量记录硬件、磁盘、副本、带宽、备份、空闲 CPU/内存和运维时间 |
| 扩容效率 | 从发现新 store 到可接收新写入、完成目标再平衡的时间、迁移 bytes、带宽和人工步骤 |
| 对象可靠性 | PUT 成功后重启/恢复仍可校验的对象比例；未检测损坏必须为 0 |
| 备份恢复 | 完整备份、恢复和校验的耗时、恢复点与失败结果 |
| 发布成功率 | release 从发布到所有目标边缘可验证的比例 |
| 推送收敛 | assignment 下发到各目标 applied/rejected 的 P50/P95/P99、离线补齐时间和重复安装数 |
| 交付时间 | 发布提交到边缘可拉取的 P50/P95/P99 |
| 骨干回源卸载率（origin offload） | 由边缘服务的下载字节占比 |
| CDN 效率 | cache hit、重复跨站 bytes、source 切换、驱逐、预热时间和单位有效交付成本 |
| 视频体验 | 首帧时间、端到端时延、卡顿率、丢帧/FEC 恢复、切源时间和播放失败率 |
| 完整性结果 | CID、清单和签名失败数；未检测篡改必须为 0 |
| 恢复时间 | gateway、leader 或 store 故障后的恢复时间 |
| 路径可用性 | 直连成功率、中继占比、路径切换成功率和恢复时间 |
| 策略有效性 | 未授权跨站请求的拒绝率必须为 100%，并能关联身份和规则 |
| 策略收敛 | 发布到各节点 applied/rejected epoch 可见的 P50/P95/P99；不得误报全网成功 |
| 数据流执行 | 各 traffic class 的队列、带宽、丢弃、背压和路径约束是否符合已发布意图 |
| 运维成本 | 部署、升级、回滚和新增站点所需人工步骤 |
| 审计完整性 | 发布、删除、密钥和下载事件的可关联比例 |

没有客户基线或可重复测试时，不把目标值写成产品事实。

## 10. 技术能力证据

### L1 组网

- 虚拟 IP overlay、DHT 发现与路由传播、ICE 直连信号、1-hop 中继和多跳学习。
- CIDR、node-id、协议 major 准入；方向、协议和端口包策略。
- pinned CIDR、子网路由、local egress fail-closed 和静态 MagicDNS。
- `turbo_mesh.h`、`meshctl`、`meshd`、节点证书和 MMP 签名信封。
- 实验性 additive V2：共享 underlay 的多 userspace Network、签名 membership、direct-member 与
  role-gated terminal subnet/exit packet、`network_uid` frame、重叠 IPv4 隔离、generation fencing
  和独立 detach；完整范围与缺口见
  [`MESH_MULTI_NETWORK_DESIGN.md`](../MESH_MULTI_NETWORK_DESIGN.md)。

### L2 分发

- 可靠有序块流、多源选择、文件 manifest diff 和断点续传。
- 媒体分段、ABR、Range/206、live edge、FEC、KCP、HLS 和源切换。
- 相关实现位于 `mesh/src/mesh_stream_*`、`mesh_sync_engine.*` 和 `mesh_media_*`。

### L3 内容服务

- 不可变 chunk CAS、manifest V2、CID、placement、receipt、repair 和 GC。
- 本地 namespace、Raft adapter、单 voter 和多 voter 元数据节点。
- M3 gateway 对象 API、Range、列表、release/HLS 路由与 SigV4 verifier。
- release pack/publish/mirror/pull、深层路径、清单 digest、可选发布者签名和逐对象校验。

### L4 节点执行

- typed Grant/Request/Result、capability/limit 求交和有界状态机。
- prestaged deployment registry、digest 绑定和 TurboRuntime raw WASM runner。
- 本地 durable journal、去重、restart recovery、签名结果、worker queue 和 egress 组件。
- control core 已区分 builtin/native/WASM permission 与 runtime availability；默认不启用 Native/WASM。
- control agent 已接有界 builtin/Native provider strategy、signed-intent/result WAL、authenticated
  checkpoint/compact、durable receipt 和 restart reconcile；Network resource 已可对注入的 userspace
  fabric 执行 canonical APPLY/DELETE、result-WAL-before-observed 和重启重建；prestaged builtin/Native
  provider adapter 已通过独立 `FlowMQ::FlowMQ` mTLS 通道由真实 reconciler 驱动。Network 路径已有
  借用 userspace fabric、拥有 bounded
  reconciler/executor/server runtime 的内部 `meshd` 组合，并完成真实 mTLS 双 Network APPLY、独立
  DELETE、attach/detach、RESULT/ACK 和 shutdown drain 测试，并接入默认关闭、严格校验的 daemon 配置。
- 当前完成本地 E1/E2、控制提交/恢复，以及 digest-pinned Native/TurboWASM child process；E3-E5
  产品 rollout 和 E6 低权限账户、OS sandbox profile、审计/跨平台验证尚未完成，第三方 WASM 默认关闭。

这些能力分别有测试或 smoke；“分别验证”不等于“已完成生产级组合验证”。

## 11. 验证快照

2026-08-05，在 commit `9f99f2f`、Windows Release 构建上复验：

```powershell
ctest --preset win-release-user --output-on-failure
```

结果：81/81 通过，总耗时 200.34 秒。

release 组件路径使用 PowerShell 7+ 复验：

```powershell
pwsh -File mesh/scripts/run_mesh_release_download_smoke.ps1
pwsh -File mesh/scripts/run_mesh_release_mirror_smoke.ps1
```

结果：两条 smoke 均通过。Windows PowerShell 5 不支持脚本使用的 `-SkipHttpErrorCheck`，因此验证
说明必须要求 `pwsh` 7+，不能只写 `powershell`。

其他产品级 smoke 位于 `mesh/scripts/`，覆盖 store、gateway、Raft、media、live、failover 和
two-tier 场景。任何“全绿”声明都必须同时记录 commit、平台、日期和实际执行清单。

## 12. 风险与边界

- **成熟度**：整体仍是 beta / demo，不能称为 GA。
- **信任**：当前发布者签名和消费者验签为显式选项；P0 产品 profile 必须改为强制。
- **凭证**：网关仍使用单 demo credential 和默认测试密钥路径，不可用于生产。
- **协议**：网关是 S3-shaped 子集，不是完整 S3 兼容服务。
- **NAS 语义**：当前不提供 SMB/NFS、透明目录挂载或既有 NAS 共享加速；相关互操作未经验证。
- **Ceph 边界**：当前不提供 CephFS 的 POSIX 文件语义、RBD 块设备或 Ceph adapter；也没有与 RGW
  的同条件兼容性、性能和运维成本对照，不能宣称替代 Ceph。
- **Starter 可用性**：单节点没有节点或磁盘冗余；未验证 backup/restore 前不能承载唯一副本。
- **扩容成熟度**：当前多 store 依赖启动时静态登记；尚无在线 add/drain/remove、自动再平衡或已验证的
  Starter 到 Cluster 迁移，不能把架构可扩展性描述为现成的一键扩容。
- **成本证据**：低成本依据是较小起步拓扑；尚无客户 TCO、同容量竞品账单或长期资源基准。
- **传输**：当前 release smoke 使用本机明文 HTTP；生产需要 TLS 与明确的端到端威胁模型。
- **多传输**：直连、中继、TCP/TLS、KCP 和 HTTP/S3 等组件尚未全部服从统一身份、策略和自动选路。
- **第三方连接**：没有 Tailscale、ZeroTier、NetBird 或 FRP adapter 与兼容性验证，当前不属于支持范围。
- **远程路径性能**：集中 relay 或 frps 可能成为 NAS 吞吐瓶颈，但原生 Mesh 尚无同条件基准；完成
  授权直连、路径诊断和端到端测量前，不承诺性能优于现有工具。
- **文件推送**：当前只有 publish/mirror/pull 内容流程，没有 Controller assignment 与 agent reconcile；
  不能把命令行镜像描述为已完成的节点组推送产品。
- **Mesh CDN**：两级分发、Range、多源和 failover 尚未服从同一 placement/cache policy，也没有驱逐、
  预热和长期命中率数据；当前不是可替代公共 CDN 的生产服务。
- **视频产品化**：已有 HLS、KCP/FEC、live window 和切源 demo，但 ingest、播放器兼容、DVR、端到端
  SLO 与安全 Mesh 组合尚未闭环。
- **块设备**：仓库没有 NBD/iSCSI/FUSE 或其他块设备实现；现有分块与多源拉取只支持数据传输，不能
  推导出 sector、flush、fencing 或崩溃一致性。可写 volume 当前不属于支持范围。
- **控制入口**：当前 `meshctl` 只覆盖网络操作；文件/release、对象、流和执行仍是分散入口或内部组件。
- **SDN 控制面**：已有 H1/H2 WS 入站、mTLS H1/H2 状态/事件/receipt 拉取、MMP control frame、有界 channel、
  desired/observed、operation/event、精确 provider registry、有界 reconciler、统一 state/replay
  signed-intent/result WAL、带 snapshot/index 一致性校验的 authenticated checkpoint/compact、provider completion peek/ACK；
  standalone agent 已能对注入 fabric 执行 Network APPLY/DELETE，并以 result-WAL-before-observed 和 restart rebuild
  收敛 userspace Network；agent 主动拨出的 H2-only mTLS typed sync、Controller durable outbox/session、
  certificate lifecycle/identity registry 已有组件和组合测试；`meshd` 已有默认关闭且严格校验的
  FlowMQ/mTLS 配置、唯一 fabric underlay owner 和有界 drain 接线；产品 Controller application/database、
  agent/FlowMQ 发布进程接线、生产私钥存储、策略编译/签名、审计和全网 epoch 收敛仍未形成闭环。生产拓扑
  不应要求 Controller 直连 NAT 后的节点。
- **节点执行**：Native/WASM 权限和 availability 已分离，Native provider strategy 已接 agent，且
  typed FlowMQ provider adapter 已通过真实 reconciler/mTLS/RESULT/ACK 集成测试。execution plane 已有
  digest-pinned Native 和 authenticated TurboWASM child process，强制有界 I/O、timeout、process-tree
  cleanup；Provider durable claim 已覆盖 lost ACK、restart recovery 与 indeterminate fencing，生产
  配置必须给出 exact-digest sandbox launcher。低权限 service account、Windows/Linux
  sandbox profile、远程 feature rollout 和审计尚未完成，第三方 WASM 因此仍默认关闭。
- **规模**：主要验证集中在 2–4 节点，10+ 节点与持续 churn 尚未完成。
- **组合**：release、Mesh overlay、Raft 和多副本 store 尚缺一条共同的产品级跨层闭环。
- **运维**：服务管理、配置热载、密钥安全存储、升级和回滚仍需产品化。

## 13. 销售发现问题

首次沟通优先确认：

1. 是个人、小团队、中小企业还是多站点组织？谁负责日常运维？
2. 应用需要对象 API、共享文件系统还是块设备？是否依赖 rename、文件锁、随机写或 POSIX 挂载？
3. 当前对象容量、对象数量、单对象大小、月读写量、出口量和增长速度是多少？
4. 现有硬件、磁盘、备份位置和恢复目标是什么？能否接受单节点非高可用？
5. 当前使用 AWS S3、Ceph RGW/CephFS/RBD、NAS 还是其他系统？月度账单和人工维护成本是多少？
6. 有多少发布源、站点和消费设备？如何镜像、回滚和确认各站点版本？
7. 文件交付是人工拉取、定时同步还是要求按节点组推送？离线节点、截止时间、部分失败和回滚如何处理？
8. CDN 主要承载软件、通用对象、点播还是直播？当前 origin、cache、edge、回源量和命中率是多少？
9. 视频需要点播还是直播？目标首帧、端到端时延、卡顿率、并发、码率、DVR 和播放器分别是什么？
10. 所谓块设备是不可变磁盘镜像分发，还是在线可写 volume？若为后者，是否要求 flush/FUA、快照、
    单写者 fencing、数据库一致性和跨公网访问？
11. 失败主要来自磁盘、带宽、NAT、人工操作、权限还是内容损坏？
12. NAS 或自建存储的本地与远程流量各占多少？远程路径是直连、第三方 relay、FRP 还是自建中心转发，
   实测吞吐、时延和出口瓶颈分别是多少？
13. 今天如何管理节点角色、路由、出口、服务、QoS 和数据流策略？是否需要 GitOps 或审计回滚？
14. 是否要求私有部署、发布者签名、下载审计、离线站点或受控 WASM 执行？
15. 哪个单节点或哪三个站点最适合试点，成功指标是什么？

单站点和小规模数据不再自动判定为低价值，应先评估 M3 Starter。只有客户现有对象服务已经同时
满足成本、隐私、接口、可靠性和运维要求时，才不应为“自建”而引入 M3。

## 14. 相关文档

- [`MESH_STATUS.md`](../MESH_STATUS.md)：Mesh core 状态与未就绪边界；其中 M3 与可选 WASM inventory
  早于当前实现，完成文档对账前不得作为 M3 或 execution 销售依据
- [`MESH_PRODUCT_CONTROL_PLANE.md`](../MESH_PRODUCT_CONTROL_PLANE.md)：产品控制面目标架构
- [`MESHCTL_PRIMITIVES_DESIGN.md`](../MESHCTL_PRIMITIVES_DESIGN.md)：`turbo_cmd` 命令树、selector DSL、
  H2/SSE Controller client、operation/watch、文件/内容删除与执行权限边界
- [`MESH_LOCAL_IPC_DESIGN.md`](../MESH_LOCAL_IPC_DESIGN.md)：FlowMQ secure patterns/mTLS loopback 上的
  `meshd` typed IPC、所有权、背压、安全与恢复契约
- [`FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md`](../FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md)：verified TLS
  certificate fingerprint 与双向 FlowMQ HELLO identity 的精确绑定、轮换、错误及验证契约
- [`MESH_PLATFORM_DESIGN.md`](../MESH_PLATFORM_DESIGN.md)：平台分层与依赖边界
- [`MESH_MULTI_NETWORK_DESIGN.md`](../MESH_MULTI_NETWORK_DESIGN.md)：一个安全 Mesh 下的多逻辑
  Network、membership、地址池、路由隔离、重叠 CIDR、共享 underlay 与兼容迁移
- [`MESH_TWO_TIER_DISTRIBUTION.md`](MESH_TWO_TIER_DISTRIBUTION.md)：骨干到当地边缘分发
- [`M3_DISTRIBUTED_STORAGE_DESIGN.md`](../M3_DISTRIBUTED_STORAGE_DESIGN.md)：M3 对象存储设计
- [`M3_VOLUME_DESIGN.md`](../M3_VOLUME_DESIGN.md)：基于不可变 Hash 块、COW Merkle tree 与 Raft root
  commit 的可写远程块设备设计
- [`M3_RAFT_DEPLOYMENT.md`](M3_RAFT_DEPLOYMENT.md)：Raft 部署与验证
- [`MESH_STREAMING_DESIGN.md`](MESH_STREAMING_DESIGN.md)：文件与媒体分发设计
- [`MESH_NODE_EXECUTION_DESIGN.md`](../MESH_NODE_EXECUTION_DESIGN.md)：节点 WASM 执行边界与 E0-E6 进度
- [`NOISE_IDENTITY_DESIGN.md`](../../p2p/NOISE_IDENTITY_DESIGN.md)：P2P 标准 Noise XX、Mesh 证书绑定、
  channel binding、资源治理与不降级迁移；v2 基线已实现，但向量、fuzz、跨平台和独立安全审查等
  发布闸门未完成，不能对外宣称已通过生产安全认证

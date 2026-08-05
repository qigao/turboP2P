# Mesh / M3 产品规划与路线图

## 文档状态

本文从产品规划视角盘点 `turbo-p2p` 仓库（mesh/ 与 m3/ 栈）当前已实现、已验证的能力，
并给出可落地的产品候选、成熟度评估、横切产品化需求与推荐路线。

- 代码现状与边界以 [`MESH_STATUS.md`](../MESH_STATUS.md) 与各设计文档为准。
- 文中标注 `事实` 的结论来自仓库代码、测试、smoke 或 commit 历史；`推论`/`待补` 明确标注
  为规划判断，不冒充现状。
- 面向用户的 mesh overlay 产品控制面设计（Controller / agent / grants）见
  [`MESH_PRODUCT_CONTROL_PLANE.md`](../MESH_PRODUCT_CONTROL_PLANE.md)，本文不重复其设计，
  只将其列为可组合的产品化路径之一。

## 1. 产品定位与总览

代码库已经覆盖「组网 → 数据分发 → 内容服务」三层，而不是单一组件：

| 层 | 定位 | 现状 |
|----|------|------|
| L1 组网 | Mesh overlay（虚拟 IP、直连/中继、策略） | beta（`事实`：2/3/4 节点验证，`MESH_STATUS.md`） |
| L2 分发 | 文件同步、媒体/直播、多源拉取 | 功能完整、demo 级（`事实`：P1–P29 smoke 全绿） |
| L3 内容服务 | S3 形态对象网关、release/CDN、HLS 服务 | 功能完整、demo 级（`事实`：P17–P32 + m3_* P1–P5） |

据此可组合出的最小产品闭环是：**「私有内容分发网络（CDN）+ 对象存储」**——内容发布到
骨干 → 镜像到当地边缘 → 消费方就近拉取/播放，全程签名与完整性校验。这是当前资产复用度
最高、最接近可演示产品的方向。

## 2. 能力地图（事实）

### 2.1 L1 组网（mesh core）

- 虚拟 IP overlay；DHT 发现 + 路由传播；ICE 直连信号与连通性检查；1-hop 中继与多跳学习。
- 准入/ACL：CIDR、稳定 node-id、协议 major 三组 allowlist；包策略（方向/协议/端口）。
- 路由策略：pinned CIDR 规则、子网路由/出口节点（local egress）fail-closed。
- MagicDNS：静态 mesh 名记录。
- 管理面：MMP 签名信封、节点证书、`meshctl` / `meshd`、`meshctl cluster`（turbo_cmd 批量聚合）。
- 库级 API：`turbo_mesh.h`（create/start/stop、ICE、peer/route/policy/diag）。
- 证据：`mesh/include/turbo_mesh.h`、`mesh/examples/meshctl.c`、`meshd.c`、`MESH_NODE_MANAGEMENT.md`、
  `mesh/tests/test_mesh*`（81 项全量 ctest 全绿）。

### 2.2 L2 数据分发（mesh stream，P1–P29）

- 可靠有序块流会话（P1）、多源块拉取 + 源选择（P2/P10）、文件同步引擎（manifest diff +
  断点续传，P3）。
- 媒体分段索引 + ABR 阶梯（P4/P9）、按需 Range/206 拉取（P8）。
- live 边缘会话（LIVE_SKIP + FEC，P5）、KCP 传输绑定（P7）、流发现/QoS/集群 smoke（P6/P11）。
- HLS 风格媒体/主播放列表（P12–P15）、多节点 live 分发 KCP→HLS（P20）、跨网关 live 源
  切换 failover（P29）。
- 证据：`mesh/src/mesh_stream_*`、`mesh/examples/mesh_stream_*_main.c`、
  `mesh/scripts/run_mesh_stream_*smoke.ps1`。

### 2.3 L3 内容服务（M3，m3_* P1–P5 + P17–P32）

- 不可变 chunk CAS + 内容寻址 manifest V2（CID=SHA-256）、placement 段。
- 元数据：本地命名空间 store + Raft 适配器 + 单点/多 voter raft 节点。
- 数据面：store 节点（receipt）、认证 chunk 传输、repair/GC。
- 网关（`m3_gateway_main`）：SigV4 认证；PUT/GET/HEAD/DELETE；Range/206；ListBuckets/
  ListObjects；HLS 播放列表路由；`release.txt` 列表；release 文件端点
  `GET /:bucket/:object/*`；release 入口点 `?listing=1` / `?redirect`。
- release 全链路：`pack`（多文件清单+版本+深层路径）→ `publish`（可选 Ed25519 签名）→
  `mirror`（骨干→边缘，顺带签名侧车）→ `pull`（按名/按 hex）→ 文件端点。
- 完整性三层校验：逐对象 CID（P28）、清单↔列表 digest（P31）、发布方签名（P32）。
- 证据：`mesh/src/m3_*.c/h`、`mesh/examples/m3_gateway_main.c`、`run_m3_*smoke.ps1`、
  `run_mesh_release_*smoke.ps1`、`MESH_TWO_TIER_DISTRIBUTION.md`。

### 2.4 横切基础

- CoroNet 协程网络、TurboHTTP（Iris + http_client + S3 客户端）、TurboRaft、Ed25519/OpenSSL。
- 分布式执行层雏形：`mesh_mgmt_execution_*`（orchestrator/runner/store/wire/lease）测试齐全，
  WASM 执行被推迟（`MESH_NODE_EXECUTION_DESIGN.md`）。

## 3. 产品候选与成熟度

| 产品 | 已有能力（事实） | 关键差距（推论/待补） | 优先级 |
|------|------------------|----------------------|--------|
| 私有软件分发 CDN | release 全链路 + 两级 mirror + 签名/完整性 + 文件端点 | 多租户/权限、配额、下载统计/审计、管理端、公钥信任分发与吊销 | P0 |
| S3 兼容 mesh 对象存储 | SigV4 网关、CRUD/Range/列表、Raft 元数据、副本/修复/GC | 多租户/配额、生命周期、事件通知、监控指标、生产持久化验证 | P1 |
| 企业 mesh 组网 + 远程访问 | overlay、直连/中继、ACL、出口节点、MagicDNS、meshctl/meshd | 生产级认证（现为简化 Noise-like）、10+ 节点规模、产品控制台、DNS 完整方案 | P1 |
| P2P 文件同步 | 同步引擎（diff + 断点续传 + 多源） | 冲突解决、版本历史、权限模型、产品化外壳 | P2 |
| 内网直播分发 | KCP→HLS、多节点、跨网关 failover | 多路 ingest 时序对齐、DVR/回看、播放器集成验证 | P2 |
| 分布式执行 | 执行层雏形 + lease + 设计文档 | WASM 沙箱、命令日志/审计、进程树清理、端到端测试 | 远期 |

### 3.1 私有软件分发 CDN（P0，首选）

定位：企业内部/边缘场景的版本化软件、固件、安装包分发，替代自建镜像站。

已闭环的用户路径（`事实`，`run_mesh_release_download_smoke.ps1` 与
`run_mesh_release_mirror_smoke.ps1` 全绿）：
1. 发布方 `release publish --sign-key <key>`：打包（支持深层路径）→ 上传对象 + 清单 + 签名侧车。
2. 骨干网关对外服务；`release mirror` 把整包同步到当地边缘网关。
3. 消费方 `release pull <name> --pubkey <key>`：取清单、验清单↔列表 digest、验发布方签名、
   逐对象验 CID，写盘。
4. 网页/脚本可直接用 `GET /rel/<name>?listing=1`（列表）或 `GET /rel/<name>/<path>`（文件）。

产品化差距（`推论`，均不涉及新协议）：
- 管理面：发布记录、版本列表、下载统计、审计日志（网关已具备 SigV4 认证，可追加租户维度）。
- 信任：公钥发布/吊销、每租户密钥。
- 配额与限流：对象大小、release 数、带宽。

### 3.2 S3 兼容 mesh 对象存储（P1）

网关已是 S3 形态（SigV4、CRUD、Range、列表），`TurboHttp::S3` 客户端可对接。产品化重点是
多租户隔离、配额、生命周期与监控，而不是协议新能力。可作为「3.1」的存储底座复用。

### 3.3 企业 mesh 组网 + 远程访问（P1）

L1 已具备 beta 组网能力；产品化依赖生产级身份认证与规模验证（`MESH_STATUS.md` 明确列出）。
`MESH_PRODUCT_CONTROL_PLANE.md` 已给出 Controller/agent 目标架构，落地需新增服务、证书、
策略编译与审计。

### 3.4 / 3.5 P2P 文件同步与内网直播

功能层已具备（sync engine、live HLS + failover），主要缺口在冲突/版本/权限等产品语义与
集成验证，适合在 P0/P1 之后作为增量产品线。

## 4. 横切产品化需求（各产品通用）

- 身份与多租户：当前网关为单凭证 demo（`事实`：S3_DEMO_* 固定密钥）；产品化需租户/密钥管理。
- 配额与容量：对象、release、bucket、并发均有上限常量，但需暴露为可配置配额并加审计。
- 可观测性：现有日志与计数（`logging-guide` 约束）需补指标（P50/P95/P99）、下载统计、
  跨节点链路追踪。
- 运维：gateway/store/raft 节点需 daemon 化（systemd/Windows 服务）、健康检查、配置热载。
- 安全审计：签名密钥不落盘明文、关键状态迁移（发布/删除/租户变更）记录可审计事件。
- 计费/用量：作为服务化前提，需用量聚合与配额计量。

## 5. 推荐路线图

- **P0（近期，复用度最高）**：软件分发 CDN 管理面——`meshctl release`（list/verify/stats）
  或网关发布记录 + 下载审计端点；把 P17–P32 零散能力聚合成可演示闭环。
- **P1（中期）**：S3 网关多租户/配额/监控；mesh 生产化（认证 + 规模 + 控制台）按
  `MESH_PRODUCT_CONTROL_PLANE.md` 分阶段推进。
- **P2（远期）**：文件同步产品语义、直播 DVR/回看、分布式执行（WASM）。

## 6. 验证方式

- 全量回归：`ctest --preset win-release-user`（当前 81/81 全绿，`事实`）。
- 产品级 smoke（`mesh/scripts/*.ps1`，均为真实多进程，`事实`）：
  - release：`run_mesh_release_download_smoke.ps1`、`run_mesh_release_mirror_smoke.ps1`、
    `run_mesh_release_smoke.ps1`
  - 对象存储：`run_m3_store_node_smoke.ps1`、`run_m3_gateway_cluster.ps1`、
    `run_m3_gateway_mesh_smoke.ps1`、`run_m3_raft_cluster.ps1`
  - 媒体/直播：`run_mesh_media_http_smoke.ps1`、`run_mesh_stream_media_smoke.ps1`、
    `run_mesh_stream_live_hls_smoke.ps1`、`run_mesh_stream_live_cluster_smoke.ps1`、
    `run_mesh_stream_live_failover_smoke.ps1`、`run_mesh_two_tier_smoke.ps1`
- 新产品化能力须附带对应 smoke/单测，保持「改动→最小验证→相邻回归→全量」的顺序。

## 7. 风险与边界

- **成熟度**：整体为 beta / demo 级（`MESH_STATUS.md`：overall mesh product readiness 非 GA）。
- **认证**：live/流与网关认证为 demo 密钥或简化 Noise-like，生产需替换为正式身份体系。
- **规模**：网络与集群验证以 2–4 节点为主，10+ 节点与 churn 下行为未验证。
- **单点**：网关/元数据 raft 的部署与运维文档不完整（`M3_RAFT_DEPLOYMENT.md` 为部署参考）。
- **测试数据/密钥**：smoke 使用固定 demo 密钥（`606162…` 等），仅限本地验证，不得用于生产。

## 8. 相关文档索引

- [`MESH_STATUS.md`](../MESH_STATUS.md)：实现状态与产品就绪度
- [`MESH_PRODUCT_CONTROL_PLANE.md`](../MESH_PRODUCT_CONTROL_PLANE.md)：产品控制面目标架构
- [`MESH_PLATFORM_DESIGN.md`](../MESH_PLATFORM_DESIGN.md)：网络平台边界
- [`MESH_TWO_TIER_DISTRIBUTION.md`](MESH_TWO_TIER_DISTRIBUTION.md)：骨干→当地两级分发
- [`M3_DISTRIBUTED_STORAGE_DESIGN.md`](../M3_DISTRIBUTED_STORAGE_DESIGN.md)：M3 对象存储设计
- [`MESH_NODE_EXECUTION_DESIGN.md`](../MESH_NODE_EXECUTION_DESIGN.md)：分布式执行（WASM 推迟）
- [`MESH_NODE_MANAGEMENT.md`](MESH_NODE_MANAGEMENT.md)：节点管理手册
- [`MESH_STREAMING_DESIGN.md`](MESH_STREAMING_DESIGN.md)、[`MESH_STREAM_PROTOCOL.md`](../MESH_STREAM_PROTOCOL.md)

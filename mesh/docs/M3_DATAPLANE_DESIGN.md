# M3 Data Plane Design（缺失功能解决方案）

状态：设计提案（2026-08）。本文件定义 M3 分布式对象存储在已完成「Raft 元数据 + 单节点 S3 网关」
之后所缺失功能的解决方案，作为 `M3_DISTRIBUTED_STORAGE_DESIGN.md` §9-§13（chunk/placement/写读事务/
repair/GC）与 §20 状态清单的落地设计。不冻结公开 API 或 wire protocol；实现前按本节逐项验证。

## 1. 缺失功能清单（对照 V1 目标）

已完成（前序提交）：
- Raft 元数据（固定 voter、CoroNet mTLS transport、三进程部署、crash/leader-switch/瞬断分区）。
- 网关多节点元数据后端 + leader 读路由 + ListObjects/ListBuckets + HTTP 端到端。
- 单节点不可变 chunk CAS（`m3_chunk_store`）、对象 CID、逐 chunk hash 校验、Range/206。

缺失（V1 目标内，本设计覆盖）：
1. **跨节点 chunk 持久化与副本**：PUT 只写本地 CAS，无跨 failure domain 副本、无 durable receipt
   （`HIGH`：leader 切换后新 leader 本地无旧 leader 的 chunk → GET 数据不可用）。
2. **PUT 原子提交**：chunk 持久化（多副本收据）+ Raft metadata commit 都成功才返回 200；当前
   chunk 只落本地、metadata 提交即返回，跨节点持久性不满足 §10 不变量。
3. **GET/Range 的 replica 选择**：从 placement 选最近健康 replica，逐 chunk 验证 CID；当前只读本地。
4. **Repair**：从 committed manifest 派生缺副本任务并补齐（§12）。
5. **GC**：以 committed snapshot 为 mark 源回收 unreferenced chunk（§12）。
6. **Mesh 虚拟网络接入**：网关/store 经 Mesh 提供能力签名流；当前为本地 HTTP。

明确非目标（沿用 §3.2）：DHT 不作 namespace 权威、对象 bytes 不入 Raft log、无动态 membership、
无 erasure coding、不修改 `p2p_put_file`/`p2p_get_file` 语义。

## 2. 设计决策摘要

| 决策点 | 选择 | 理由 |
|--------|------|------|
| chunk 数据通路 | **Mesh bulk stream + 签名 capability**，非 DHT value | §4 采用「Raft metadata + immutable chunk replicas」；仓库已有 `m3_chunk_capability`/`m3_chunk_access_store`/`m3_chunk_fetch_service` 可复用 |
| placement 事实源 | **committed manifest 记录实际收据**，非瞬时观察 | §6「followers 必须应用 leader 已选择的 placement」；manifest 已作为不透明字节存于 raft namespace |
| 副本数 | 配置化 `target_replicas=3`、`min_durable_replicas=2`、failure-domain label | §9.2 建议默认值；全部可配置 |
| 写入失败语义 | 达到 min-durable 可 commit + repair debt；未达到则整个 PUT 失败 | §9.2 |
| store 节点形态 | 独立数据面服务 `m3_store_node`（可嵌入网关进程或独立进程） | §5 架构图「M3 Store node A/B/C」；与 metadata 进程解耦 |
| 元数据 leader 角色 | leader 兼 placement 决策者；store 只接受带 capability 的 chunk 流 | §5.1 组件职责 |

## 3. Store 节点服务（`m3_store_node`）

复用现有组件组装一个数据面服务，负责不可变 chunk 的授权 PUT/READ/校验/配额：

```
m3_store_node
 ├─ m3_chunk_store          （本地不可变 CAS，已实现）
 ├─ m3_chunk_capability     （签名 capability 校验，已实现）
 ├─ m3_chunk_access_store   （authorized PUT/READ 适配器，已实现）
 ├─ m3_chunk_replay         （request UUID 幂等 journal，已实现）
 ├─ m3_chunk_read_service   （只读组合根，已实现）
 ├─ m3_chunk_fetch_service  （P2P 回源：从健康 peer 拉缺失 chunk，已实现，需 p2p_node）
 ├─ 容量/租户配额策略       （新增：每租户字节上限、store 健康观测）
 └─ Mesh bulk stream 接入   （新增：p2p_node 或 mesh_mgmt transport）
```

新增能力（在现有组件之上）：

- `m3_store_node_config`：store root、max_chunk_bytes、租户配额表、failure-domain label、
  `target_replicas`/`min_durable_replicas`（用于判定收据是否够）、p2p/mesh 端点。
- `m3_store_node_put_chunk`：接收「已验签 PUT capability + bytes」→ `m3_chunk_access_store_put_v1`
  → 返回**由 store identity 签名的 durable receipt**（新结构 `m3_chunk_receipt_v1_t`：
  `{store_node_id, cid, size, fsync 后原子发布完成, signature}`）。
- `m3_store_node_read_chunk`：接收「已验签 READ capability + range」→
  `m3_chunk_read_service_execute_v1`（逐 chunk 全量校验 CID）。
- `m3_store_node_health`：供 leader 形成 placement score（free capacity、failure domain、
  最近 RPC 结果、quota 余量）；仅作观察，不自行提交状态。

`m3_chunk_receipt_v1_t` 是本设计新增的最小结构：它是「数据已 durable」的可验证证据，由
placement proposal 引用，并由 committed manifest 持有（§5）。

## 4. Chunk capability 协议（网关 ↔ store）

复用 `m3_chunk_capability_claims_v1_t`（tenant、cid、operation、range、audience_node_id、
request_id、issued/expires）。网关（签发者）与 store（audience）之间的消息经 Mesh 加密流传输：

- **PUT_CHUNK**：`{capability_claims, signature, bytes}` → store 验签 + 校验 audience==自身 +
  CID 匹配 + range 完整 → 写入 CAS → 返回 `m3_chunk_receipt_v1_t`（签名）。
- **GET_CHUNK**：`{capability_claims, signature}` → store 验签 + 校验 audience + 范围 → 流式返回
  chunk bytes（整 chunk 校验 CID 后按 range 发送）。
- 所有消息带 request_id；store 用 `m3_chunk_replay` 保证幂等（重试返回同一结果）。
- capability TTL/字节上限受 `m3_chunk_capability_policy_v1_t` 约束（已实现）。

消息帧：复用仓库 mesh_mgmt 的定长/有界帧语义（canonical length-first LTV），新增 service
`m3-chunk/v1`（控制）与 `m3-chunk-bulk/v1`（chunk bytes）。不接受弱格式 fallback：解码/验签失败
即关闭该 peer session。

## 5. Placement 模型

### 5.1 Manifest V2

当前 `m3_object_manifest_v1_t = {object_cid, chunks[]}`。V2 增加 placement 段（versioned、向后
可解码 V1）：

```
manifest_v2 {
  version = 2
  object_cid, chunks[]              // 不变
  placements[] {                    // 每个 chunk 一组收据
    chunk_index
    receipt { store_node_id[32], receipt_sha256[32] }
    ...
  }
}
```

约束：
- placement 是「leader 已选择并写入 command」的事实；followers 原样应用（§6）。
- manifest 仍作为**不透明字节**存于 raft namespace（`m3_namespace_raft_adapter` 无需改动）。
- `m3_object_manifest_encode_v1/decode_v1/validate_v1` 增加 V2 编解码与完整性校验（envelope digest
  覆盖 placement 段）。
- 每个 chunk 的收据数 ∈ [min_durable_replicas, target_replicas]；不足即 repair debt。

### 5.2 placement 决策

leader 为 PUT 的每个 chunk 选 `target_replicas` 个 store：优先满足 failure-domain 分散，再按
`m3_store_node_health` 打分（free capacity、quota、近端）。决策只用 leader 的瞬时观察形成 proposal；
committed manifest 才是权威。

## 6. PUT 事务（data durable before metadata commit）

```
HTTP PUT
  -> 网关 auth + quota + leader resolve（follower 网关 503/307）
  -> 流式读 body，切 chunk，算 CID（chunk size 可配置，默认 8 MiB）
  -> 为每个 chunk 向 target_replicas 个 store 并行发 PUT_CHUNK（带签名 capability）
  -> 收集 durable receipt；验证每张收据的 store_node_id/CID/签名
  -> 达到 min_durable_replicas：构建 manifest_v2（含 placement）+ 剩余收据不足项记为 repair debt
     （未达到 min-durable：整个 PUT 失败，不提交 metadata）
  -> 通过 raft adapter propose manifest（幂等 command_id，重试同 UUID 返回同一 version）
  -> commit 后返回 ETag/version/committed index
```

不变量（§10）：
- **数据先 durable 后 metadata commit**：PUT 200 意味着 ≥min-durable 副本已 fsync 落盘。
- metadata commit 是对象可见性的唯一切换点。
- commit 前失败的 chunk 是 orphan → grace-period GC 回收（§9）。
- overwrite 产生新 version，旧 manifest/chunk 不可变。

网关集成点（现有代码）：
- `m3_gateway_meta_put`（node 模式）从「本地 chunk store + propose manifest」改为「并行
  PUT_CHUNK 到 store + 收集收据 + propose manifest_v2」。本地 CAS 保留为最后一层 cache。
- `m3_raft_node` 的 propose 路径不变（manifest 仍为不透明 bytes）。

## 7. GET / Range

```
GET/HEAD
  -> 网关 auth + leader 线性化读 manifest_v2（follower 网关 503/307）
  -> 把 HTTP Range 映射到 chunk span
  -> 对每个 chunk 从 placement 选最近健康 replica（Mesh path/RTT + health）
  -> 签发 READ capability（audience=replica store），bounded 并行 GET_CHUNK
  -> 逐 chunk 全量校验 CID；只向客户端发请求 range
  -> 一个 replica 失败/校验失败：标记 corruption observation，换另一已授权 replica
  -> 全部候选失败：明确 5xx/data-unavailable，绝不返回截断 200
```

复用：`m3_object_resolver`/`m3_object_download_service` 的对象级读组合可扩展为「placement-aware
replica 选择 + 并行 chunk 拉取」。网关 `read_object_range` 保持逐 chunk 校验语义。

## 8. Repair

后台服务（可由 metadata leader 或独立 repair 进程运行）：
1. 定期扫描 committed manifests（raft snapshot/状态机枚举）。
2. 对每个 chunk 计算 `target_replicas - 当前收据数` 的 debt（含 corruption observation 换店）。
3. 从健康 replica 签发 READ capability 拉 chunk，向新 store 发 PUT_CHUNK，取得新收据。
4. 通过 raft propose `UPDATE_PLACEMENT`（新收据）；commit 后旧 placement 才移除。
5. repair 不修改 object version；全程幂等（request_id）。

复用：`m3_chunk_fetch_service`（P2P 回源）可作为 repair 的「从 peer 拉」路径之一。

## 9. GC

- mark 源：committed snapshot（所有 live object manifest_v2 引用的 CID）。
- store 节点只回收满足全部条件的 chunk：unreferenced + grace period 到期 + 无 pending upload
  lease（upload session 持有）。
- GC 由「快照服务」下发 live-CID 集（经 Mesh 或本地快照文件）；store 不自行按本地时间删除。
- 幂等、可中断、配额释放可观测。

## 10. Mesh 接入

- 网关与 store 节点各持一个 `p2p_node`（或 mesh_mgmt transport），注册 service record
  （`m3-gateway/<id>`、`m3-store/<id>`、`m3-raft/<id>`）。
- 服务发现：网关发现 store 节点、metadata peer 端点；leader 发现复用 raft peer 表。
- 所有 chunk/控制流走已认证 Mesh 加密流（identity + 签名 capability）；audience_node_id 绑定
  store 身份。
- 保持「本地 HTTP」为单节点 fallback/测试模式（`m3_gateway_main` 不带 store/mesh 时）。

## 11. 与现有代码的集成点汇总

| 现有组件 | 改动 |
|----------|------|
| `m3_chunk_store` / `m3_chunk_access_store` / `m3_chunk_capability` / `m3_chunk_replay` / `m3_chunk_read_service` / `m3_chunk_fetch_service` | 直接复用，新增 `m3_store_node` 编排 + receipt 结构 |
| `m3_object_manifest` | V2：placement 段（versioned encode/decode/validate） |
| `m3_gateway`（node 模式） | PUT：本地写 → 并行 PUT_CHUNK + 收据 + propose manifest_v2；GET：replica 选择 + 拉取 |
| `m3_raft_node` / `m3_namespace_raft_adapter` | 不改（manifest 仍为不透明 bytes；`UPDATE_PLACEMENT` 作为新 command type 进入 adapter） |
| `p2p` / `mesh_mgmt` | store/gateway 接入 Mesh（service record + 加密 bulk 流） |

新增文件（预估）：
- `mesh/src/m3_store_node.{c,h}`（store 服务编排）
- `mesh/src/m3_chunk_receipt.{c,h}`（durable receipt 编解码/验签）
- `mesh/src/m3_placement.{c,h}`（placement 策略 + proposal 构造）
- `mesh/src/m3_repair.{c,h}`、`mesh/src/m3_gc.{c,h}`（后台任务）
- `mesh/examples/m3_store_node_main.c`（独立 store 进程）
- `mesh/src/m3_gateway` 数据面 client（capability 签发 + PUT_CHUNK/GET_CHUNK 调用）

## 12. 分阶段实施计划与验证门禁

建议顺序（每阶段独立可验证、可提交）：

1. **P1：manifest V2 + receipt 结构** —— `m3_object_manifest` V2 编解码/校验（含 placement 段）、
   `m3_chunk_receipt` 编解码/验签。
   验证：`test_m3_object_manifest_v2`（round-trip、篡改拒绝、V1 兼容解码）、
   `test_m3_chunk_receipt`（签名/验签、过期/audience 拒绝）。

2. **P2：store 节点服务（本地能力）** —— `m3_store_node` 本地授权 PUT/READ（capability →
   access_store → receipt），不接 Mesh。
   验证：`test_m3_store_node`（PUT/READ/幂等/配额/audience 拒绝）；跨进程 store 冒烟。

3. **P3：网关跨节点 PUT/GET（进程内两 store）** —— 网关把 chunk 写/读到两个 store 节点
   （capability + receipt + manifest_v2），PUT 达到 min-durable 才提交 metadata。
   验证：`test_m3_gateway_datapane`（PUT → 两 store 均有 chunk 收据；GET 从 replica 读回；
   leader 切换后新 leader GET 仍可经 store 拉 chunk —— 修复 §1 的 `HIGH` 数据可用性问题）。

4. **P4：Mesh 接入** —— 网关/store 经 p2p/mesh 加密流（service record + 签名 capability），
   替换 P3 的本地直连。
   验证：`run_m3_gateway_cluster.ps1` 扩展为「3 网关 + 3 store 经 Mesh」；跨进程 S3 PUT/GET 闭环。

5. **P5：Repair + GC** —— 后台补齐/回收。
   验证：`test_m3_repair`（删副本 → repair 补足 → placement 收敛）、`test_m3_gc`
   （orphan chunk 在 grace 后回收、live chunk 保留）。

6. **P6：配额/多租户/审计/流式 multipart**（V1 尾部）—— 配置化配额、多凭证 resolver、
   `iris_app_route_stream` + `req_read_body` 无上限流式、multipart complete 校验。

每阶段全量 ctest 保持全绿；与 `M3_DISTRIBUTED_STORAGE_DESIGN.md` §17 Verification gates 对齐。

## 13. 风险与前置

- **manifest V2 是格式变更**：`M3_OBJECT_MANIFEST_VERSION` 升版 + V1 兼容解码；已存 V1 对象在
  repair 时可迁移为 V2（或用 V1 只读 + 新写 V2）。
- **store 节点需要密钥签发 receipt**：密钥管理沿用仓库 identity/密钥规范，不硬编码、不落日志。
- **capability 时钟**：TTL/有效期依赖节点时钟；沿用 ±900s 窗口约定。
- **跨 failure domain**：V1 用配置 label 近似，不实现真实 zone 感知。
- **动态 membership**：V1 固定三 voter + 固定 store 集；store 健康只影响 placement score，不动态
  增删 voter。

## 14. 相关参考

- `M3_DISTRIBUTED_STORAGE_DESIGN.md` §5/§6/§9-§13/§20
- `M3_RAFT_DEPLOYMENT.md`（已完成的元数据部署清单）
- `m3_chunk_store.h` / `m3_chunk_capability.h` / `m3_chunk_access_store.h` /
  `m3_chunk_read_service.h` / `m3_chunk_fetch_service.h` / `m3_object_manifest.h`
- `p2p.h`（Mesh 节点 API）

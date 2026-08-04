# M3 Distributed Object Storage Design

状态：架构提案。本文不表示 M3 已实现，也不冻结公开 API、配置格式或 wire protocol。

## 1. 决策摘要

M3 是运行在 Mesh 虚拟网络之上的可选分布式对象存储服务，不是 Mesh core 的组成部分。

- Mesh 继续只拥有身份、虚拟网络、路由、ACL、审计锚点和可靠/不可靠数据转发。
- M3 拥有 bucket/object namespace、不可变 chunk、replica placement、repair、GC 和 S3-shaped HTTP gateway。
- Raft 只复制 M3 元数据，不复制对象 bytes。对象数据走独立的 Mesh bulk stream。
- `TurboNet::CoroNet` 提供 Raft transport、协程、timeout、连接生命周期和背压；Raft 状态机保持为独立模块。
- `TurboHttp::Iris` 提供 HTTP server 与流式 request body；`TurboHttp::S3` 用于客户端和兼容性测试，不充当 M3 server implementation。
- M3 采用 crash-fault-tolerant Raft，不声称抵抗拜占庭节点。恶意节点防护依靠身份、签名 receipt、内容 hash、ACL 和审计。

推荐依赖方向：

```text
M3 service
  -> TurboHttp::Iris
  -> TurboHttp::S3          # client/conformance only
  -> TurboP2P::Mesh
  -> TurboNet::CoroNet
  -> TurboUtils::Core

TurboP2P::Mesh -X-> M3
TurboNet::CoroNet -X-> Raft state machine
```

M3 适合放在独立 sibling repository 或独立顶层 product target。turbo-p2p 只保留通用 Mesh
transport、service discovery 和 capability contract，不引入 bucket、manifest 或磁盘 layout 类型。

## 2. 当前证据与边界

### 2.1 Mesh 已有边界

[`MESH_PLATFORM_DESIGN.md`](MESH_PLATFORM_DESIGN.md) 已定义 Mesh 是业务连接事实源而不是业务
协议实现，并把 HTTP、文件和数据库列为 Mesh 上层业务。现有 native stream V1 已提供认证绑定、
有界 frame、严格顺序、绝对 receive window 和背压语义，适合承载 M3 的 control/bulk flow，但当前
transport target 不写文件，也不拥有业务状态。

### 2.2 当前 P2P file API 不是存储系统

`p2p_put_file()` 当前只登记本地路径并公告 hash；`p2p_get_file()` 只发起 DHT lookup，没有把对象
bytes 写到调用方输出路径。`p2p_minio_s3` 上传后会删除临时文件。因此它没有 durable local store、
replication、repair、object commit 或一致性保证，不能作为 M3 实现继续扩展。

### 2.3 TurboHTTP 可复用能力与实施缺口

可直接复用：

- Iris explicit `iris_app_t`、route middleware、security limits。
- `iris_app_route_stream()`、`req_read_body()` 和 `req_body_read_error()` 的 fail-fast request streaming。
- HTTP Range client、multipart/S3 schema、credential provider 和 SigV4 client-side 兼容性测试能力。

需要在 TurboHTTP 上游先补齐的能力（2026-08 复核）：

- ~~Iris 公共 chunked response API 不返回底层发送错误~~ → **已补齐**：`reply_chunked_write()` 在底层发送失败时返回 -1（iris/router.c），M3 GET 可据此不误报成功。
- ~~`s3_put_object_from_file()` / `s3_download_object_stream()` 整对象读内存~~ → **已补齐**：两者均走 `s3_execute_signed_stream()` + 回调式流式读写（s3_client.c）。
- **server-side SigV4 verification 仍缺失**：TurboHTTP 只有 client 侧 canonical helper 与 JWT/Bearer，没有 Authorization 签名验证。turbo-p2p 在 `mesh/src/m3_gateway_sigv4.*` 提供 Phase 1 过渡实现（单凭证、AWS4-HMAC-SHA256、x-amz-date/x-amz-content-sha256 必填、时间窗 ±15min、常量时间比较），长期应下沉到 TurboHTTP 独立模块并接入 Iris 认证中间件。

这些缺口应以 additive、可返回错误的 streaming API 修复；M3 不直接访问 Iris `Res` 内部 socket，
也不在 gateway 里另写 HTTP parser。

## 3. 目标与非目标

### 3.1 V1 目标

- 通过 Mesh virtual network 提供 native M3 HTTP API。
- 在三个固定 metadata voter 上提供线性一致的 bucket/object namespace。
- 对对象进行内容寻址、不可变 chunk、跨 failure domain 副本和后台 repair。
- PUT 只有在最小数据持久化条件和 Raft metadata commit 都成功后才返回成功。
- GET/Range 从满足授权的最近健康 replica 读取，并逐 chunk 验证 hash。
- 所有可增长结构、frame、队列、并发、对象大小、bucket 数和 pending upload 都有配置上限。

### 3.2 V1 非目标

- 不把对象 bytes、节点 heartbeat 或实时 path metrics 写入 Raft log。
- 不使用 DHT 或 Gossip 作为 object namespace 的权威事实源。
- 不支持动态 Raft membership；V1 使用启动时校验的固定三个 voter。
- 不实现 Byzantine consensus、跨互不信任组织的仲裁或加密货币式账本。
- 不在 V1 实现 erasure coding、跨 region 强同步数据副本或完整 AWS S3 管理 API。
- 不修改现有 `p2p_put_file()` / `p2p_get_file()` 的公开语义来伪装 M3。

## 4. 候选方案

| 方案 | 一致性 | 数据路径 | 主要问题 | 结论 |
|------|--------|----------|----------|------|
| DHT 同时保存 key 和对象 | eventual | DHT value | value 上限、冲突、无原子提交和 repair | 拒绝 |
| Raft 复制全部对象 bytes | strong | Raft log | 大文件放大、snapshot 和 follower catch-up 阻塞 | 拒绝 |
| 外部 MinIO/S3 + Mesh | 由外部服务定义 | HTTP over Mesh | 可立即使用，但不是 Mesh-native distributed bucket | 保留为 adapter |
| Raft metadata + immutable chunk replicas | namespace strong | Mesh bulk stream | 需要独立 store、repair 和 GC | 采用 |

Raft core 的来源必须经过独立准入：优先评估成熟、许可兼容、支持持久化回调的 C/C++ Raft core，
并用 CoroNet 实现 transport adapter。若没有满足 ABI、许可和 event-loop 约束的实现，才允许在 M3
内实现 fixed-membership Raft；该路径必须先具备确定性 simulator、crash/recovery、partition、
snapshot 和线性一致性测试，不能把未经验证的共识代码放入 CoroNet。

## 5. 总体架构

```text
S3/native HTTP client
        |
        v
+--------------------+      proposal/read-index      +---------------------+
| M3 Gateway (Iris)  | ----------------------------> | M3 Metadata Leader  |
| auth/range/stream  |                               | Raft state machine  |
+---------+----------+                               +----+-----------+----+
          |                                               |           |
          | signed fetch/store capability                 | Raft      | Raft
          v                                               v           v
+--------------------+                              +----------+ +----------+
| Mesh service/route |                              | Follower | | Follower |
+---------+----------+                              +----------+ +----------+
          |
          | m3-chunk/v1 bulk streams
          v
+--------------------+   replicas/repair   +--------------------+
| M3 Store node A    | <-----------------> | M3 Store node B/C  |
| immutable CAS      |                     | immutable CAS      |
+--------------------+                     +--------------------+
```

### 5.1 组件职责

| 组件 | 唯一职责 | 不拥有 |
|------|----------|--------|
| `m3_gateway` | HTTP/S3-shaped adapter、认证、流式 request/response、错误映射 | Raft state、chunk filesystem |
| `m3_raft` | term/log/quorum/read-index/snapshot、确定性 metadata apply | HTTP、path 评分、对象 bytes |
| `m3_meta_store` | WAL、hard state、snapshot 的 durable adapter | 网络重试、业务授权 |
| `m3_chunk_store` | immutable chunk temp-write/fsync/atomic-publish/read/range | bucket namespace |
| `m3_placement` | 根据 policy 和 observation 产生显式 placement proposal | 自行提交状态 |
| `m3_repair` | 从 committed manifest 派生缺副本任务并补齐 | 修改 object version |
| Mesh | identity、service discovery、route/path、encrypted flow、ACL | M3 metadata 和 disk state |

## 6. 单一事实源

| 状态 | 权威 owner | 派生状态 |
|------|------------|----------|
| bucket/object/version/ACL | committed Raft state machine | gateway cache、list view |
| manifest page | committed Raft state machine | read plan |
| chunk bytes | store node immutable CAS；CID 定义内容身份 | replica cache |
| placement intent | committed manifest | repair queue |
| store health/capacity | leader 的有 TTL observation | placement score |
| Mesh path/RTT | Mesh path manager | nearest-replica score |
| upload body progress | gateway/upload session | multipart progress view |
| audit event | committed index + append-only audit sink | search/index view |

followers 必须应用 leader 已选择并写入 command 的 placement，不能使用各自瞬时 health/path metric
重新计算，否则同一 Raft log 会产生不同状态。

## 7. Raft over CoroNet

### 7.1 线程与协程模型

每个 metadata process 使用一个 CoroNet owner loop。Raft mutable state 只在该 loop 修改：

- 一个 election/heartbeat timer coroutine。
- 每个 peer 一个 bounded replication coroutine 和一个 receive coroutine。
- 一个 listener 接受经过 Mesh identity admission 的 metadata peer。
- snapshot transfer 使用独立 bulk stream，不能让大 snapshot 阻塞 heartbeat/control stream。
- blocking fsync、directory sync 和 snapshot file I/O 由 ordered durable-I/O queue 执行，完成事件
  带 sequence fence 并通过 `coro_post()` 返回 owner loop；不得在 event loop 内执行阻塞磁盘 I/O，
  也不得让并行 I/O completion 乱序推进 hard state。

`coro_context_spawn()` 创建的 managed coroutine 由 context 自动回收。shutdown 顺序固定为：停止
新 proposal、取消 timer、停止 listener、唤醒 pending recv、drain/abort replication、等待 durable
I/O completion、持久化 hard state，最后销毁 socket/context。

### 7.2 Transport contract

Raft RPC 使用独立 service `m3-raft-control/v1`，通过已认证 ordered Mesh stream 传输。wire frame
采用 canonical length-first LTV，所有整数 big-endian，并有以下硬约束：

- `cluster_id`、sender/receiver node identity、protocol version 必须匹配 admission fact。
- frame length、entry count、单 entry bytes、outstanding bytes 和 pending RPC 数有启动时上限。
- 每个 RPC 带 term、request ID 和明确的 previous-log coordinates。
- V1 只定义有界的 `PRE_VOTE`、`REQUEST_VOTE`、`APPEND_ENTRIES`、ReadIndex context 和
  `INSTALL_SNAPSHOT_BEGIN/CHUNK/END` 消息；业务 command 不直接成为 transport message type。
- decode/auth/schema 失败立即关闭该 peer session，不尝试弱格式 fallback。
- send 成功只表示进入 transport；只有 follower durable-ack 才能计入 Raft replication quorum。
- reconnect 使用有界 exponential backoff 和 CSPRNG jitter；旧 connection generation 的响应丢弃。

Raft control stream 不通过 Gossip 广播。Gossip 可以传播 voter endpoint hint，但不能授予 voter 身份、
改变 membership 或推进 term。

### 7.3 持久化与提交顺序

每个 voter 的 durable fact 包含 `current_term`、`voted_for`、log、snapshot index/term 和 checksum。
follower 只有在对应 hard state/log entry 已 durable 后才能回复成功。leader 写入流程为：

1. 校验 command、request UUID、ACL 和资源配额。
2. 本地 append WAL 并等待 durable completion。
3. 并行复制给 followers；只计算 durable success。
4. 当前 term 的 entry 获得多数派后推进 `commit_index`。
5. 按 index 顺序应用 deterministic state machine。
6. gateway 只在目标 command 已 apply 后返回成功。

三 voter quorum 为二，容忍一个 crash fault；五 voter quorum 为三，容忍两个。V1 固定三个 voter，
storage node 不参与投票。少数分区拒绝 write 和 linearizable read，不以 stale cache 假装成功。

### 7.4 Timeout 与读取

election timer 使用 monotonic clock 和 CSPRNG 随机窗口。部署值由观测计算：

```text
base_election_timeout >= max(10 * peer_RTT_P99,
                             2 * durable_fsync_P99,
                             operator_minimum)
heartbeat_interval <= base_election_timeout / 5
randomized_election_timeout in [base, 2 * base]
```

这些是启动配置和校验关系，不是 wire 常量。V1 linearizable read 使用 quorum ReadIndex；不使用
wall-clock leader lease。显式 `stale=allowed` 的诊断读取可以返回 applied index，并必须在响应中暴露
staleness，不能用于 GET/HEAD 的默认 namespace 语义。

### 7.5 Log、snapshot 与幂等

- client mutation 带 CSPRNG request UUID；state machine 保存有界 dedupe result。
- manifest 被拆为有界 pages，通过多个 Raft commands 写入；最终 object commit 只引用已 committed pages。
- snapshot 包含完整 namespace、manifest pages、policy 和 dedupe floor，并带 version/hash。
- snapshot 写临时文件、fsync、原子替换并同步目录；安装完成前旧 snapshot/log 保持可恢复。
- compaction 只删除已被 durable snapshot 覆盖且所有必要状态可重建的 log prefix。

## 8. Metadata model

核心命令建议保持窄而确定：

- `CREATE_BUCKET` / `DELETE_BUCKET`
- `SET_BUCKET_POLICY`
- `BEGIN_UPLOAD` / `RECORD_PART` / `ABORT_UPLOAD`
- `PUT_MANIFEST_PAGE`
- `COMMIT_OBJECT_VERSION`
- `TOMBSTONE_OBJECT_VERSION`
- `UPDATE_PLACEMENT`，仅由 repair 完成且 receipt 验证后提交

committed object version 至少包含：

```text
tenant_id, bucket_id, object_key, version_id
object_size, content_type, root_hash
manifest_page_ids[]
placement_policy_id
created_at, retention/tombstone state
encryption key envelope reference
committed_raft_index
```

object key 是 namespace，不是内容身份。chunk CID 由 versioned hash algorithm、长度和 bytes 计算；
hash algorithm ID 必须进入 manifest，禁止未来静默改变算法。

## 9. Chunk store 与 placement

### 9.1 Immutable CAS

store 接收 `PUT_CHUNK` 时：

1. 验证短期 capability、audience node、CID algorithm、declared length 和 quota。
2. 流式写入同 filesystem 的随机临时文件，同时计算 CID。
3. EOF 后比较 computed CID 与 requested CID；不匹配则删除临时文件并失败。
4. fsync file，原子 publish 到 CID path，必要时 fsync parent directory。
5. 返回由 store identity 签名的 durable receipt。

已存在相同 CID/length 的 chunk 是幂等成功；相同路径但内容或 header 不一致视为 corruption，节点
进入只读隔离并触发审计。store 不接受原地覆盖。

### 9.2 V1 placement

建议默认 profile 使用三个目标副本、至少两个 durable receipt，并要求跨不同 failure domain。
`target_replicas`、`min_durable_replicas`、failure-domain label、chunk size 和并发度均为外部配置。
初始 chunk size 可取 8 MiB，但实现必须支持 versioned profile，不能把该值写死为协议不变量。

placement score 可使用 free capacity、failure domain、store health 和 Mesh path cost。瞬时观察只用于
leader 形成 proposal；committed manifest 记录实际 receipt/placement。目标副本未全部完成但达到
最小持久化条件时可 commit，并立即生成 repair debt；未达到最小条件则整个 PUT 失败。

## 10. Object write transaction

```text
HTTP PUT/multipart
  -> gateway auth + quota + leader resolve
  -> BEGIN_UPLOAD
  -> stream body, chunk, hash and optional encrypt
  -> parallel PUT_CHUNK to selected stores
  -> collect and verify durable receipts
  -> PUT_MANIFEST_PAGE(s)
  -> COMMIT_OBJECT_VERSION through Raft
  -> return ETag/version/committed index
```

关键不变量：

- data durable before metadata commit。
- metadata commit 是对象可见性的唯一切换点。
- metadata commit 前失败留下的 chunk 是 orphan，不回滚不可变 CAS；由 grace-period GC 回收。
- metadata commit 后 gateway 断线，重试使用相同 request UUID 返回同一 version/result。
- overwrite 创建新 version，不原地修改旧 manifest/chunk。
- multipart complete 校验 part order、ETag/CID、总大小和 upload generation；失败不提交半个对象。

## 11. Object read and Range

默认 GET/HEAD 通过 leader ReadIndex 或已确认的 linearizable read barrier 读取 object version。gateway
把 HTTP Range 映射到 manifest chunk span，仅选择需要的 chunks：

1. 取得 immutable manifest snapshot 和 applied Raft index。
2. 按 Mesh path/health 选择最近 eligible replica；授权事实不由距离覆盖。
3. 为 CID、gateway 所需的完整 chunk span、audience store、request UUID 和 expiry 签发短期 capability。
4. 使用 bounded parallel bulk streams 读取，按顺序向 HTTP response 施加背压。
5. V1 对边界 chunk 也读取完整 bytes 并验证 CID，只向 HTTP client 发出请求 range；不把 transport
   integrity 当作内容 hash 的替代。并行窗口必须有界，不能按对象总 chunk 数分配 buffer。
6. 正确返回 `Accept-Ranges`、`Content-Length`、`Content-Range`、ETag 和 version ID。

若一个 replica hash/receipt 失败，标记 corruption observation 并尝试另一已授权 replica；只有完整
range 被验证并发送时读取才算成功。所有候选失败返回明确 5xx/data-unavailable，不能返回截断 200。

## 12. Delete、GC 与 repair

- DELETE 通过 Raft 提交 tombstone；commit 后新 linearizable read 不再返回该 version。
- retention/version policy 决定旧 version 是否仍可读取，不由 store 本地时间自行删除。
- GC 使用 committed snapshot 做 mark source；chunk 必须同时满足 unreferenced、grace period 到期、
  无 pending upload lease，才可 sweep。
- repair 从 committed placement 与健康 observation 计算 debt，从健康 replica 复制并验证 CID，取得
  新 durable receipt 后通过 `UPDATE_PLACEMENT` 提交；旧 placement 只有在 commit 后才移除。
- scrub 周期读取 chunk header/bytes 并重算 CID；corruption 不允许静默修补原文件。

## 13. HTTP/S3 surface

### 13.1 Native M3 API

V1 先提供 narrow native API，使用 explicit Iris app 和 stream routes：

```text
PUT    /m3/v1/buckets/{bucket}/objects/{key}
GET    /m3/v1/buckets/{bucket}/objects/{key}
HEAD   /m3/v1/buckets/{bucket}/objects/{key}
DELETE /m3/v1/buckets/{bucket}/objects/{key}
POST   /m3/v1/uploads
PUT    /m3/v1/uploads/{upload_id}/parts/{part_number}
POST   /m3/v1/uploads/{upload_id}/complete
DELETE /m3/v1/uploads/{upload_id}
```

以上路径只表达语义，不冻结 Iris route pattern。object key 必须支持 `/`、percent encoding 和 UTF-8；
最终 adapter 必须使用经过测试的 catch-all route/canonicalizer，且每个 component 只解码一次，避免
`%2F`、重复 slash 或 double-decode 产生授权别名。

请求 body、bucket/key/header/range/multipart 数量都由 Iris security limits 和 M3 domain limits 双重
校验。HTTP adapter 只把外部格式转换为类型化 command/query，不在 handler 内直接修改 storage state。

### 13.2 S3 compatibility

S3-compatible path-style gateway 是后续 profile，复用 TurboHTTP 的 XML、credential provider 和 S3
client 做 conformance，但 server-side SigV4 verifier 必须是独立、可测试的 trust boundary。第一批
兼容操作限定为 bucket CRUD、Put/Get/Head/Delete Object、ListObjectsV2 和 multipart；lifecycle、
replication、SelectObjectContent、legal hold 等不能返回伪成功。

## 14. Security and audit

- internal service admission 绑定 Mesh node identity 和 `m3.gateway`/`m3.meta`/`m3.store` role。
- Raft voter allowlist 来自固定 cluster configuration；service discovery 只提供 endpoint hint。
- chunk capability 最小授权到 tenant、CID、operation、range、audience、expiry 和 request UUID。
- bucket/object ACL 的唯一事实源是 committed Raft state；gateway cache 只能按 applied index 派生。
- object encryption 使用 per-object data key；Raft 只保存 key envelope reference，不记录明文 key。
- secret、token、SigV4 key、data key、presigned query 不进入日志或错误文本。
- mutation audit 至少记录 principal、operation、bucket/key hash、version、Raft term/index、result 和
  trace ID；审计 sink 失败策略由部署 profile 明确，不能静默丢失。

M3 V1 防止未授权访问、重放、内容篡改和单节点 crash，但不防止获得合法 voter/store identity 的
恶意节点协同作恶。跨不可信组织部署必须另行设计 BFT metadata 和 proof/audit model。

## 15. Failure semantics

| 失败 | 对外结果 | 可接受内部状态 |
|------|----------|----------------|
| leader unavailable/minority partition | 503 + retry hint | 无 metadata mutation |
| chunk 未达最小 durable replicas | PUT 失败 | orphan chunks 等待 GC |
| Raft commit 失败 | PUT 失败/状态未知需按 request UUID 查询 | durable orphan chunks |
| commit 成功但 HTTP response 断开 | 客户端可幂等重试 | object 已可见且 version 不变 |
| GET replica timeout | 尝试另一 eligible replica | corruption/timeout observation |
| 所有 replicas 不可用 | 明确 data unavailable | metadata 不删除、不伪造空对象 |
| store disk full | 该 store 拒绝新 chunk | 已 committed chunks 保持可读 |
| snapshot/WAL corruption | voter fail-fast 不参选 | 由健康 voter snapshot 恢复 |

## 16. Resource and observability contract

配置必须覆盖并在启动时校验：voter 列表、frame/entry/log/snapshot limits、election/heartbeat 关系、
chunk/profile size、replica policy、per-tenant quota、pending uploads、parallel streams、HTTP limits、
GC grace、repair bandwidth 和 disk reserve。

至少导出：

- Raft role/term/leader/commit/applied index、replication lag、election count、fsync P50/P95/P99。
- PUT/GET/Range latency、bytes、backpressure time、retry/error counts。
- store used/free/reserved bytes、chunk count、corruption、orphan、scrub result。
- replica debt、repair queue age/rate、GC mark/sweep counts。
- 每个错误携带 operation、tenant/bucket/object 摘要、request UUID、stage 和稳定错误码。

## 17. Verification gates

### 17.1 Deterministic Raft tests

- 3/5 node election、leader crash、follower restart、duplicate/reordered/dropped RPC。
- network partition、minority rejection、old-term response、log conflict truncation。
- fsync failure、torn/corrupt WAL、snapshot install interruption、restart recovery。
- request UUID dedupe、ReadIndex linearizability、snapshot/compaction equivalence。

### 17.2 Storage tests

- chunk boundary/empty/maximum、CID mismatch、atomic publish、disk full、restart scan。
- target/min replica combinations、failure-domain constraint、repair and scrub corruption。
- orphan GC 不删除 committed、pending upload 或 retention-protected chunk。
- multipart abort/resume/complete ordering 与 gateway disconnect 幂等。

### 17.3 HTTP and integration tests

- Iris streaming upload 保持有界内存，body read error 不提交对象。
- chunked/Content-Length/Range response 在 send failure 时传播错误。
- S3 client conformance：Put/Get/Head/Delete/List/Multipart、SigV4 tamper 和 clock skew。
- local real three-node CoroNet cluster；随后在 eu/bj/sh 注入 latency、loss、partition 和 process kill。
- Debug/Release、Windows/Linux；涉及 CoroNet shutdown 时运行其 shutdown regressions。

## 18. Migration and rollback

1. 在独立 M3 target 建立 feature-off 的 Raft simulator、durable store interface 和 CoroNet adapter。
2. 固化 fixed-membership metadata KV，不接 HTTP、不保存对象。
3. 增加 local immutable chunk store 和 native M3 API，先单 store 验证 transaction。
4. 增加三副本 placement、repair、scrub、GC 和真实三节点测试。
5. 补齐 TurboHTTP error-returning response streaming 与 server-side SigV4，再启用 S3 profile。
6. 基于规模和故障数据评估五 voter、erasure coding 和跨 region policy。

M3 通过独立 feature/进程启停；关闭 M3 不改变 Mesh route、identity 或 TUN 行为。每个 on-disk format
和 wire protocol 都带 version。升级失败时停止新写入、保留旧 reader 和 snapshot/WAL/chunk 数据，
不得通过删除或隐式迁移回滚。


## 20. Phase 1 gateway 落地状态（2026-08）

turbo-p2p `mesh/` 内已落地一个单节点 M3 gateway 原型（`mesh/src/m3_gateway.*` +
`mesh/examples/m3_gateway_main.c`），用于验证网关层接线与 SigV4 边界，不是分布式 M3：

- 路由（Iris）：`PUT/GET/HEAD/DELETE /:bucket/:object`、`GET /`。
- 认证：`m3_gateway_sigv4`（server-side SigV4，见 2.3 复核）；未签名/篡改/过期请求返回 403。
- 存储：对象分块（≤ `max_chunk_bytes`）→ `m3_chunk_store`（不可变 CAS，落盘于
  `m3store/v1/chunks/`）；对象 CID = SHA-256(concat(chunk digest))，size = sum(chunk size)。
- 元数据：`m3_namespace_local_store`（单节点，`apply_put`/`apply_tombstone` + 线性化查询适配器）。
- 校验：PUT 校验 `x-amz-content-sha256` 与 body 一致；GET 逐 chunk `read_range` 后 `reply_chunked_*`
  流式返回，发送失败（-1）即终止，不误报成功。
- 测试：`test_m3_gateway_sigv4`（6 用例，自签名 + 篡改/过期/密钥/格式）；端到端冒烟覆盖
  小对象与 2MB 多块对象的 PUT/GET/HEAD/DELETE 闭环、403/404。

Phase 1 明确边界（后续 Phase 处理）：
- 单节点：元数据无 Raft（`m3_namespace_raft_adapter` 为 Phase 2 预留）；对象无副本/repair/GC。
- Iris 路由为非 stream，请求体整缓冲（main 将 `max_request_body_size` 提到 64MB）；Phase 2 改
  `iris_app_route_stream` + `req_read_body` 以支持无上限流式。
- object key 不含 `/`（单段路由参数）；query 不参与签名（multipart/范围参数后续支持）。
- 单凭证（AKID + 32 字节 secret），后续扩展多凭证/轮换。

Phase 2 目标：固定三 voter 的 Raft 元数据（复用 `m3_namespace_raft_adapter`）+ 流式路由 +
Range/206 与 multipart；Phase 3：chunk 副本/repair/GC 与容量配额。

### 20.1 已完成 vs 未完成（对照 V1 目标，2026-08）

已完成（单节点 S3 网关面）：
- S3 HTTP：`PUT/GET/HEAD/DELETE /:bucket/:object`、`GET /`、`GET /:bucket`（ListObjects：prefix/marker/max-keys/IsTruncated/NextMarker）、Range/206/416、ETag（带引号，各接口一致）。
- 认证：server-side SigV4（Authorization header、presigned URL、多凭证 resolver；x-amz-content-sha256 必填、时间窗 ±900s）。
- 数据面：不可变 chunk CAS（`m3_chunk_store`）、对象 CID=SHA-256(concat(chunk digest))、manifest 编解码、逐 chunk hash 校验。
- 元数据：单节点 `m3_namespace_local_store`（原子持久化 `namespace.bin` + 重启恢复 + 确定性枚举）。
- 校验/错误：payload hash 一致性、S3 错误 XML、未签名 403、缺失 404。

未完成（V1 目标内）：
- 分布式元数据：三固定 voter 的线性一致 namespace（Raft）——**适配层已实现，未接线到网关**（见 20.2）。
- PUT 原子提交：chunk 持久化 + Raft metadata commit 都成功才返回。
- 数据面：跨 failure domain 副本、后台 repair、GC（chunk 回收）、健康 replica 选择。
- 通过 Mesh 虚拟网络提供服务（当前为本地 HTTP）。
- multipart upload、无上限流式请求体（当前整缓冲 64MiB）、CopyObject、版本/标签/条件请求。
- 配置化容量配额、多租户 ACL、审计、监控指标。

### 20.2 下一步计划与 Raft 元数据可行性评估（2026-08，实证）

优先级：Raft 元数据（V1 核心）→ Mesh 接入 → 副本/repair/GC → multipart/流式/配额。

Raft 可行性评估结论（`事实`：已实证）：
- TurboRaft 已安装（`external/pkgs/turboraft`），含 `raft_service.h`、`raft_coronet_transport.h`（CoroNet transport）、`raft_sqlite_storage.h`、`raft_snapshot_*`、`raft_service_owner.h`。
- `m3_namespace_raft_adapter`（`mesh/src/m3_namespace_raft_adapter.c`，449 行）已完整实现：command encode/decode、state machine、bind_service、raft lookup adapter、propose、poll；测试 `test_m3_namespace_raft_adapter`（2 用例/41 断言）全绿。
- 仓库内参考实现 `mesh_control_raft_service`（TurboRaft 服务封装：sqlite + core config + transport + tick/step/poll）测试全绿（2 用例/33 断言）。
- `TURBOP2P_BUILD_TURBORAFT_M3=ON` 配置/构建成功（TurboRaft 包已接入）。

剩余工作（Phase 2a→2c）：
1. **Phase 2a 网关接线**：`m3_gateway` 从 local store 切到 raft adapter——init 建 raft service（`tr_raft_core_config_t` + `raft_coronet_transport`）、PUT/DELETE 用 `m3_namespace_raft_propose_v1`、GET/HEAD/List 用 raft lookup adapter、事件循环 poll 驱动；local `persist/load` 保留为单节点 fallback/测试用。
2. **Phase 2b 三 voter 部署**：固定三节点成员 + CoroNet transport + SQLite 持久化；gateway 只接受 leader 写、follower 提供 linearizable 读。
3. **Phase 2c 故障验证**：crash/partition/recovery、leader 切换、线性一致性读测试；对照 M3_DESIGN 17（Verification gates）的确定性 simulator 与 Raft 测试。

### 20.3 Phase 2a 落地状态（2026-08，已实现并验证）

- `mesh/src/m3_gateway_raft.*`：单 voter raft 元数据后端——SQLite（log/snapshot）+ `m3_namespace_raft_adapter`（状态机/线性化读/propose）+ no-op transport + open 时 tick 驱动自选 leader；`put/tombstone` 同步等待应用到本地 store；`lookup` 走 read-index barrier（异步，由网关 poll 驱动）。
- `m3_gateway`：元数据后端抽象（local/raft 二选一，`gateway_meta_*` helper），新增 `m3_gateway_init_raft_v1`；`m3_gateway_main` 支持 `--raft <sqlite>`。
- 验证：`test_m3_gateway_raft`（提交 + 线性化读 + tombstone + 重启恢复，2 用例/22 断言）全绿；raft 模式网关 e2e（PUT/GET/LIST + 重启后元数据恢复）通过；全量 ctest 54/54。
- 已知约束（Phase 2a）：单节点（无 transport/多副本）；TurboRaft `read_index` 要求当前 term 已提交条目——leader 就任后首次读前需先提交一次写（raft 标准行为，已注释于代码）；`TURBOP2P_BUILD_TURBORAFT_M3` 已置 ON 纳入常规构建。
### 20.4 Phase 2b-i 落地状态（2026-08，单进程三 voter 集群已验证）

- `mesh/tests/test_m3_raft_cluster.c`：单进程三 voter（`{1,2,3}`）raft 集群，内存 transport（`enqueue` 按目标投递 inbox + `step` 处理），每节点独立 namespace store + SQLite(`:memory:`) + `m3_namespace_raft_adapter`。
- 验证：选举出 leader → leader `propose` PUT → 复制 + quorum 提交 → **三个 voter 的状态机全部收敛**（各节点 store 均含该 key）。1 用例 / 8 断言全绿；全量 ctest 55/55。
- 结论：TurboRaft 三 voter 正确性（选举/复制/提交/多数派）与 m3 namespace adapter 多节点应用已验证，为 Phase 2b-ii（真实 CoroNet transport + 三进程部署 + follower 读）铺路。
- **重要发现（约束）**：TurboRaft 	r_raft_core_read_index 仅 leader 支持（非 leader 直接返回 TURBO_EPROTO，core 层无 read-index 转发）。因此 M3 的 linearizable 读必须**路由到 leader**；「follower 提供读」需要 TurboRaft 上游增加 read-index 转发（或上层把读请求转发给 leader）。Phase 2b-ii 按「读走 leader」设计。

### 20.5 Phase 2b-ii（wire codec 边界）落地状态（2026-08）

- mesh/tests/test_m3_raft_wirecodec.c：三 voter 集群，所有 raft 消息经 	r_raft_wire_codec 编解码后投递（模拟进程/网络序列化边界），验证选举 + quorum 提交 + 三节点状态机收敛。1 用例 / 9 断言全绿；全量 ctest 56/56。
- 依赖：wire codec 使用 DataBind（TBE），运行需 data_bind.dll（已纳入顶层 runtime DLL 复制 target）。
- 说明：本步验证「跨序列化边界后 raft 正确性不变」，为真实 CoroNet transport 三进程部署（含 TLS 身份 + 事件循环）提供 wire-format 证据；CoroNet transport 集成仍为后续独立迭代。

### 20.6 Phase 2b-ii（CoroNet transport 组件验证）落地状态（2026-08）

- mesh/tests/test_m3_raft_coronet_transport.c：验证 CoroNet raft transport 组件 API 可用性——确定性拨号方向（小 ID 拨出/大 ID 接收）、peer manager 配置校验（重复/乱序/含自身 id 拒绝，空 peer 列表合法）、证书身份解析（sha256: 指纹 → node id；未注册指纹拒绝）。3 用例 / 18 断言全绿；全量 ctest 57/57。
- 结论：transport 组件 API 可用且约束明确，真实三进程部署的剩余工作集中在 CoroNet 事件循环集成（session/inbound/dial）+ TLS 证书签发 + 网关 leader 读路由。



风险与前置：
- TurboRaft 需按 M3_DESIGN 4.4 完成独立准入复核（许可/ABI/事件循环约束；测试已覆盖单服务，三节点网络待验证）。
- 网关切 raft 后，`applied_index` 同步与 propose 失败重试语义需明确（幂等 command_id 去重）。
- 构建开关：`TURBOP2P_BUILD_TURBORAFT_M3` 默认 OFF；建议 Phase 2a 起默认 ON 以纳入常规构建/测试。
## 19. Primary references

- Raft extended paper: <https://raft.github.io/raft.pdf>
- AWS S3 multipart upload overview: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html>
- HTTP semantics and Range requests: <https://www.rfc-editor.org/rfc/rfc9110.html>

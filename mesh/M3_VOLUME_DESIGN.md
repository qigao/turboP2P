# M3 可写远程块设备设计

## 1. 文档状态与结论

本文定义基于 M3 不可变内容寻址存储（CAS）的可写远程 volume 方案。它是工程设计和验证基线，
不是当前产品能力或销售承诺。

文中使用三类标记：

- `事实`：来自当前仓库实现、测试或已有设计约束。
- `目标`：本设计要求实现并验证的行为。
- `推论`：基于现有能力得到的设计判断，仍需通过实现和故障测试确认。

核心结论：**Hash 块显著简化数据不可变性、去重、校验、快照和复制，但不能单独保证可写块设备
正确性。** 可写正确性还需要逻辑块映射、写入顺序、durable receipt、Raft root commit、幂等请求、
单写者 lease/fencing，以及明确的 `FLUSH`/`FUA`/断线语义。

V1 采用：

```text
4 KiB logical block
        |
        v
immutable data blob in M3 CAS
        ^
        | LBA -> CID
copy-on-write sparse Merkle tree
        |
        v
Raft committed {root CID, generation, writer fence, committed sequence}
```

Raft 只复制小型可变元数据，不复制 data blob 或 Merkle node bytes。一次写入只有在所有新引用 blob
达到最小持久副本数、且新 root 经 Raft commit 后才成功。

## 2. 与现有 M3 的关系

`事实`：当前 M3 已提供以下可复用基础：

- SHA-256 CID 标识的不可变 chunk；写入时校验预期 CID，使用临时文件、fsync 和原子 rename 发布。
- 多 store 数据面、目标副本数、最小 durable replica 数和绑定 CID/request ID 的签名 receipt。
- “data durable before metadata commit”；metadata commit 是对象可见性的唯一切换点。
- commit 前失败产生 orphan，交由 grace-period GC 回收；request UUID 支持幂等恢复。
- repair 先生成 durable 新副本并提交新 placement，之后才允许移除旧副本。
- Raft namespace adapter 和三 voter 选举、复制、quorum commit 的测试基础。

`事实`：当前仓库没有 NBD、iSCSI、FUSE 或其他可挂载块设备实现。

`目标`：volume 复用 M3 CAS、store transport、receipt、repair、GC 和 Raft 基础设施，但拥有独立的
metadata state machine、wire protocol、权限、资源配额和测试。S3 bucket/key namespace 不是 volume
事实源，volume 写入也不通过对象 PUT/overwrite 隐式推进。

## 3. 目标与非目标

### 3.1 V1 目标

- 从单机 profile 起步，并可在不改变逻辑块身份和 volume API 的前提下迁移到固定三 voter、多 store。
- 提供 4 KiB 对齐的 `READ`、`WRITE`、`FLUSH`、`FUA`、`WRITE_ZEROES` 和 `DISCARD`。
- 单写者、线性一致 root 切换、明确的 read-after-write 和崩溃恢复语义。
- 不可变块的端到端 CID 校验，以及 cluster profile 下的副本、repair、scrub 和 GC。
- 快照和基于快照的 clone；两者都通过固定 Merkle root 实现。
- Linux 首个可挂载适配器采用成熟 NBD 实现或框架，适配器保持薄层。
- 所有队列、请求、缓存、并发和保留 payload 都有硬上限和背压。

### 3.2 V1 非目标

- 多写者共享磁盘或集群文件系统语义。
- 跨地域同步数据库盘的性能承诺。
- 动态 store membership、在线 store-set 迁移或 erasure coding。
- 小于 4 KiB 的逻辑扇区、未对齐 I/O、可变 block size。
- volatile write-back cache、客户端离线写入或冲突合并。
- volume shrink、在线 compact、跨租户收敛加密去重。
- 自研 OS 内核驱动或自创通用块设备协议。

## 4. 候选方案与决策

| 方案 | 优点 | 主要问题 | 决策 |
|------|------|----------|------|
| 每个 LBA 是可覆盖文件偏移 | 实现直观，顺序读性能容易理解 | 原地写破坏 CAS，不易做原子快照、去重和多副本校验 | 不采用 |
| 每个写入生成完整 LBA map | 查询简单 | 元数据随 volume 容量线性增长，root commit 过大 | 不采用 |
| 日志结构映射 + 周期 checkpoint | 顺序写友好 | replay、compaction、GC 和故障边界复杂 | 暂不采用 |
| 不可变数据块 + COW Merkle tree + Raft root | root 小、快照廉价、增量写只改路径、适配 CAS | 随机写产生多个小 node，需缓存和批量发布 | V1 采用 |

`推论`：该方案把“数据是否正确”简化为 CID 校验，把“哪个版本可见”简化为一个 committed root；
但它没有消除写入事务，只是把事务提交点收敛到了 root。

## 5. V1 固定 profile

| 参数 | V1 值 | 约束 |
|------|-------|------|
| logical block | 4096 bytes | offset 和 length 必须 4 KiB 对齐 |
| Merkle fanout | 64 | 每层使用 6 bit LBA 索引 |
| Merkle height | 5 | `64^5 * 4096 = 4 TiB` |
| maximum volume size | 4 TiB | 创建和 grow 后仍须为 4 KiB 整数倍 |
| maximum write transaction | 256 KiB / 64 blocks | 大请求由 adapter 有序拆分 |
| writer count | 1 | 由 committed lease 和 fencing token 约束 |
| mutation order | per-volume serial | read 可以有界并发 |
| store set | fixed per volume | 动态迁移不进入 V1 |
| Cluster target replicas | default 3 | 外部配置，不是协议常量 |
| Cluster minimum durable replicas | default 2 | 未达到即拒绝 root commit |

Starter profile 可使用一个本地 store 和一个 durable metadata adapter，但必须明确标记为非高可用；
Cluster profile 使用固定三 voter，并按部署策略跨 failure domain 放置 store。两个 profile 使用相同的
canonical blob、Merkle tree、volume commands 和错误语义，禁止在 Cluster 配置错误时静默退回 Starter。

## 6. Canonical blob 与 CID

### 6.1 CID 计算

所有 volume blob 使用独立 domain separator，避免与普通 M3 object chunk 混淆：

```text
CID = SHA-256(
    "m3-volume/v1" ||
    blob_type ||
    profile_id ||
    canonical_payload_length ||
    canonical_payload
)
```

整数统一使用网络字节序；reserved bytes 必须为零；解析器拒绝未知 version、未知 type、非 canonical
长度和非零 reserved 字段。CID 覆盖完整 canonical 表示。store 仍按现有临时写、校验、fsync、原子
publish 流程保存 blob，不允许原地覆盖。

### 6.2 Data blob

V1 data payload 恰为 4096 bytes。逻辑全零块使用“缺失 leaf”表示，不创建 zero blob。若启用静态加密，
存储 payload 是带随机 nonce 和 AEAD tag 的密文 envelope，CID 对密文 canonical blob 计算；相同明文
再次写入不保证得到相同 CID，但未改变的 COW block 仍然共享。

### 6.3 Merkle node

每个 node 包含：

```text
magic, format_version, node_type, level, profile_id
presence_bitmap: 64 bits
children[64]: 32-byte SHA-256 digest
```

缺失 entry 的 digest 必须全零。`level == 0` 的 child 指向 data blob；更高 level 指向下一层 node。
node 约 2.1 KiB，固定大小和 canonical encoding 使任意节点都可独立校验。根为 level 4，五个 6-bit
索引覆盖最多 `64^5` 个逻辑块。空 volume 使用 profile 定义的 canonical empty root CID。

解析 parent 时，child blob 类型和期望 level 由 parent level 推导；类型不匹配、CID 不匹配、越过
logical size 或结构非 canonical 都是数据损坏，不能解释为零块。

## 7. 状态事实源与所有权

### 7.1 Raft committed state

每个 volume 的唯一可变事实源至少包含：

```text
volume_id, tenant_id, profile_id
logical_size, store_set_id
root_cid, generation
writer_id, fencing_token, lease_state
committed_write_sequence
bounded request_id -> result dedupe records
snapshot_id -> {root_cid, generation, logical_size}
encryption_key_envelope_reference
```

所有 mutation 按 Raft log index 应用。读缓存、store 健康、路径 RTT、repair debt 和 replica observation
只是派生状态，不能独立改变 root、lease 或 snapshot。

### 7.2 CAS state

CAS 保存 immutable data blob、Merkle node 和可选 transaction descriptor。它不判断某个 root 是否可见，
也不因本地存在一个 blob 就把写入视为成功。

### 7.3 Runtime owner

每个已 attach volume 由一个 owner event loop 管理可变 runtime 状态：writer session、next sequence、
mutation FIFO、in-flight transaction、root cache 和 shutdown phase。只有 owner 可以发起 mutation；worker
只执行有界 hash、CAS I/O 或网络 I/O，并把完成事件送回 owner。

## 8. Raft 状态机命令

V1 命令保持窄、确定且带 `request_id`：

- `CREATE_VOLUME`
- `ACQUIRE_WRITER` / `RENEW_WRITER` / `RELEASE_WRITER`
- `EXPIRE_WRITER` / 管理员显式 `FENCE_WRITER`
- `COMMIT_ROOT`
- `CREATE_SNAPSHOT` / `DELETE_SNAPSHOT`
- `CLONE_VOLUME`
- `GROW_VOLUME`

`COMMIT_ROOT` 至少携带：

```text
volume_id
request_id
writer_id
fencing_token
write_sequence
expected_generation
previous_root_cid
new_root_cid
transaction_descriptor_cid
```

状态机只在下列条件全部满足时应用：fence 与当前 writer 相同、sequence 是上一个 committed sequence + 1、
generation 和 previous root 精确匹配、request ID 未以不同参数使用。成功后原子更新 root、generation、
sequence 和 dedupe result。重复 request ID 返回原结果；同一 request ID 参数不同返回冲突错误。

durability receipt 的签名、store set、CID 和最小副本数由 leader 在 propose 前验证。Raft 假设 crash fault，
不把恶意 leader 纳入 V1；状态机不在 apply 阶段执行网络读取。transaction descriptor 可保存本次新增
CID、目标 store 和 receipt 摘要，用于审计、repair 和 unknown-commit 恢复，但 blob bytes 不进入 Raft log。

dedupe 记录必须有容量和 compaction floor。客户端不得在记录过期后重用 request ID；snapshot 必须保存
可接受的 dedupe window 和 floor，避免 log compaction 后把旧请求误作新写。

## 9. Writer lease 与 fencing

V1 每个 volume 只允许一个 writer。`ACQUIRE_WRITER` 经 Raft commit 分配单调递增 fencing token；后续
每个 mutation 都携带该 token。新 writer 获得更大 token 后，旧 writer 即使仍能访问 store，也只能
产生未引用 orphan，不能提交 root。

lease timeout 可以触发 leader 提议 `EXPIRE_WRITER`，但超时观察本身不修改状态；只有 expiry 或新的
fence command committed 后才允许接管。leader 切换时应保守等待 lease 上限和 clock-skew margin，或由
管理员显式 fence。时钟只影响可用性，不得绕过 token 检查影响安全性。

renew、release、expire 和 force fence 都写入审计记录。session 断线不等于 lease 立即失效；adapter
必须停止提交，Controller 或新 leader 按策略完成 fencing。V1 不支持两个 NBD connection 共享写 lease，
也不宣告 `NBD_FLAG_CAN_MULTI_CONN`。

## 10. WRITE 事务

### 10.1 正常流程

```text
validate auth, alignment, size, lease, fence, sequence and quota
  -> read current committed root
  -> hash/encrypt changed 4 KiB data blobs
  -> build changed Merkle paths bottom-up, coalescing shared parents
  -> publish all new data/node/descriptor blobs to target stores
  -> verify minimum durable receipts for every newly referenced blob
  -> Raft COMMIT_ROOT(previous root, new root, sequence, request ID, fence)
  -> wait until command is committed and applied
  -> ACK
```

同一 volume 只允许一个 root mutation in flight，因此 write order 等于 owner 分配的 sequence。发布 CAS
blob 可以在事务内部有界并发，但 root commit 不可越序。adapter 把超过 256 KiB 的请求拆成多个有序
事务；拆分后不提供跨事务原子性，设备上层必须通过 `FLUSH`/日志文件系统建立更大事务边界。

### 10.2 失败边界

- receipt 未达到最小副本数：不提交 root，返回 `DATA_NOT_DURABLE`，已写 blob 成为 orphan。
- Raft 明确拒绝：不提交 root，返回对应 fence/conflict/quorum 错误，blob 等待 GC。
- commit 成功但 ACK 丢失：客户端以相同 request ID 查询或重试，得到相同结果。
- commit 状态无法判定：内部返回 `UNKNOWN_COMMIT`，禁止生成新 request ID 盲重试。

NBD 无法完整表达 `UNKNOWN_COMMIT`。NBD adapter 必须先按 request ID 查询；超时仍无法判定时，断开
该 writer session 并把 attach 置为 `recovery_required`，重新 attach 时先恢复 sequence/dedupe 状态。
不能把状态未知映射成普通可安全重试的 `EIO` 后继续接受后续写。

## 11. READ、一致性与校验

V1 attach 和读 root 通过 leader ReadIndex 或等价线性一致 barrier。若 metadata quorum 不可用，READ 和
WRITE 都 fail closed；不从可能过期的本地 root 猜测数据。未来可以增加显式只读 snapshot/offline profile，
但不能作为 V1 隐式 fallback。

一次 READ 固定使用开始时取得的 committed root snapshot：

1. 按 LBA 的五层索引解析 Merkle path；缺失 entry 返回零。
2. 根据固定 store set 和 CID 计算 eligible replicas，按 Mesh path/health 选择来源。
3. 读取完整 node/data blob 并验证 CID、类型、profile、长度和 AEAD。
4. 将验证后的 requested bytes 返回 adapter。

坏副本产生 corruption observation，并尝试另一个已授权副本；所有候选失败返回 `DATA_UNAVAILABLE`。
repair 根据 observation 异步进行，不能让未验证 bytes 进入客户端或 cache。读取 cache 仅以 CID 为 key，
有容量上限；root/generation 变化不要求失效不可变 blob，但 root path cache 必须按 root CID 分区。

## 12. FLUSH、FUA、DISCARD 与 zero

V1 使用 write-through：

- 普通 `WRITE` 返回时，所有新引用 blob 已达到 minimum durable replicas，root 已 committed/applied。
- 带 `FUA` 的 WRITE 与普通 WRITE 使用同一 durable 完成条件，不实现易失 write-back 快路径。
- `FLUSH` 进入同一 per-volume FIFO，等待此前所有 accepted sequence 得到确定结果，再返回成功。
- `WRITE_ZEROES` 和 `DISCARD` 都通过删除对应 leaf、重建 Merkle path 和 commit 新 root 实现。

V1 的 `DISCARD` 是逻辑归零提示，不保证立即物理擦除、空间回收或安全销毁；物理回收由 snapshot-aware
GC 决定。NBD adapter 只有在相应内部操作完整实现并通过 crash test 后，才公告 FLUSH、FUA、TRIM 和
WRITE_ZEROES capability。未支持的 flag 必须在协商期拒绝，不能接收后伪成功。

## 13. 快照、clone 与 resize

- snapshot command 把当前 `{root CID, generation, logical size}` 固定为新的 GC root，创建为 O(1) 元数据操作。
- clone 以 snapshot root 创建新的 volume record，之后各自 COW；writer lease、sequence 和 encryption
  policy 独立，不能从源 volume 继承活动 writer。
- 删除 snapshot 只删除 Raft 引用；实际 blob 由后续 GC 判定。
- V1 只支持 grow。grow 经 Raft commit 更新 logical size，新范围读为零；shrink 不支持，避免静默截断。

snapshot 只保证块设备 crash-consistent。如果需要应用一致性，调用方必须先冻结应用或文件系统并
执行 FLUSH，再创建 snapshot；M3 不伪造 guest/application quiesce。

## 14. Placement、repair 与 GC

### 14.1 确定性 placement

V1 volume 绑定固定 `store_set_id`。目标 store 按下式做确定性 rendezvous 排序：

```text
score = H(tenant_id || store_set_id || CID || store_id)
```

再应用 committed failure-domain 和 replica policy。这样 read、repair 和审计可从 CID 重算目标，不需为
每个 4 KiB block 在 Raft 保存 placement。容量不足或目标故障时，不允许任意选择未授权 store；任何
替代 placement 必须符合该 store set 的确定规则和 receipt policy。

固定 store set 不等于 store 永远健康。repair 从健康副本复制并校验 CID，取得新 durable receipt 后
更新可验证的 replica observation；移除旧副本前必须保证 committed root 所需的最小 durable replicas。
store-set 迁移会改变海量 blob 的归属和 GC 条件，单独作为后续协议设计。

### 14.2 可达性 GC

GC mark roots 包含：

- 每个 volume 的 current root。
- 所有 snapshot 和 clone root。
- 已进入 publish/commit 阶段的 active transaction descriptor 和 candidate root。
- 正在服务的 read pin。

blob 只有同时满足下列条件才能 sweep：从全部 roots 不可达、grace period 到期、无 active transaction、
无 read/pin，并且 replica/GC epoch 满足部署策略。任何 Merkle node 缺失、CID 损坏、解析失败或 mark
遍历不完整都必须中止该轮 sweep，不能把“无法证明可达”当作“不可达”。

GC、repair 和 scrub 使用独立低优先级有界队列，并受 IOPS/带宽配额限制。前台写压力下允许 repair debt
增长到告警阈值，但达到安全上限后应拒绝新写，不能无界积压。

## 15. `m3-volume/v1` 协议边界

volume core 提供类型化 API，并通过经认证的 Mesh/CoroNet session 暴露。V1 操作至少包括：

```text
NEGOTIATE / ATTACH / DETACH
GET_GEOMETRY / GET_STATUS
READ / WRITE / QUERY_REQUEST
FLUSH / WRITE_ZEROES / DISCARD
CREATE_SNAPSHOT
```

每个 frame 包含 protocol version、tenant/volume/session、request ID、operation、offset、length、flags 和
有界 payload length。协议协商固定最大 frame、alignment、feature bits 和 error codes。外部输入必须在
分配 payload 前校验长度、溢出、权限、session/fence 和配额。

数据 session 使用 Mesh node identity、volume ACL 和短期 capability；capability 至少绑定 tenant、volume、
operation、audience、writer fence、expiry 和 request ID。路径可直连或按策略中继，但传输选择不能改变
授权和持久化语义。Controller 只下发 intent/ACL，不转发块数据，也不是 root 事实源。

## 16. Linux NBD 适配器

首个 OS 接入采用成熟 NBD userspace server/framework 或隔离插件，不在 M3 core 中手写内核协议栈。
adapter 的职责只有：

- 协商并公告 4 KiB minimum/preferred block size 和实际 volume size。
- 把 NBD request handle 映射到内部 request ID，拆分大请求并维持 barrier/order。
- 把 NBD READ/WRITE/FLUSH/FUA/TRIM/WRITE_ZEROES 映射到 `m3-volume/v1`。
- 在 unknown commit、fencing、detach 和 shutdown 时执行规定的 session recovery。
- 把有限内部错误映射为 OS error，同时保存可诊断的稳定错误码和 trace ID。

adapter 不持有 root、不自行缓存未提交写、不选择 replica，也不绕过 owner loop。Windows adapter 和具体
驱动签名/部署边界在 Linux 正确性通过后另行评估。

## 17. 内存、队列与背压

建议初始上限：

| 资源 | 默认上限 | 满载行为 |
|------|----------|----------|
| single write payload | 256 KiB | 协商期限制或拆分 |
| per-volume mutation FIFO | 128 requests | 等待有界超时或 `RESOURCE_EXHAUSTED` |
| retained write payload | 32 MiB/volume | 拒绝继续接收 |
| concurrent reads | 64/volume | 排队或 `BUSY` |
| retained read payload | 16 MiB/volume | 暂停 socket read |
| global in-flight bytes | deployment configured | 跨 volume 公平背压 |

`32 MiB = 128 * 256 KiB`，只是 payload 预算，不含 Merkle node、加密和 transport overhead；实现时须用
实测 high-water mark 校准并设置进程级 hard limit。queue depth、timeouts、cache 和 background job 上限
均为外部配置，启动时验证乘积不会超过内存预算。

CoroNet receive buffer 在回调/协程边界按其所有权契约释放。borrowed payload 若会跨 suspend、入队或
交给 worker，必须先复制到 owned bounded buffer 或显式转移所有权。拒绝、取消、超时、fence 和 close
路径都必须有唯一释放点。V1 不需要 lock-free queue；单 owner + bounded FIFO 更易验证顺序和 shutdown。

## 18. Shutdown 与恢复

正常 shutdown 顺序：

```text
stop accepting new attach/write
  -> wake or cancel blocked producers
  -> reject queued but unstarted mutations
  -> resolve submitted Raft operations or mark UNKNOWN_COMMIT
  -> drain/cancel bounded active reads
  -> release recv buffers and owned request payloads
  -> release writer session according to policy
  -> close data sessions and listener
  -> stop managed coroutines
  -> destroy volume stores and CoroNet context
```

不得先销毁 context/store 再等待协程退出。crash restart 时从 durable Raft/local metadata 恢复 root、
generation、fence、sequence 和 dedupe window；扫描 CAS 只恢复 blob inventory，不推断可见 root。未完成
candidate roots 在 grace period 内作为 pending/orphan 处理。

## 19. 安全与加密

- volume create/attach/read/write/snapshot/fence 分离授权，默认最小权限。
- writer capability 必须绑定 fencing token；reader capability 不能升级为 writer。
- store receipt 和 blob read capability 绑定 CID、operation、audience、request ID 和 expiry。
- transport 必须认证并加密；relay 不能看到明文 volume data，具体端到端加密 profile 需固定。
- per-volume data key 使用 envelope reference；明文 key、token、NBD payload 和完整 CID 列表不进入普通日志。
- 随机 nonce AEAD 优先保护机密性；不采用跨租户 convergent encryption，避免内容相等性泄露。
- 配额覆盖 logical size、physical retained bytes、snapshot 数、IOPS、bandwidth 和 in-flight memory。

V1 是 crash-fault tolerant，不是 Byzantine storage。合法 voter/store identity 被攻陷后的协同恶意行为
需要独立的 BFT、远程证明或外部审计方案。

## 20. 失败语义

| 失败 | 对外结果 | 可接受内部状态 |
|------|----------|----------------|
| metadata quorum 不可用 | READ/WRITE fail closed | committed root 不变 |
| minimum durable replicas 不足 | `DATA_NOT_DURABLE` | orphan blob 等待 GC |
| stale writer/token | `FENCED`，session 停止写 | 旧 writer 可能留下 orphan |
| expected root/generation 冲突 | `WRITE_CONFLICT` | root 不变，重新 attach 恢复 |
| Raft commit 明确失败 | 对应稳定错误 | candidate blob 可回收 |
| commit 结果未知 | `UNKNOWN_COMMIT`，先 query | 可能已提交，禁止盲重试 |
| ACK 丢失 | 相同 request ID 返回原结果 | root 最多推进一次 |
| replica timeout/corruption | 尝试其他 eligible replica | 记录 observation/repair debt |
| 全部 replica 不可用 | `DATA_UNAVAILABLE` | 不返回零或未验证数据 |
| queue/global bytes 满 | `RESOURCE_EXHAUSTED`/`BUSY` | 不丢请求、不无界增长 |
| GC 遍历损坏/不完整 | 中止 sweep 并告警 | 不删除无法证明安全的 blob |
| shutdown 中已提交状态未知 | query 或 recovery-required | 不伪报成功/失败 |

## 21. 可观测性与审计

至少导出：

- volume root generation、committed sequence、writer/fence、lease age、attach count。
- READ/WRITE/FLUSH 延迟和 bytes，分别统计 data durable、Merkle build、Raft commit、backpressure 时间。
- queue depth/high-water、owned bytes、global in-flight bytes、timeout/cancel/fenced/unknown-commit 数。
- blob publish、receipt、replica availability、CID corruption、repair debt/age、scrub 和 GC mark/sweep。
- NBD disconnect/reconnect、request split、feature negotiation 和 error mapping。
- Raft role/term/leader/commit/applied index、replication lag、election 和 fsync P50/P95/P99。

每个 mutation audit 至少记录 principal、tenant/volume、operation、request ID、fence、sequence、old/new
generation、Raft term/index、结果和 trace ID；敏感 payload、key 和 token 必须脱敏。

## 22. 验证门槛

### 22.1 数据结构与模型测试

- canonical codec golden vectors、非 canonical 输入、type/level/length/CID 错误。
- 用 byte-array reference model 对 Merkle tree 做 property test：随机 aligned write/read/zero/discard。
- 空树、边界 LBA、4 TiB 上界、共享 parent、重复数据、同 CID 幂等 publish。
- snapshot/clone 隔离、grow 后零读、root 可达性和重启恢复。

### 22.2 状态机与故障注入

- lease acquire/renew/expire/fence、stale writer、sequence gap、generation conflict、request dedupe。
- 在 hash、每个 blob publish、receipt、descriptor、Raft propose/commit/apply、ACK 前后逐点注入故障。
- leader crash、minority partition、store crash/disk full、ACK 丢失和 unknown-commit 查询。
- repair 与 GC 并发；任何执行顺序都不得删除 current/snapshot/clone/pending/read-pinned blob。
- bounded queue full、global bytes full、producer timeout、cancel、fence 和每个 shutdown phase。

### 22.3 集成与系统测试

- 三 metadata voter + 多 store + 真实 CoroNet/Mesh transport，覆盖选举、重连和长期故障恢复。
- Linux NBD 临时 volume：`mkfs`、mount、文件校验、`fio`、FLUSH/FUA、unmount、reconnect、`fsck`。
- writer 被强制 fence、网络分区、leader/store 重启过程中运行 filesystem journal workload。
- ASan/TSan、CoroNet pending recv/close/shutdown regression 和长时间资源 high-water 检查。

### 22.4 性能门槛

正确性测试与性能测试分开。基准至少报告 4 KiB random read/write、256 KiB sequential、FLUSH latency、
IOPS、P50/P95/P99、CPU、网络和 write amplification，并分别测单机、局域网 Cluster 和经 relay 路径。
没有基线和长期测试前，不宣称适合数据库盘、跨公网低时延或具有特定吞吐。

## 23. 分阶段实现

1. **Merkle core**：canonical codec、COW tree、reference model、local CAS 和 property tests，不接 OS。
2. **单机 volume engine**：复用 local durable metadata adapter，完成 owner、事务、FLUSH、恢复和边界测试；
   明确标记非高可用。
3. **Cluster state machine**：接入固定三 voter、receipt、固定 store set、fencing、unknown-commit 和故障注入。
4. **Mesh data path**：实现 `m3-volume/v1`、capability、QoS、背压、repair/scrub/GC 和多进程测试。
5. **Linux NBD adapter**：选择成熟框架，完成 capability negotiation、session recovery、`fio`/`fsck` 门槛。
6. **快照与 clone 产品化**：配额、审计、运维命令、备份/恢复和滚动升级验证。

每一阶段通过 feature flag 和独立进程/target 暴露；未通过该阶段门槛的 feature 不在协议协商中公告。

## 24. 架构影响、兼容性与回滚

该方案新增 volume domain、Raft commands、CAS blob types 和协议，不改变现有 S3-shaped API、object CID、
release manifest 或 Mesh route 语义。新 blob 使用独立 domain/version，旧 store 可拒绝未知 type，避免
静默误读。volume metadata 使用独立 namespace/on-disk format，不与 bucket namespace 混写。

主要成本是 4 KiB data blob 带来的 metadata/小文件放大、随机写时最多五层 COW node、同步 root commit
延迟，以及 snapshot 保留造成的物理容量增长。实现前必须实测当前 filesystem CAS 是否能承受小 blob
数量；若不能，应在 store 内增加经过 benchmark 和 crash test 的 pack/index 层，但 CID 和上层协议不变。

回滚以 detach/disable volume feature 为边界：停止新写、确认或恢复 unknown commit、保留全部 committed
roots 和 CAS blobs，再回退服务。任何 on-disk format 升级都必须版本化、先写可回读 snapshot，并提供
升级中断恢复测试；不通过复制目录或删除未知 blob 完成降级。

## 25. 主要参考

- M3 对象存储设计：[`M3_DISTRIBUTED_STORAGE_DESIGN.md`](M3_DISTRIBUTED_STORAGE_DESIGN.md)
- NBD protocol：<https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md>
- Linux NBD：<https://docs.kernel.org/admin-guide/blockdev/nbd.html>
- Raft extended paper：<https://raft.github.io/raft.pdf>

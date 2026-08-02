# Mesh Node Execution with TurboRuntime

状态：架构规范与分阶段实现。E0 schema/journal simulator、E1 本地 prestaged runner core
和 E2 local durable command adapter core 已有实现；独立 OS worker、真实 signed Grant
authority 及 MMP network feature 尚未实现。本文不冻结公开 API、配置格式或 MMP wire
protocol。

## 1. 决策摘要

Mesh 节点执行采用独立、显式启用的 execution plane：

```text
Controller / authorized operator
  -> signed ExecutionGrant + command ID
  -> MMP targeted command and persistent journal
  -> node execution adapter
  -> isolated execution worker
  -> TurboRuntime
  -> TurboWasm
  -> wasm3
```

核心决策：

- MMP 负责身份、签名授权、重放防护、持久化幂等和签名结果，不解释 Wasm manifest。
- node execution adapter 只运行本机 deployment registry 中已预置、已校验 digest 的应用。
- TurboRuntime 负责 package、manifest、host grant、effective capability、runner 和 provider
  生命周期。
- TurboWasm 是 guest import、线性内存、host function 和执行配额的唯一强制边界。
- M3 可提供按内容寻址的 package、input 和 output artifact，但不授予执行权限。
- 不提供远程 shell、任意 argv、任意宿主路径、原始 socket、DLL 路径或 native symbol。
- V1 不把执行能力加入 MMP/1 baseline；必须通过 additive `node-execution-v1` feature 协商。
- feature 默认关闭。没有有效本地 execution policy、持久化 command journal 或安全 worker
  配置时，节点拒绝所有执行请求。

## 2. 当前事实

### 2.1 Mesh management

当前仓库已经具备以下可复用边界：

- MMP canonical envelope、Ed25519 signature、certificate 和 session identity binding。
- 有界 replay cache、sequence gate 和 typed dispatch。
- shared-node MMP runtime、签名 endpoint/RPC service discovery 和持久化 record epoch。
- 本地 RPC task classification，但当前 node mutation 只开放有限操作。

当前仍缺少：

- `COMMAND_REQUEST` / `COMMAND_RESULT` 完整 payload 和领域 adapter。
- 持久化 command journal。
- product-level Grants、policy compiler、signed rollout 和 audit closure。
- 独立 `mesh-agent` supervisor/service deployment。

因此 execution plane 不能直接接入现有 `/v1/task-model`，也不能把未实现的 command kind
当成稳定协议。

### 2.2 TurboRuntime and TurboWasm

当前 TurboRuntime 已公开：

- `turbo_runtime_create()` / `turbo_runtime_destroy()`。
- `turbo_runtime_load_app()`、`turbo_runtime_load_wasm()` 和 `turbo_runtime_app_run()`。
- host capabilities、mount grants、HTTP origins、provider capabilities 和 execution limits。
- input、stdout、stderr、stack、linear memory、module、deadline、control-flow step、
  host-call 和 copied-byte 配额。

TurboWasm 当前 capability 包含 core、utils、HTTP、file read/write 和 app。它拒绝未知或未授权
import，并强制 mount、origin、guest-memory 和 invocation quota。

TurboRuntime isolated provider worker 已提供协议、deadline、输出和进程树生命周期隔离，但当前
不等同于低权限 OS sandbox。生产 execution worker 仍需部署层账户、Windows Job/Linux cgroup、
filesystem namespace 和网络限制。

## 3. 目标与非目标

### 3.1 V1 目标

- 授权者可请求目标节点运行一个已预置、digest 固定的 TurboRuntime application。
- 同一 command ID 在重试、断线和节点重启后最多执行一次。
- manifest 只能请求能力；本机 policy 和 signed grant 只能缩小权限，不能扩大 host grant。
- CPU、memory、deadline、host calls、I/O 和 artifact 大小均有硬上限。
- 输入和输出通过有界 inline bytes 或不可变 artifact reference 表达。
- command 状态、执行结果、usage 和 audit correlation 可查询。
- management、network、object 和 execution policy 使用独立 typed schema。

### 3.2 V1 非目标

- 任意 shell、argv、环境变量或工作目录继承。
- 从网络 payload 接收宿主绝对路径、DLL、provider path 或 native pointer。
- 在 `meshd` packet event loop 内运行 Wasm。
- 自动下载并立即运行未知 module。
- 通用容器编排、长驻 service scheduler、cron 或 DAG workflow。
- 把 Wasm sandbox 描述为可以隔离受信 native provider 自身的系统调用。

## 4. 候选方案与取舍

| 方案 | 优点 | 风险 | 结论 |
|---|---|---|---|
| MMP 直接传 shell/argv | 实现快 | 任意代码执行；授权不可分析；不可移植 | 拒绝 |
| `meshd` 直接链接 wasm3 | 组件少 | 绕过 TurboWasm policy；扩大 TUN 进程攻击面 | 拒绝 |
| `meshd` 内嵌 TurboRuntime | 部署简单 | guest/provider 故障影响数据面；阻塞 event loop | V1 拒绝 |
| 独立 worker + TurboRuntime | 边界清楚；可限制账户和资源 | 新增 IPC、journal 和部署单元 | 采用 |
| M3 收到对象后自动执行 | 数据路径短 | storage authority 变成 execution authority | 拒绝 |

性能代价是一次本地 IPC 和 artifact staging；相对于隔离不可信执行，这是可接受的固定成本。
热路径仍是 Mesh packet forwarding，不经过 execution worker。

## 5. 组件与依赖方向

```text
Controller
  -> policy signer
  -> MMP command adapter

mesh-agent
  -> command journal
  -> execution policy snapshot
  -> execution supervisor adapter
  -> worker client

execution worker
  -> TurboRuntime::Runner/Core
  -> TurboWasm::Runtime
  -> TurboUtils

M3 client adapter
  -> package/input fetch by immutable digest
  -> output artifact commit
```

禁止反向依赖：

- Mesh core 不依赖 TurboRuntime、TurboWasm 或 M3。
- TurboRuntime 不依赖 MMP、Mesh identity 或 M3。
- M3 不依赖 execution command journal。
- execution worker 不修改 Mesh route、TUN、peer 或 policy snapshot。
- Wasm guest 不获得 MMP session、management key 或 raw Mesh socket。

## 6. 单一事实源

| 状态 | 唯一事实源 | 派生状态 |
|---|---|---|
| application deployment | 本机 deployment registry | loaded app cache |
| module/manifest identity | immutable package digest | display name/version |
| execution authorization | signed policy bundle + local host grant | effective grant |
| command lifecycle | target persistent command journal | RPC status/cache |
| runtime usage/result | execution worker result receipt | metrics/audit view |
| package/input/output bytes | M3 immutable object或本机 prestaged store | staging file |
| execution availability | local agent/worker health | Controller inventory |

M3 metadata、DHT cache、RPC response 和 UI cache 都不能推进 command 状态。

## 7. Deployment registry

网络请求不携带 package path。节点本机 registry 使用稳定 deployment identity：

```text
deployment_id
generation
package_digest
manifest_digest
module_digest
application_name
application_version
allowed_profile
enabled
installed_at
```

规则：

- deployment 由本机部署或受控 policy rollout 创建。
- package、manifest 和 module digest 必须在执行前重新验证。
- registry 中的 host path 不通过 MMP、RPC、result 或 audit 暴露。
- symlink、reparse point、absolute path、`..` 和非普通文件按 TurboRuntime 规则拒绝。
- package 更新创建新 generation；不能原地改变既有 digest。
- command 只引用 deployment ID、generation 和 digest。

## 8. ExecutionGrantV1

`ExecutionGrantV1` 是 policy compiler 生成并签名的不可变授权，不是通用 map：

```text
version
grant_id
mesh_id
policy_epoch
subject_principal
target_node_id
deployment_id
deployment_generation
package_digest
allowed_operation
capability_profile
mount_ids[]
mesh_service_ids[]
provider_capability_ids[]
max_limits
not_before_ms
expires_at_ms
issuer_key_id
signature
```

约束：

- `allowed_operation` V1 只有 `RUN_PRESTAGED_WASM`。
- target、generation 和 package digest 必须精确匹配。
- grant 不包含 host path、provider DLL path、secret、raw socket 或 environment。
- mount 使用本机 policy 定义的 mount ID；远程请求只能引用 ID。
- mesh service 使用 verified service ID；不能携带物理 endpoint。
- 未知 capability、重复 ID、空 production policy、过期 grant 和较旧 policy epoch 全部拒绝。
- grant expiry 不能超过 node certificate、policy bundle 和 deployment authorization expiry。

## 9. 权限与限额求交

有效权限只有一个计算路径：

```text
effective =
  application manifest request
  intersect local host grant
  intersect signed ExecutionGrant
  intersect node hard maximum
```

任一必需 capability 不在交集中时，整个 command 授权失败，不删除 capability 后继续运行。

每一维资源限额取最小值：

```text
effective_limit =
  min(manifest request, local host grant, ExecutionGrant, node hard maximum)
```

缺失、零值和 unlimited 语义必须由版本化 schema 明确定义，不能依靠 C 默认值推断。

## 10. ExecutionRequestV1

```text
command_id
grant_id
target_node_id
deployment_id
deployment_generation
package_digest
input_kind
input_digest
input_length
inline_input
output_mode
deadline_ms
request_nonce
correlation_id
```

输入模式：

- `NONE`
- `INLINE`：小型、有固定上限的 bytes。
- `M3_OBJECT`：tenant、object version、content digest 和只读短期 capability。
- `PRESTAGED_OBJECT`：本机 registry 中预置的 immutable input。

V1 不接受 argv。应用参数必须编码在版本化 input schema 中，避免平台 quoting 和编码差异破坏
command digest、幂等与审计。

## 11. Command journal

状态机：

```text
RECEIVED
  -> AUTHORIZED
  -> ACCEPTED
  -> STAGING
  -> RUNNING
  -> SUCCEEDED | FAILED | EXPIRED | CANCELLED | FAILED_INDETERMINATE
```

`REJECTED` 是未进入 ACCEPTED 的 terminal 状态。

处理顺序固定为：

```text
decode canonical payload
-> verify MMP signature/session/feature
-> verify replay/deadline
-> resolve current policy snapshot
-> verify ExecutionGrant
-> verify deployment and digests
-> persist ACCEPTED
-> stage immutable input
-> persist RUNNING
-> invoke worker
-> commit output artifact
-> persist terminal result
-> send signed COMMAND_RESULT
```

不变量：

- ACCEPTED 持久化前没有 guest/provider 副作用。
- 相同 command ID + 相同 request digest 返回已有状态，不再次执行。
- 相同 command ID + 不同 digest 返回 `COMMAND_CONFLICT`。
- ACCEPTED 后任何失败都持久化 terminal result。
- agent 崩溃后不能猜测 RUNNING 成功；无法确认 worker generation 时进入
  `FAILED_INDETERMINATE`。
- terminal 状态不可回退。

## 12. Worker、并发与资源

worker 输入只包含已验证 package authority、effective policy、有限 input/staging handle 和
command/correlation ID。它不接收 management key、Controller credential、MMP session、TUN
handle、deployment registry 写权限或 M3 metadata 写权限。

worker concurrency、pending queue、staging bytes 和 active output 都必须有固定上限。队列满返回
`RESOURCE_EXHAUSTED`，不创建无界线程或进程。阻塞 package I/O、fsync 和 worker wait 不在
Mesh/MMP event loop 执行。

## 13. 文件与 M3

文件规则：

- host root 只来自本机 host grant。
- request 只引用 mount ID 和 guest-relative logical name。
- TurboRuntime/TurboWasm 继续执行 handle-relative、no-follow、path、file size、open handle 和
  read/write quota。
- staging/output 按 command ID 隔离。

M3 capability 最小绑定：

```text
tenant
object/version or CID
operation
byte range
audience node
request UUID
expiry
```

execution adapter 只使用 package/input 的只读 capability，以及 output temporary object 的
create/commit capability。M3 fetch 成功只证明 bytes 与 digest 可用，不证明允许执行。

没有 M3 时，V1 仍可使用 prestaged package/input；不得回退到任意 HTTP URL 下载。

## 14. Mesh network access

TurboRuntime HTTP capability 按精确 origin 授权，并禁止 raw socket。Mesh execution 不应通过
关闭 private-address/SSRF 检查来访问虚拟服务。

需要网络访问时新增独立 `mesh.service/v1` provider：

- 输入为 verified service ID，不是 host/port 字符串。
- resolver 只返回签名 virtual DNS/IP。
- provider 重新检查 NetworkGrant、service capability、policy epoch 和 expiry。
- 物理 endpoint 不进入 guest、result 或 audit。
- request/response、timeout、并发和 bytes 有独立配额。

该 provider 完成前，远程 execution profile 默认无 Mesh 网络能力。

## 15. Result 与错误语义

`ExecutionResultV1`：

```text
command_id
request_digest
target_node_id
deployment_id
deployment_generation
package_digest
policy_epoch
grant_id
state
runtime_code
runtime_stage
guest_exit_code
usage
stdout_digest
stderr_digest
output_artifact
started_at_ms
finished_at_ms
worker_generation
correlation_id
result_signature
```

stdout/stderr 默认不内嵌完整内容。RPC 只返回有界摘要、长度和 artifact reference。Runtime failure
与 guest non-zero exit 保持不同语义。

稳定错误至少包括：

- `EXECUTION_FEATURE_DISABLED`
- `POLICY_MISSING`
- `POLICY_STALE`
- `GRANT_INVALID`
- `GRANT_EXPIRED`
- `DEPLOYMENT_NOT_FOUND`
- `DEPLOYMENT_DIGEST_MISMATCH`
- `COMMAND_CONFLICT`
- `RESOURCE_EXHAUSTED`
- `INPUT_UNAVAILABLE`
- `WORKER_UNAVAILABLE`
- `RUNTIME_FAILED`
- `GUEST_FAILED`
- `OUTPUT_COMMIT_FAILED`
- `FAILED_INDETERMINATE`

## 16. Cancellation 与 timeout

- deadline 在授权、排队、staging、worker 和 output commit 每阶段重新检查。
- ACCEPTED 前可直接取消；RUNNING 后取消是有 journal 的请求，不声称没有发生副作用。
- worker timeout 必须终止对应 process tree，并记录实际 kill outcome。
- timeout 后不自动使用新 command ID 重试。
- MMP disconnect 不取消已 ACCEPTED command。

## 17. Audit

每次请求至少记录 actor、target、command/grant ID、policy epoch、deployment/package digest、
effective capability digest、limits、状态迁移、runtime/guest result、usage、artifact digest、
correlation ID 和时间。

禁止记录 secret、完整 input/stdout/stderr、宿主绝对路径、管理私钥和物理网络 endpoint。

audit spool failure 由 deployment profile 明确选择：

- `required`：不能持久化 ACCEPTED audit 时拒绝新执行。
- `best-effort`：允许执行，但 health/status 必须显示 degraded。

## 18. 安全边界与剩余风险

已定义的边界：

- signed grant 不能通过 manifest 获得额外 host capability。
- M3 object ownership 不能授权执行。
- guest 不能选择 host root、provider binary、raw endpoint 或 shell 参数。
- module、manifest、input 和 output 绑定 digest。
- command ID 与 request digest 绑定。
- MMP relay 不能替 target 授权。

剩余风险：

- TurboWasm 只能限制 guest；同进程 native provider 仍是受信代码。
- isolated provider worker 当前不是低权限 OS sandbox。
- Wasm 逻辑 bug 仍可能产生合法但错误的业务输出。
- capability provider 错误解释 service/object ID 会破坏上层授权。
- signer/policy authority 失陷后可签恶意 grant，仍需 rotation、revoke、短 expiry、审批和审计。

## 19. 兼容、迁移与回滚

- execution 默认关闭，不改变现有 Mesh、MMP query、RPC 或 packet policy。
- 新 operation 只在双方协商 `node-execution-v1` 后使用。
- 不支持的节点返回 `UNSUPPORTED_FEATURE`，不能降级为 shell 或本地 RPC。
- 停用 worker 后，Mesh 数据面和 management query 继续工作。
- production policy 回滚使用更高 epoch 的已验证旧语义 bundle。
- package 回滚创建新 deployment generation，不修改旧 bytes。
- journal/result schema 版本化，升级失败保留旧 reader。

实施阶段：

1. **E0 schema/journal simulator**：固化 Grant/Request/Result、状态机和 crash/replay model tests。
2. **E1 local prestaged runner**：独立 worker、deployment registry、digest validation；只允许
   core/utils。
3. **E2 durable command adapter**：journal、dedupe、restart recovery、signed result；仍不开放
   网络提交。
4. **E3 MMP feature**：additive payload、feature negotiation、authorization adapter；先
   shadow，再单节点 canary。
5. **E4 controlled artifacts**：prestaged mounts、bounded output、M3 immutable adapter。
6. **E5 Mesh service capability**：`mesh.service/v1` provider 和 NetworkGrant evaluator。
7. **E6 production hardening**：低权限 OS worker sandbox、job/cgroup limits、audit required、
   revocation 和 staged rollout。

当前实现进度：

- E0：typed Grant/Request、授权求交、状态机和有界 journal simulator 已实现。
- E1：deployment registry、digest binding、TurboRuntime raw Wasm runner 和真实 guest test
  已实现；runner 仍是进程内 core，尚未达到独立低权限 worker 边界。
- E2：单写者 durable journal store、V1 reader/V2 writer、SHA-256 完整性、原子替换、去重、
  restart recovery、canonical request digest、signed rich result、terminal/result 原子提交和
  同步本地 orchestrator 已实现。orchestrator 强制注入 Grant verifier，但真实 Grant
  authority/codec 留在 E3；所有调用仍必须离开 Mesh/MMP event loop。
- E3-E6：未实现。

E3 之前不能从网络触发执行；E6 之前不能宣称多租户生产隔离。

## 20. 验证门槛

### Identity、policy 与 journal

- 错误 mesh、target、issuer、epoch、generation 或 digest 全部拒绝。
- 四层权限和限额正确求交；未知 capability fail closed。
- 每个 crash point 都有确定恢复结果。
- 相同 command ID 不重复执行，不同 payload 返回 conflict。

### Runtime 与隔离

- module、memory、steps、deadline、host calls、copied bytes 和输出达限即失败。
- WASI、raw socket、未知 import、绝对路径、链接逃逸和未授权 provider 拒绝。
- worker crash、EOF、malformed IPC、timeout 和 process-tree cleanup 覆盖。

### M3、文件与 Mesh

- digest mismatch、partial fetch、expired capability 和 output commit failure 不误报成功。
- M3 unavailable 不回退 HTTP download。
- execution workload 不阻塞 `mesh_poll()`、MMP handshake 或 forwarding。
- service provider 只使用 verified virtual address，不暴露 physical endpoint。

## 21. 产品完成条件

只有全部满足以下条件才可声明 node execution product complete：

- 网络请求不能选择代码、宿主路径、native provider、raw endpoint 或 shell 参数。
- 每次执行由 signed grant、本机 host grant 和 immutable deployment 共同授权。
- command journal 在重启和网络重试后保持最多一次执行。
- TurboRuntime/TurboWasm 配额和 capability 在真实 worker 路径强制执行。
- worker 使用明确的低权限 OS sandbox profile。
- input/output、result 和 audit 可通过 command/correlation ID 关联。
- production 无有效 policy 或 worker health degraded 时 fail closed。

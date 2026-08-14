# meshctl 原语、命令树与 Controller API 设计

## 文档状态

本文定义目标产品中的 `meshctl`。递归命令树、三个只读 Controller 查询以及 placement plan 的
Selector V1 语法/适配链路已经进入 Phase 1；其余 Controller mutation、watch 和 transfer 不描述为
已经可用。实现成熟度仍以
[`MESH_STATUS.md`](MESH_STATUS.md) 为准；控制面状态、身份与
南向协议以 [`MESH_PRODUCT_CONTROL_PLANE.md`](MESH_PRODUCT_CONTROL_PLANE.md) 为准；节点本地
执行边界以 [`MESH_LOCAL_IPC_DESIGN.md`](MESH_LOCAL_IPC_DESIGN.md) 为准。

证据类型约定：

- `事实`：来自当前仓库、TurboParser/TurboHTTP 公开头文件、实现或测试。
- `推论`：依据当前结构得出的影响判断，仍需实现验证。
- `目标`：本文选择的产品契约，不代表代码已经完成。
- `常用做法`：仅用于解释取舍，不替代仓库证据。

本文同时记录目标设计和已实现切片；已实现范围在下节单独列出。

## 实现状态（2026-08-13）

`事实`：Phase 1 已实现：

- TurboParser 已增加 additive recursive command node、结构化 `parse_ex` 和 sink-based help；旧解析 API
  保持兼容，并有递归、错误、help 与 freeze 测试。
- `meshctl nodes list`、`meshctl nodes get`、`meshctl operations get` 使用 owned bounded command，
  复用一个单调时钟 deadline，并通过显式 HTTP/2 + mTLS 发起无重试、无 redirect 的只读查询。
- client 只接受 HTTPS origin、现存 credential regular file、受限 identifier 和类型化 `/v1/meshes/...`
  route；响应体上限 1 MiB、header 上限 32 KiB，JSON 校验通过后才输出。
- Iris northbound adapter 注册对应三个 GET route，从已验证的 mTLS peer 提取 CoroNet
  `sha256:<64-lower-hex>` 身份，先调用授权接口，再调用只读 query source；page 和 response 均有硬上限。
- TurboParser `Selector` 使用 re2c lexer + Lemon parser 实现 V1 allowlist DSL，生成 owned immutable
  program 和 deterministic canonical form；支持三值缺失语义、同步无分配求值和结构化位置诊断。
- `meshctl placements plan release:<id> --selector <expr>` 在本地校验/规范化后，以严格 versioned JSON
  通过 H2+mTLS POST 到 `/v1/meshes/{mesh}/placements:plan`。Iris adapter 在 mTLS/RBAC 后权威重解析，
  计算 canonical selector SHA-256，再把 digest、canonical selector 与仅在回调期间有效的 immutable
  program 交给有单调时钟 deadline 的 inventory planner。
- 新命令在独立 `meshctl_product` 模块中，legacy `genkey/init/doctor/up/rpc/cluster` 分派未改语义。

`事实`：Phase 1 尚未提供可部署 Product Controller 或权威 inventory/journal source；Iris adapter 只定义
授权、查询和只读 planner 回调边界。因此 placement plan 目前是可集成接口，尚不能独立产生真实 inventory
结果。mutation/apply、request-ID 去重、UNKNOWN_COMMIT、SSE watch、显式取消、context/OS key store 和
数据 transfer 均未实现。当前同步 TurboHTTP 请求有单次 bounded timeout，但还没有 Ctrl-C 到 request
cancellation token 的闭环。

## 决策摘要

`目标`：`meshctl` 是 TurboP2P capability platform 的类型化操作入口，不是事实源、任务执行器、
消息代理或远程 shell。命令经过以下固定路径：

```text
argv
  -> TurboParser turbo_cmd 命令树
  -> 类型化 meshctl command
  -> 领域校验 / plan
  -> Controller client
  -> mTLS HTTP/2 resource API
  -> immutable query/plan response，或 mutation 的 durable operation ID
  -> render，或 operation status/SSE watch
```

核心决策如下：

1. 普通 CLI 采用 `资源 + 动词`，例如 `meshctl releases publish`；不用 DSL 代替 flags、位置参数和
   自动帮助。
2. `turbo_cmd` 负责命令树、类型、choices、validator、环境变量和帮助；为了支持生产级多层命令，
   以兼容方式给 TurboParser 增加递归 command node、非退出式 parse result 和 leaf dispatch。
3. re2c/Lemon 只用于 selector、placement policy 等真正需要组合表达式的领域语言。V1 Selector 已选择
   独立 immutable predicate program，因为 QueryVM 尚不能同时满足集合、三值缺失语义、field allowlist、
   canonical AST 和结构化位置诊断；它不是通用脚本语言。
4. H1/H2/WS/SSE 是传输原语，不是作业原语。CLI 的业务原语是 QUERY、PLAN、MUTATE、WATCH、
   CANCEL 和 TRANSFER；节点南向原语仍是 INTENT、OBSERVATION、OPERATION、EVENT 和 RECEIPT。
5. 生产 `meshctl` 默认使用显式 HTTP/2 + mTLS，不静默降级。V1 `watch` 采用 HTTP/2 SSE，复用
   TurboHTTP facade 的有界 streaming API；RFC 8441 WebSocket 留给 Controller 与 agent 的双向会话。
6. CLI 不直连节点，也不加入 FlowMQ。Controller 是全局 desired state 和 operation/audit 的事实源；
   FlowMQ 只位于 agent 与 `meshd`/worker 的本地执行边界。
7. 不提供 `meshctl exec`、`run-native <path>`、任意 HTTP path、任意 FlowMQ topic 或 shell/argv
   透传。Builtin/Native/WASM 都必须落到已注册 provider 的类型化资源命令；V1 的第三方 WASM 不可用。
8. 文件删除不是立即广播 `unlink`。对象名、release、placement 和物理 chunk 分别有 tombstone、
   revoke/withdraw、evict 和引用可达性 GC 语义。
9. 安全决策采用“逐层求交”而不是“通过 mTLS 即可信”：传输身份、产品 RBAC、资源 scope、已批准
   plan、节点本地 policy 和精确 provider/artifact 必须同时允许。
10. `--timeout` 表示整条本地命令的端到端预算。所有排队、连接、重试、响应和等待阶段共享一个基于
    单调时钟的 absolute deadline；任何重试都不得重新获得完整 timeout。

## 当前事实与缺口

### 当前 meshctl

`事实`：[`examples/meshctl.c`](examples/meshctl.c) 当前同时承担：

- `genkey`、`init`、`doctor`、`up` 等单机开发入口；
- 直接节点 RPC；
- 交互式本地 status、health、DHT、peer、route、policy、admission、dump 和 ping；
- 实验性的 `cluster status/list`。

顶层与交互式命令主要由 `strcmp` 分派。`cluster` 已经通过 `<turbo_parser.h>` 使用
`turbo_cmd_create()`、`turbo_cmd_add_subcommand()` 和 `turbo_cmd_parse_subcommand()`，然后手工分割
逗号分隔的节点列表并手工执行 handler。对应解析测试位于
[`tests/test_meshctl_rpc.c`](tests/test_meshctl_rpc.c)。

`推论（MED）`：继续在单个 `meshctl.c` 中增加 product Controller、文件、CDN、网络和 function 命令，
会让解析、鉴权、传输、领域状态和输出格式混成同一职责，且难以稳定 machine-readable output 和
错误码。现有命令必须保留，但新产品命令应进入独立的命令树与 handler 模块。

### turbo_cmd 能力

`事实`：TurboParser 的 `turbo_parser.h` 已公开 flag、string、integer、float、string list、enum、
required argument、environment、group、choices、validator 和一层 subcommand。其实现以 opaque parser
持有 descriptor，解析后的 string 指向输入或环境值；parser 不替调用方拥有这些业务字符串。

`事实`：TurboParser 现已增加递归 command node、结构化非退出式 `turbo_cmd_parse_ex()` 和
sink-based `turbo_cmd_render_help()`；命令树首次解析后冻结。旧 `turbo_cmd_parse*()` 仍保留既有打印/
退出兼容行为，因此嵌入式调用方必须使用新 API，不能把旧 API 当作结构化错误接口。

`推论（MED）`：parser 基础边界已补齐，但目前只有三个只读 leaf 接入 typed command；继续扩展时仍应
按领域模块注册 handler，不能重新退回 argv pre-scan 或大量 `strcmp`。

### HTTP 与控制面

`事实`：TurboHTTP facade `TurboHttp::TurboHttp` 已支持显式 H2、TLS client credential、完整响应、
streaming response、请求取消、响应大小上限和 caller-owned `http_response_t`；显式 H2 连接 H1-only
peer 会 fail fast。stream callback 的 data 只在 callback 期间有效。

`事实`：Iris 同一 WebSocket route 支持 H1 RFC 6455 与 H2 RFC 8441；底层 HTTP/2 client 支持
extended CONNECT，但 TurboHTTP facade 当前没有 facade 级 WebSocket client API。Iris 同时支持 SSE。

`事实`：当前 Mesh control core 已有 node/network/function/service/route/release、operation journal、
request ID、epoch/precondition、generation-consistent status page、event cursor 和 durable receipt。
另有 Phase 1 `meshctl` H2+mTLS read-only client 与 Iris northbound adapter，但尚无把它们接到全局权威
状态、持久化 journal 和部署生命周期的 Product Controller runtime。

## 目标与非目标

### 目标

- 一套可发现、可组合、可自动化的 `资源 + 动词` 命令树。
- 一个 CLI command 精确映射一个领域 query、plan、mutation、watch、cancel 或 transfer。
- 人类表格输出和稳定 JSON/JSON Lines 输出分离。
- 所有 mutation 有 request ID、base epoch、actor、reason 和 operation ID。
- 大范围内容发布先 plan，再以选择快照摘要提交，避免 selector 目标漂移。
- 所有输入、响应、分页、stream decoder 和队列有硬上限。
- 保留现有 developer `meshctl` 命令，并允许按阶段迁移。

### 非目标

- 不把 `meshctl` 做成通用 REST client、FlowMQ console、SSH 替代品或 workflow engine。
- 不让 CLI 自己决定全网 desired state，也不在 CLI 本地维护 operation 真相。
- 不把文件/chunk/media bytes 塞进 Controller control request 或 FlowMQ command。
- 不让节点自行重新解释 operator selector。
- 不把 fan-out 称为 wire-level exactly-once，也不把 `202 Accepted` 称为节点执行成功。
- 不在 V1 开放第三方 WASM，亦不允许任意 Native 二进制、路径或 argv。

## 三类原语

### CLI 原语

| 原语 | 是否改变事实源 | 返回 | 示例 |
|------|----------------|------|------|
| `QUERY` | 否 | generation-consistent page/detail | `nodes list`、`operations get` |
| `PLAN` | 否 | plan digest、base epoch、目标快照、风险和估算 | `placements plan` |
| `MUTATE` | 是 | durable Controller receipt + operation ID | `routes apply` |
| `WATCH` | 否 | 从 cursor 开始的有序 event stream | `operations watch` |
| `CANCEL` | 是 | cancel operation ID；不保证被取消动作尚未完成 | `operations cancel` |
| `TRANSFER` | 元数据与数据分层改变 | object/release CID + operation | `objects put`、`releases publish` |

`TRANSFER` 仍不是任意远程执行：CLI 先向 Controller/M3 gateway 获取受限 capability 或上传会话，
bytes 通过 M3/Mesh 数据路径流动，Controller 只提交 CID、manifest 和 placement intent。

### Controller 资源原语

Controller 暴露 versioned resource API，负责认证、RBAC、epoch、幂等、selector 展开、operation journal
和 audit。外部 JSON 只是适配格式；进入领域核心前必须转换为类型化 command。

### Agent/节点原语

Controller 将 product resource 编译为已有南向原语：

| CLI/Product resource | Controller 事实源 | 南向 resource/行为 |
|----------------------|-------------------|--------------------|
| devices | identity/device registry | node enrollment/revocation，而非普通 function |
| nodes | inventory/desired role | `NODE` observation/intent |
| networks | network desired state | `NETWORK` APPLY/DELETE |
| routes | route desired state | `ROUTE` APPLY/DELETE |
| services | service desired state | `SERVICE` APPLY/DELETE |
| releases | manifest、name、retention | `RELEASE` assignment/tombstone |
| placements | selector snapshot + per-node assignment | 多个目标明确的 `RELEASE` assignment |
| functions | provider catalog + assignment | `FUNCTION` APPLY/DELETE |
| operations/audit | Controller journal | query/event/receipt；不是新节点 resource |
| objects | M3 namespace/object metadata | M3 capability/data API，不扩展 MMP 为文件传输 |

`目标`：不要为了每个产品聚合视图立即扩展 `mesh_control_resource_kind_v1_t`。只有节点必须持久化和
reconcile 的新 desired state，才增加南向 kind 并通过版本/capability 协商发布。

## 命令树

统一语法：

```text
meshctl [global-options] <resource> <verb> [arguments] [options]
```

全局 options：

```text
--context <name>
--endpoint <https-url>
--mesh <id-or-name>
--output <table|json|yaml|jsonl>
--transport <h2|h1|auto>
--timeout <duration>
--request-id <uuid>
--page-size <n>
--base-epoch <n>
--reason <reason-code>
--wait
--yes
--no-color
```

约束：

- production context 默认 `transport=h2`，对应 TurboHTTP `TURBO_HTTP_TRANSPORT_H2`，不允许 fallback。
- `auto` 是操作者显式选择的兼容模式；不得由 TLS/H2 失败自动切换明文或跳过证书验证。
- private key、password、bearer token 不接受命令行值。context 只保存 OS credential/key store 引用。
- `--request-id` 供 CI 恢复未知提交；未提供时由 secure UUID 生成。
- `--wait` 等待 operation terminal；默认 mutation 在 Controller durable accept 后返回 operation ID。
- `--yes` 只跳过本地确认，不能跳过 server-side plan、RBAC、epoch 或审批。

### V1 command surface

| Resource | Verbs | 关键语义 |
|----------|-------|----------|
| `contexts` | `list/get/use/set/delete` | 本地 endpoint/tenant/certificate reference；删除不删除证书 |
| `devices` | `list/get/approve/revoke/retag` | 身份生命周期；revoke 要求 reason 和 step-up policy |
| `nodes` | `list/get/status/watch/cordon/drain` | runtime inventory；drain 是 operation，不是 kill |
| `networks` | `list/get/plan/apply/delete` | logical Network snapshot 与 drain/tombstone |
| `routes` | `list/get/plan/apply/delete` | advertised/approved/active 分离 |
| `services` | `list/get/plan/apply/delete` | 类型化 service desired state |
| `objects` | `put/get/stat/list/delete` | M3 数据 API；delete 先提交 namespace tombstone |
| `releases` | `publish/list/get/status/withdraw/revoke/purge` | manifest/CID、分发和 retention 分离 |
| `placements` | `plan/apply/list/get/status/cancel/evict` | selector 展开后成为明确 per-node assignment |
| `functions` | `catalog/plan/apply/status/stop/delete` | 仅 catalog 中的 builtin/Native；WASM V1 unavailable |
| `operations` | `list/get/watch/cancel` | 所有异步 mutation 的统一观察入口 |
| `audit` | `list/watch/export` | append-only 审计视图；export 本身是 operation |
| `diagnostics` | `run/get/cancel` | allowlisted profile；不接受 shell/argv |

命名规则：resource 使用复数，verb 使用稳定动词。旧 `meshctl up`、`rpc`、`cluster` 等保留原入口，
不强行改名；新 product commands 不复用旧命令的不同语义。

一个 Mesh 下的 Network、address pool、membership 和 external subnet route 必须分开表达。
`networks members ...` 和 `networks pools ...` 是 Network 子资源命令；`routes ...` 表达
subnet-router、exit 或显式 inter-network gateway。Network membership 不自动产生跨网路由。
完整状态、权限、重叠 CIDR 和共享 underlay 设计见
[`MESH_MULTI_NETWORK_DESIGN.md`](MESH_MULTI_NETWORK_DESIGN.md)。

### 内容放置示例

```text
meshctl placements plan release:web-v42 \
  --selector 'region == "eu-west" && role in ["edge", "cache"] && capability("m3-cache")'

meshctl placements apply release:web-v42 \
  --selector-file selector.expr \
  --selection-digest sha256:... \
  --base-epoch 71 \
  --reason cdn-rollout

meshctl operations watch op_01... --from-cursor 8821
```

第一条命令返回 selector digest、inventory generation、选中节点数、预计 bytes 和风险；第二条只在
generation/base epoch 和 selection digest 仍一致时提交。Controller 逐节点生成明确 assignment，节点
只看到自己的 target、manifest CID、quota 和 operation ID。

这在数据处理形态上是 map-like fan-out + reduce-like aggregation，但控制协议不是 MapReduce：assignment
是 desired state，节点独立 reconcile；聚合状态由 Controller 从 observations/receipts 派生；Pub/Sub
仅传播可重建事件，不能替代命令、receipt 或 operation journal。

## turbo_cmd 扩展设计

### 为什么扩展而不是另写 parser

| 方案 | 优点 | 风险 | 结论 |
|------|------|------|------|
| 继续 `strcmp` + 手工 argv | 改动小 | 重复校验、帮助漂移、多层命令难测 | 仅保留 legacy |
| meshctl 自建递归 CLI parser | 可完全定制 | 与 TurboParser 重复，形成第二个 CLI framework | 不采用 |
| 扩展 `turbo_cmd` 命令树 | 统一类型、帮助、validator 和测试 | 需要 additive TurboParser API | 采用 |
| 用 re2c/Lemon 解析所有命令 | grammar 强 | shell quoting/completion/help 重复，普通 flags 过度设计 | 不采用 |

### Additive TurboParser API（已实现基础）

以下基础 API 已实现；后续仍需随新增 option 类型补齐 node 对称能力：

```c
typedef struct turbo_cmd_node_s turbo_cmd_node_t;
typedef int (*turbo_cmd_write_fn)(const char *data, size_t size,
                                  void *write_context);

typedef enum {
  TURBO_CMD_PARSE_OK = 0,
  TURBO_CMD_PARSE_HELP,
  TURBO_CMD_PARSE_VERSION,
  TURBO_CMD_PARSE_INVALID
} turbo_cmd_parse_status_t;

typedef struct {
  size_t size;
  turbo_cmd_parse_status_t status;
  const turbo_cmd_node_t *leaf;
  int argument_index;
  const char *error_code;
  const char *message;
} turbo_cmd_parse_result_t;

turbo_cmd_node_t *turbo_cmd_root(turbo_cmd_parser_t *parser);
turbo_cmd_node_t *turbo_cmd_add_command(turbo_cmd_node_t *parent,
                                        const char *name,
                                        const char *description);
int turbo_cmd_parse_ex(turbo_cmd_parser_t *parser,
                       int argc, char **argv,
                       turbo_cmd_parse_result_t *result);
int turbo_cmd_render_help(const turbo_cmd_parser_t *parser,
                          const turbo_cmd_node_t *node,
                          turbo_cmd_write_fn write_fn,
                          void *write_context);
```

具体约束：

- command node 可递归，leaf 才能绑定 meshctl handler ID；parser 不知道 Controller、HTTP 或 Mesh 类型。
- `parse_ex` 不打印、不 `exit()`；error code、argument index 和 message 由调用方渲染。
- 现有 `turbo_cmd_parse*()` 和 `turbo_cmd_show_help()` 保留兼容行为，可内部调用新 API 后打印/退出。
- command tree 在 parse 前构建，随后冻结；不得在并发 parse 中修改。
- leaf dispatch 只调用本地 CLI handler。它不赋予节点 Native/WASM 执行权限。
- subcommand option 能力与 root 对称：enum、list、required、group、choices、validator 和 env 都可用。
- parser、node、descriptor 仍为 opaque C ABI；新增 struct 使用 size prefix，不能向调用方暴露内部数组。
- 所有 realloc/duplicate 失败必须返回明确错误，不保留半注册 node。
- parser 配置必须有 command nodes、每 node options、argv bytes 和 nesting depth 的硬上限。

### meshctl 内部 command model

`meshctl` 不把 leaf handler 做成 `void *` 参数包。以下是内部结构草图，不是可复制的公共 API；每个
leaf builder 输出一个有界的 tagged union：

```c
typedef enum {
  MESHCTL_COMMAND_NODES_LIST,
  MESHCTL_COMMAND_RELEASES_PUBLISH,
  MESHCTL_COMMAND_PLACEMENTS_APPLY,
  MESHCTL_COMMAND_OPERATIONS_WATCH
} meshctl_command_kind_t;

typedef struct {
  meshctl_command_kind_t kind;
  meshctl_common_options_t common;
  union {
    meshctl_nodes_list_args_t nodes_list;
    meshctl_release_publish_args_t release_publish;
    meshctl_placement_apply_args_t placement_apply;
    meshctl_operation_watch_args_t operation_watch;
  } args;
} meshctl_command_t;
```

完整枚举由各领域 module 注册，示例只说明结构。parser output/argv 是 borrowed view；leaf builder 必须在
parser 销毁或异步请求前，把需要保留的值复制进有总 bytes 上限的 invocation arena。handler 接收 const
command，只能调用对应 client role interface：query、mutation、watch、transfer 或 render。

建议模块边界：

```text
meshctl_main.c                 process lifecycle / signal / exit code
meshctl_command_tree.c         turbo_cmd registration and parse adapter
meshctl_command.h              typed internal invocation
meshctl_*_commands.c           per-domain build + validate + execute
meshctl_controller_client.h    opaque query/mutate/watch interface
meshctl_turbo_http.c           private TurboHTTP adapter
meshctl_m3_transfer.c          bounded object byte streaming
meshctl_selector.c             syntax adapter only
meshctl_render.c               table/json/yaml/jsonl
```

`meshctl` target 应直接 PRIVATE link `TurboParser::Parser` 和 `TurboHttp::TurboHttp`；领域 header 不暴露
TurboParser、TurboHTTP、Iris、CoroNet 或 FlowMQ 类型。

## Selector DSL

DSL 仅表达“选择哪些 Controller inventory resources”，不表达“在节点上执行什么代码”。建议 V1 grammar：

```text
selector    := or_expr
or_expr     := and_expr ("||" and_expr)*
and_expr    := unary_expr ("&&" unary_expr)*
unary_expr  := "!" unary_expr | "(" selector ")" | predicate
predicate   := field ("==" | "!=") string
             | field ("in" | "not in") string_list
             | "has" "(" field ")"
             | "capability" "(" string ")"
field       := allowlisted_identifier | "tag." allowlisted_identifier
```

不包含循环、赋值、I/O、任意函数、时间读取、网络读取、宿主路径或正则表达式。source 以 UTF-8 处理；
identifier、operator 和 field 集合 versioned。

实现选择：

1. `事实`：QueryVM 目前不能同时表达 `in/not in`、三值缺失语义、field allowlist、canonical AST 与
   结构化位置诊断；Selector V1 因此不复用 QueryVM bytecode。
2. `事实`：lexer 由 re2c 生成，parser 由 Lemon 生成，编译结果是精确拥有 nodes/strings/list values 的
   immutable predicate program；同步 evaluate 不分配、不做 I/O、不推进 inventory 状态。
3. re2c/Lemon 是 build-time generator；运行时不调用生成器，也不接受用户 grammar。

V1 profile：source 最大 4 KiB、token 最大 512、嵌套深度最大 16、集合元素最大 128、单字符串最大
256 bytes。Controller 必须重新解析、校验并在一个 immutable inventory generation 上求值；CLI 本地
解析只为快速反馈，不能成为授权依据。计划结果绑定：

`计算`：128 项列表至少包含 `field + in + [ + 128 strings + 127 commas + ] = 259` 个词法 token；
因此 256 token 会令合法列表上限不可达。512 是保留 128 项集合语义的简单硬上限。

```text
selector_digest
+ selector_language_version
+ inventory_generation
+ ordered_target_id_digest
+ base_epoch
= selection_digest
```

apply 时任何一项变化均返回 precondition failure，操作者重新 plan；不静默扩大或缩小目标集合。

复杂度：parse 为 O(source bytes)，求值为 O(node count × predicate count)。Controller 必须同时限制
node count、predicate count 和评估 deadline；不得让 selector 在 agent 或 packet hot path 执行。

## Controller HTTP API 映射

### Resource routes

典型映射如下：

```text
GET    /v1/meshes/{mesh}/nodes?cursor=...&limit=...
GET    /v1/meshes/{mesh}/nodes/{node}
POST   /v1/meshes/{mesh}/placements:plan
POST   /v1/meshes/{mesh}/placements
GET    /v1/meshes/{mesh}/placements/{placement}
POST   /v1/meshes/{mesh}/placements/{placement}:cancel
DELETE /v1/meshes/{mesh}/objects/{namespace}/{key}?version=...
GET    /v1/meshes/{mesh}/operations/{operation}
POST   /v1/meshes/{mesh}/operations/{operation}:cancel
GET    /v1/meshes/{mesh}/events?cursor=...
```

外部媒体类型使用明确版本，例如
`application/vnd.turbop2p.control+json;version=1`。URL/JSON 只在 Iris/Controller adapter 中解析；
领域 core 使用类型化 command 和 immutable result。

mutation body 至少包含：

```json
{
  "request_id": "018f...",
  "base_epoch": 71,
  "reason": "cdn-rollout",
  "resource": {},
  "plan": {
    "selection_digest": "sha256:..."
  }
}
```

`202 Accepted` 只表示 Controller 已 durable 接收并创建 operation。节点接受、下载、应用、失败或部分
完成必须查询 operation/status/event；不能从 HTTP 连接成功推导。相同 request ID + 相同 canonical
mutation 返回同一 operation；相同 request ID + 不同 digest 返回 conflict 并写 security audit。

### H2、H1、SSE 与 WebSocket

| 通道 | 用途 | V1 meshctl |
|------|------|------------|
| H2 request/response | query、plan、mutation、cancel、page | production 默认 |
| H2 SSE | operation/event/audit watch | 采用 |
| H1 request/SSE | 显式兼容或开发 | 可选，不自动降级 |
| RFC 8441 WebSocket | Controller 与 agent 双向 session | CLI 不使用 |
| FlowMQ | agent 与本机 `meshd`/worker | CLI 禁止直连 |

V1 选择 SSE 是因为 CLI watch 只需要 server-to-client ordered events，TurboHTTP facade 已有跨 H1/H2
streaming response，而 facade 尚无 WebSocket client。若未来 CLI 需要真正双向 interactive stream，
应先给 TurboHTTP facade 增加 typed WebSocket API；不得让 `meshctl` 直接依赖底层 `http2_client_ex2()`、
WebSocket frame parser 或 Iris server internals。

### Watch 与分页

SSE event 必须携带 `id`（Controller cursor）、`event`（versioned kind）和有界 JSON data。CLI 使用
`Last-Event-ID` 或 query cursor 恢复。V1 不建立后台 event queue：TurboHTTP callback 将 borrowed chunk
送入同一 owner 上的有界 incremental SSE decoder，组成完整 event 后立即渲染；慢 stdout 通过 H2 flow
control 自然施加背压。

默认/硬上限目标：

| Resource | 默认 | 硬上限 | 超限行为 |
|----------|------|--------|----------|
| control request body | 64 KiB | 64 KiB | 拒绝；大 manifest 先存 M3，以 CID 引用 |
| buffered response | 256 KiB | 1 MiB | `RESPONSE_TOO_LARGE`，改用分页/stream |
| page items | 100 | 1000 | 参数错误 |
| selector source | 4 KiB | 4 KiB | 本地与 Controller 同时拒绝 |
| SSE event | 64 KiB | 64 KiB | 取消 stream，报告 protocol error |
| SSE decoder retained bytes | 64 KiB | 64 KiB | 取消 stream，不增长 |
| invocation arena | 64 KiB | 64 KiB | parse/build 失败 |

这些是 product profile，必须由 validated config/constants 表达，不能依赖 TurboHTTP 默认 100 MiB response
cap。若 CLI 引入异步 renderer，必须另外限定 entries 和 bytes；V1 没有证据需要该队列。

断线不自动无限重试。无 body mutation 在 transport failure 后进入 `UNKNOWN_COMMIT`：CLI 先按 request ID
查询，再决定返回；禁止生成新 request ID 盲重试。watch 可在操作者显式设置 bounded reconnect policy
后从最后完整 cursor 恢复。

## Operation 状态与取消

节点已有状态固定为：

```text
SUBMITTED -> ACCEPTED -> RUNNING -> SUCCEEDED
                |           |  \-> FAILED
                |           \----> EXPIRED / INTERRUPTED
                \----------------> REJECTED
```

实际转换必须服从 `mesh_control_operation_transition_allowed_v1()`，上图只表达主路径。Controller 的
multi-node operation 保存目标总数和 accepted/running/succeeded/failed/interrupted counts；“partial”是
聚合结果，不伪装成当前节点状态枚举。

`operations cancel` 自身是一个有 request ID 的 mutation。若原 operation 尚可中断，agent/provider 最终
把它收敛为 `INTERRUPTED`；若已 terminal，cancel 返回 already-terminal。关闭本地 CLI、Ctrl-C 或断开
watch 只取消本地 wait/stream，不取消远程 operation。

## 文件与内容删除

删除按事实层分开：

| 操作 | 立即效果 | 后台收敛 | 不能承诺 |
|------|----------|----------|----------|
| `objects delete key --version v` | namespace 写 tombstone，新读不可见 | 等待 snapshot/release/pin 引用释放后 GC | 所有 chunk 立即物理消失 |
| `releases withdraw id` | 停止按名发现和新的 placement | 撤销未开始 assignment | 已授权读立即失效 |
| `releases revoke id` | capability/policy epoch 拒绝新的授权 | 在线节点同步 deny/revocation | 离线副本立即擦除 |
| `placements cancel id` | 不再创建新下载工作 | 已运行 worker 在安全点中断并报告 | 已完成 cache 自动删除 |
| `placements evict id` | 目标节点 desired presence=ABSENT | 节点删除 cache 引用并提交 receipt | 仍被其他 release/snapshot 引用的 chunk 被删 |
| `releases purge id` | 创建受审计 GC operation | mark roots、grace、pin/read check、sweep、replica receipt | 未完成 receipt 前的 hard-delete 证明 |

内容寻址数据的 CID/hash 证明 bytes 身份，不证明它仍被哪个文件名或 release 引用。GC root 至少包含当前
namespace、release、snapshot、clone、pin、active transfer 和 pending transaction。任一引用图读取失败
都 fail closed；不能猜测不可达。`purge` 输出每个 store/node 的 receipt 和未完成列表，只有所有要求的
副本都确认后才能报告策略定义的 physical purge complete。

## Function 与节点执行边界

允许：

```text
meshctl functions catalog
meshctl functions plan approved-transcoder --selector ... --config-cid ...
meshctl functions apply approved-transcoder --artifact-cid ... --config-cid ...
meshctl diagnostics run node-7 --profile network-basic
```

拒绝：

```text
meshctl exec node-7 -- sh -c ...
meshctl functions run --path C:\tool.exe --args ...
meshctl rpc POST /arbitrary/path
meshctl flowmq publish arbitrary-topic ...
```

Native assignment 只包含 exact provider ID、artifact/config digest、typed input、resource limits、network
policy digest 和 generation；worker 必须是预部署、低权限、进程外且本机显式启用。WASM schema/permission
可以保留，但 V1 catalog 不返回 available WASM provider。CLI 不根据 runtime 类型绕过统一 plan、RBAC、
operation 或 audit。

## 状态归属、所有权与线程模型

| 状态 | 唯一事实源 | CLI 持有方式 |
|------|------------|--------------|
| desired resource/epoch | Controller durable store | response snapshot only |
| operation/request dedupe | Controller operation journal | operation ID/cursor only |
| node durable accept/result | agent WAL/checkpoint | Controller observation/receipt view |
| actual network/function state | `meshd`/provider owner | derived observation |
| object name/release/snapshot roots | M3 metadata service | page/detail view |
| chunk bytes | M3 CAS stores | streamed bytes/CID only |
| context preference | local meshctl config | explicit local state，不含 key material |

单次 CLI 调用使用一个 owner coroutine/context。`turbo_http_create_sync()` 创建的 facade 自己拥有 CoroNet
context，`turbo_http_destroy()` 释放；普通 create 的 context 由调用方持有。所有 response 由调用方调用
`http_response_free()`；stream callback data 和 parser string 是 borrowed，跨 callback/parse 生命周期前
必须复制。

## 错误与输出契约

### Stable error categories

Controller error body至少包含 `code`、`message`、`field_path`、`correlation_id`、`current_epoch` 和可选
`operation_id`。CLI 不解析日志文本决定行为。

| Exit | 类别 | 示例 |
|------|------|------|
| 0 | success / durable accepted | query 成功；mutation 返回 operation ID |
| 2 | usage/validation | flag、selector、document 非法 |
| 3 | authentication/authorization | certificate、RBAC、step-up 失败 |
| 4 | not found | resource/operation 不存在 |
| 5 | conflict/precondition | request collision、base epoch/plan stale |
| 6 | partial aggregate | `--wait` 后仅部分目标成功 |
| 7 | unavailable/timeout/unknown commit | 网络、Controller quorum 或提交状态未知 |
| 8 | resource exhausted | client/server hard cap 或 queue full |
| 9 | internal/protocol | 无法安全解释的响应 |

这些 exit code 只适用于新 product command tree；legacy 命令保持现有返回行为，直到单独发布兼容迁移。

### Output

- stdout 只写请求结果；stderr 写诊断、progress 和确认提示。
- `--output json` 输出一个 versioned JSON document；`watch --output jsonl` 每行一个完整 event。
- table/yaml 面向人类，不是稳定 machine contract。
- error JSON 在显式 machine output 下写 stderr，schema 稳定。
- secret、private key、bearer token、raw capability 和完整证书不得输出或记录。
- mutation 默认至少输出 request ID、operation ID、accepted epoch 和查询命令。

## 安全威胁模型与控制协议

### 信任边界与攻击面

`事实`：当前 Mesh agent 已校验 Controller 客户端证书 SHA-256、Controller node ID、证书 serial、
`issued_at_ms`/`expires_at_ms` 和 permission；最终 function 权限是 Controller permission、本地 policy、
runtime 可用性和 exact provider 的交集。Phase 1 `meshctl` 已强制 H2、mTLS、peer/hostname verification、
origin/credential file 校验和响应上限，但产品 RBAC、scope、证书轮换/撤销与 OS key store 仍属于
Controller/runtime 后续闭环。

`目标`：设计至少防御以下边界，而不是只防止链路窃听：

| 边界 | 主要威胁 | 必须保留的控制 |
|------|----------|----------------|
| 本机用户 -> `meshctl` | argv/env 泄密、context 篡改、符号链接替换、恶意输出路径 | 凭据句柄化、权限校验、安全打开、输出脱敏 |
| `meshctl` -> Controller | MITM、DNS 污染、协议降级、跨源 redirect、响应放大、重放 | mTLS、origin 绑定、显式 H2、请求摘要、硬上限 |
| operator -> resource | selector 扩权、跨 tenant/mesh、批量误操作、旧 plan 重放 | RBAC + scope、plan digest、base epoch、step-up/审批 |
| Controller -> agent | 被盗 Controller 凭据、过期 intent、重复投递 | 签名信封、短 TTL、request/message dedupe、本地 policy |
| agent -> provider | 任意 native path/argv、权限逃逸、资源耗尽 | catalog allowlist、exact digest、进程隔离、配额、deadline |
| node -> mesh | 冒充其他节点、伪造 receipt/observation、污染其他 tenant | 节点身份、tenant/mesh 绑定、签名 receipt、服务端校验 |
| watch/transfer | 慢消费者、连接囤积、事件/内容膨胀 | 并发配额、stream lease、心跳、flow control、bytes cap |

节点或 Controller 的单点身份被攻破后不能承诺“系统仍然可信”；设计目标是限制 blast radius，保留
可撤销、可审计和重新收敛的路径。Controller 不得仅凭自己通过 TLS 就绕过节点本地 policy；节点也不得
自行扩大 Controller 已批准的目标集合。

### 有效授权与危险操作

每项节点执行的有效权限必须满足：

```text
effective authority =
    authenticated principal
  ∩ product RBAC grant
  ∩ tenant / mesh / resource / action scope
  ∩ approved plan and selection digest
  ∩ node-local policy
  ∩ runtime availability
  ∩ exact provider / artifact / config digest
```

任一项缺失、未知或版本不匹配都 fail closed。TLS 身份只回答“连接对端是谁”，不代替资源授权。
Controller 必须从已验证的 mTLS/OIDC session 建立 actor，忽略 body 中试图自报的 actor、role 或 tenant；
若兼容字段存在且与 session 不同，返回 `AUTH_CONTEXT_MISMATCH` 并写 security audit。

`--yes` 只关闭本地交互提示，不能跳过 Controller 的 RBAC、step-up、审批、plan 或 epoch 检查。以下操作
必须携带 reason、base epoch 和服务端生成的 plan digest，并允许部署策略要求二次认证或双人审批：

- trust root、Controller/agent certificate 和 principal grant 变更；
- 跨大量节点的 route/network/function rollout；
- release revoke、placement evict 和 physical purge；
- 降低 replica/durability、扩大 native network/filesystem permission。

### 连接、凭据与配置

- endpoint 必须是 context allowlist 中的规范化 HTTPS origin；禁止 URL userinfo、明文、证书校验关闭和
  自动 H2 -> H1 降级。生产 Controller API 默认禁用 redirect；若 read-only 兼容 profile 允许 redirect，
  也只能到相同 scheme/host/port，并重新执行认证与响应上限检查。
- `--endpoint` 只能选择 trust policy 已允许的 origin，不能覆盖 CA、pin、客户端身份、tenant 或 mesh scope。
  不提供生产 `--insecure` 逃生开关。
- mTLS private key 或 OIDC refresh credential 由 OS key store/受限 credential provider 持有；命令行、环境
  变量、context 文件、日志和 crash message 不保存 secret。context 只保存 credential reference，并拒绝
  owner/ACL 不符或被不安全符号链接替换的文件。
- pin rotation 保存明确的 `current`/`next` 集合、not-before/not-after 和审计记录；不能在连接失败后学习
  新 pin。证书撤销或 principal epoch 更新后，新请求立即拒绝，已有 watch 在有限时间内关闭。
- 生产 mutation 设置 `follow_redirects=0`、HTTP automatic retry=0、cookie=off。当前 TurboHTTP 显式 H2
  本就不会静默回退；meshctl profile 必须用集成测试固定这一行为。

### 请求绑定、重放与幂等

mutation 的 canonical digest 至少绑定以下字段；编码必须使用版本化 canonical serialization，不能直接
hash 未规范化 JSON 文本：

```text
media/schema version
HTTP method + normalized route
tenant + mesh
resource kind + resource ID + action
base epoch + selection/plan digest
request ID + payload digest
requested operation timeout
```

认证 session 中的 principal、certificate serial、principal epoch 和 channel binding 由 Controller 加入
audit/dedupe record，不能信任客户端 body。相同 request ID + 相同 canonical digest 返回原 operation；
相同 request ID + 不同 digest 返回 `REQUEST_ID_COLLISION`，不覆盖旧记录。dedupe retention 必须覆盖允许的
客户端重试与 unknown-commit 查询窗口，同时以时间、entries 和 bytes 三个上限约束；过期后返回明确的
`DEDUPE_EXPIRED`，不能假装“从未提交”。

节点南向信封继续绑定 mesh ID、target node ID、origin identity、certificate serial、permission、request/
message ID、issued/expires、precondition 和 payload digest。Controller 操作去重与 agent message 去重是两层
不同事实：前者证明业务 mutation 是否已创建，后者防止同一节点副作用重复执行。

### 输入、资源与审计

- Controller 只接受该 route 声明的 media type/schema version；拒绝未知关键字段、重复 JSON key、超深
  nesting、非法 UTF-8、整数溢出和尾随数据。path/query/header/body、selector cost、page、response、event
  和解压后 bytes 都有独立硬上限。
- 限流至少按 principal、tenant、action、estimated target count 和并发 operation/watch 计费。selector
  必须在 plan 阶段受 token/depth/evaluation deadline 限制；不能借一个短请求制造无界 fan-out。
- command/operation/receipt 队列满时返回 `RESOURCE_EXHAUSTED` 或 bounded admission timeout，不丢弃、不
  合并 mutation。只有可重建 telemetry 可以按文档化策略采样或合并。
- 每次 mutation 审计 actor、credential/principal epoch、tenant/mesh、request/operation、resource/action、
  before/after epoch、plan digest、reason、决策链和结果。高风险审计记录进入防篡改存储；日志不记录
  文件内容、credential、raw capability 或未脱敏配置。
- stdout 文件导出采用安全创建语义：拒绝目录逃逸和特殊设备，默认不跟随 symlink，不用响应中的名称
  直接拼接本地路径；已存在目标只有操作者显式选择原子替换时才覆盖。

## Deadline、timeout、lease 与取消

### 两种时钟与一个端到端预算

`事实（HIGH）`：当前 `mesh_control_agent_config_v1_t.now_ms` 可注入，agent 用它比较签名信封的
`issued_at_ms`/`expires_at_ms`，但公开结构没有规定这个 callback 的时钟域；同一实现的 shutdown drain
则使用 `turbo_monotonic_ms()`。若把 monotonic 值与 UTC epoch 混用，合法命令会被拒绝或过期命令可能被
接受。

`目标`：时间语义必须拆开：

- wall/UTC epoch milliseconds 只用于证书、签名信封 `issued_at`/`expires_at` 和审计时间；agent 的相应
  callback 必须改名或文档化为 UTC clock。
- monotonic clock 只用于 elapsed time、queue wait、网络 attempt、provider execution、heartbeat idle 和
  shutdown drain；任何 wall-clock 跳变都不能延长本地等待。
- Controller 接收客户端相对 `timeout_ms`，立即夹在 endpoint 最小/最大值内并转换成本机 monotonic
  deadline；不接受客户端 wall-clock absolute deadline 作为权威。
- 节点启动和定期状态报告观测 authenticated Controller time offset。偏差超过 `max_clock_skew_ms` 时
  返回 `CLOCK_SKEW` 并 fail closed，不自动修改 OS 时间。正常信封仍严格满足
  `issued_at <= utc_now < expires_at`，不能用 skew tolerance 静默延长 expiry。

一条命令的有效截止时间为：

```text
effective deadline = min(
    client end-to-end budget,
    Controller endpoint hard cap,
    credential/session expiry,
    operation-kind hard cap,
    signed intent expiry)
```

每一跳只转发“剩余预算”或由本机重新计算的更早 deadline，不能重置成原始 timeout。排队时间计入预算；
请求离开任何 queue 前都重新检查 deadline。`lease` 表示服务端资源/ownership 的有版本状态，不等同于
客户端 socket timeout；lease 的授予、续期、fencing 和过期必须通过其事实源提交。

### 分阶段 timeout profile

以下是 `目标` 默认值，不是当前实现事实；均由 validated config/constants 表达，并受硬上限约束：

| 阶段 | 默认预算 | 推荐硬上限 | 超时时的语义 |
|------|----------|------------|----------------|
| 本地 parse/config/selector 初检 | 2 s | 5 s | 未发送，安全失败 |
| DNS + TCP + TLS + ALPN | 5 s | 15 s | 未建立认证 session |
| query/page 单次请求 | 10 s | 30 s | 可用同一整体 deadline 做显式重试 |
| mutation durable admission | 15 s | 30 s | 可能为 `UNKNOWN_COMMIT` |
| server-side selector plan | 30 s | 2 min | 不创建 mutation operation |
| operation queue admission | 2 s | 5 s | 未 durable 接收则不创建 operation |
| `--wait` 本地等待 | 5 min | 24 h | operation 继续，返回 operation ID |
| SSE heartbeat / idle | 15 s / 45 s | 60 s / 180 s | 从最后完整 cursor 有界恢复 |
| 单条 watch stream lease | 60 s | 10 min | 到期重新认证、从 cursor 续接 |
| CLI cancel/shutdown drain | 5 s | 30 s | 非零退出并报告最后已知标识 |

长任务的 execution deadline 按 operation kind 配置，例如诊断、drain、内容放置分别使用不同上限；不能
让通用 `--timeout` 解除 provider 的 CPU、内存、网络、磁盘或运行时配额。`--wait` 只控制 CLI 等待多久，
不修改已经 durable 创建的远程 operation deadline。需要改变远程期限时，必须是显式、可授权和可审计的
领域字段。

### TurboHTTP/CoroNet 实现边界

`事实`：TurboHTTP facade 的 `timeout_ms` 同时参与连接/请求阶段，当前
`http_request_control_t` 只有 `cancel_token`，没有 absolute deadline 字段；facade 还可以在内部执行
redirect/retry。因此一次 transport timeout 不能自然证明整条 meshctl command 未超预算。

V1 实现规则：

1. 每条 CLI 命令在调用方拥有的 CoroNet context 上建立 monotonic absolute deadline 和
   `coro_cancel_source_t`；deadline coroutine 到期只调用 `coro_cancel_source_request()`。
2. mutation 禁用 facade redirect/retry。read-only query/watch 如需重试，由 meshctl 在 facade 外执行；
   每次 attempt 重新计算 remaining，且 attempt timeout 不得超过 remaining。
3. token 与发起 I/O 的 CoroNet context 必须相同。source、注册项和 context 的创建/销毁都在 owner lane；
   跨线程只允许 `coro_cancel_source_request()`。
4. 请求完成、deadline 到期和 Ctrl-C 竞争时，只允许一个 terminal local result。受保护 wait 返回后必须
   `coro_cancel_unregister()`；待所有 registration/dispatch 清空后再 destroy source，否则
   `coro_cancel_source_destroy()` 会返回 `TURBO_EBUSY`。
5. cancel 是 cooperative wakeup，不是释放 socket/response 的许可证。必须先让 request coroutine 退出、
   释放 caller-owned response 和 copied buffer，再关闭 client/context。不能用
   `coro_socket_interrupt_wait()` 代替完整取消，因为它只唤醒 pending receive，底层 receive 仍可能 armed。

若未来给 TurboHTTP 增加 per-request absolute deadline，应以 additive API 扩展
`http_request_control_t`，保持现有 cancel-only 调用 ABI/语义，并验证 H1、H2、streaming 和 multiplexing；
V1 不以修改该公开 API 为前置条件。

### 超时、取消与提交结果

| 超时/取消点 | 返回语义 | 客户端后续动作 |
|-------------|----------|----------------|
| 本地校验或发送前 | `TIMEOUT_NOT_SENT` / `CANCELLED_NOT_SENT` | 修正或用同一 request ID 重试 |
| mutation bytes 可能已发送，尚无 durable ACK | `UNKNOWN_COMMIT` | 先按 request ID 查询，禁止换 ID 盲重试 |
| Controller durable 创建 operation，CLI 等待超时 | `WAIT_TIMEOUT` + operation ID | operation 继续；以后 query/watch |
| Controller queue admission 超时且证明未提交 | `ADMISSION_TIMEOUT` | 同一 request ID 可重试 |
| agent 信封在接受前过期 | `EXPIRED`，无 provider 副作用 | Controller 按 operation policy 决定重派 |
| provider 执行 deadline 到期 | terminal `EXPIRED` 或 `INTERRUPTED` receipt | 不伪装为 transport failure |
| watch heartbeat idle | `WATCH_IDLE` + last complete cursor | 重新认证后有界 resume |
| 收到半个 JSON/SSE event 后断开 | protocol/incomplete，绝不输出成功 JSON | 丢弃不完整记录，保留最后完整 cursor |
| shutdown drain 超时 | 非零退出 + request/operation/cursor | 不强行 free 仍被 callback 引用的对象 |

`UNKNOWN_COMMIT` 不是通用“网络错误”文本，而是状态机结果：只有无法证明 durable mutation 已提交或未提交
时返回。若响应已包含可信 operation ID，则结果是 durable accepted；若 Controller 能证明 admission 前失败，
则是 not committed。查询自身也不可用时，CLI 保留 request ID 和 correlation ID，返回 exit 7。

本地 Ctrl-C 默认只取消正在进行的 request、watch 或 `--wait`，不改变远程 operation。远程取消必须另发
`operations cancel` mutation；该 mutation 本身也遵守相同的 request ID、deadline、unknown-commit 和审计
规则。

### Watch、背压与恢复

- 每条 SSE heartbeat 携带当前 cursor/generation，不推进业务状态。连续超过 idle deadline 未收到完整
  heartbeat/event 即关闭本地 stream；TCP keepalive 不能替代应用心跳。
- stream lease 到期、credential/principal epoch 撤销或权限变化时，Controller 主动终止 stream。每次
  reconnect 都重新认证和授权，不能沿用已过期 session。
- reconnect 次数、总时长和指数退避均有上限，且计入原命令 deadline。`Last-Event-ID` 只接受有界、规范
  cursor，并绑定同一 tenant/mesh/filter；cursor gap 返回 `CURSOR_CONFLICT`，客户端获取一致 snapshot 后
  才能继续。
- Controller 限制每 principal/tenant 的 active watches、events/s 和 retained state。慢 stdout 依靠 H2
  flow control 反压；超过 idle/lease/bytes cap 就关闭，不增加无界 renderer queue。
- HTTP `429`/`Retry-After` 只是 admission 建议。mutation 遇到任何“可能已发送”的 429/连接中断仍先查
  request ID，不能因 Retry-After 自动生成第二个 operation。

## Shutdown 与 drain

正常完成：

```text
stop accepting local input
-> finish current response/event decode
-> flush complete stdout record
-> release response / invocation arena
-> close TurboHTTP session
-> destroy owned CoroNet context
```

Ctrl-C/timeout：

```text
atomically choose local terminal reason (Ctrl-C or deadline)
-> request cancellation source once
-> stop accepting new stream chunks
-> let protected request/wait unregister and exit owner lane
-> discard incomplete SSE event and report last complete cursor
-> release response / borrowed-to-owned buffers
-> quiesce cancellation dispatch and deadline task
-> destroy cancellation source
-> close client/context within bounded drain deadline
-> exit without sending remote cancel
```

收到第二次 Ctrl-C 可缩短本地 drain，但仍不能释放尚被 callback/registration 引用的对象；若 drain 到期，
记录非零退出与未静止阶段，让进程退出回收资源，不能在活跃 context 内强行 destroy。若操作者要求取消
远程工作，必须显式执行 `operations cancel`，并观察 cancel operation 的 receipt。

## Observability

CLI diagnostics 至少包含固定字段：command kind、endpoint origin、transport、request/operation ID、stage、
terminal reason、configured/remaining deadline、queue/connect/request/wait elapsed、HTTP status/error、response
bytes、pages/events、last cursor 和 retry count。不得记录 secret、完整 selector 目标清单或 response body；
指标/log label 不把 resource ID、node ID 或 operation ID 作为无界维度。

Controller 侧至少观察：query/mutation/watch 数量、auth deny、epoch conflict、request dedupe/collision、
plan stale、selector targets/evaluation duration、operation state latency、event cursor gap、response cap、
stream disconnect、clock skew、expired-before-admission、queue wait、deadline stage、cancel race 和 per-principal
rate limit。deadline 指标按有限 stage/reason 聚合，不把 request ID 放入 label。

## 验证门槛

### TurboParser

- 递归 command tree、global + ancestor + leaf options、required/enum/list/validator/env。
- `parse_ex` 的 success/help/version/error 都不打印、不退出；legacy wrapper 行为不变。
- duplicate command/option、OOM、容量、深度和错误位置。
- help golden output、shell completion metadata（若实现）与 Windows/POSIX argv。
- parser/argv/owned invocation 生命周期在 ASan 下验证。

### meshctl command core

- 每个 leaf 的 parser golden cases 和非法组合；command builder 输出精确 tagged union。
- legacy `genkey/init/doctor/up/rpc/cluster` 行为与 exit code 回归。
- selector source/token/depth/list 边界；CLI/Controller shared golden vectors。
- table/json/yaml/jsonl 不混入 progress；secret redaction。
- Ctrl-C 只取消本地 wait/watch，不意外取消远端 operation。
- 不安全 context ACL/symlink、URL userinfo、跨源 redirect、`--endpoint` trust override 和输出路径逃逸固定
  拒绝；argv/env/log/crash output 不泄露 credential。
- canonical mutation golden vectors覆盖字段顺序、Unicode、数字边界、重复 JSON key、未知关键字段和
  request ID 相同而 digest 不同的 collision。

### Controller client

- 真实 Iris mTLS H2 query/mutation/page/SSE；显式 H2 对 H1-only peer fail fast。
- H1 仅显式 profile；plaintext、错误/过期/撤销证书、错误 SAN/pin、DNS rebinding 和跨 origin redirect
  全部拒绝；current/next pin rotation 有正反例。
- principal/tenant/mesh/resource/action scope、selector 扩权、stale plan/base epoch、step-up 和双人审批策略
  均有 deny/audit 用例。
- request ID 幂等、collision、ACK lost、leader failover、unknown commit query。
- pagination generation change、event fragmentation、cursor resume/gap、64 KiB event 和慢 stdout。
- header/body/JSON depth/decompression/response/event 上限，slow headers/body 和 active watch/rate/queue 耗尽。
- 在 parse、DNS、connect、TLS、queue、send、commit 前后、response、watch idle、provider 和 shutdown 每个
  阶段注入 timeout；验证 retry/redirect 从不重置整体 deadline。
- cancel 与 response 同 tick、重复 cancel、registration 未清理、source destroy `TURBO_EBUSY`、borrowed
  callback copy 和 shutdown；ASan/TSan 下无 UAF/double-free/data race。
- H2 multiplex 下一个 stream timeout/cancel 不误杀其他 stream；SSE heartbeat fragmentation、stream lease、
  credential revoke、bounded reconnect 和 last complete cursor 恢复。
- UTC 前跳/后跳、monotonic 连续性、刚好等于 issued/expiry、允许/超出 clock skew 的 deterministic tests。

### 领域闭环

- selector plan 到明确 per-node assignment，离线/重启/重复 delivery 后收敛。
- content pull 的 CID、manifest signature、quota、receipt 和聚合状态。
- object tombstone、withdraw/revoke、cancel/evict、snapshot/pin 与 GC 不删除可达 chunk。
- Native catalog/permissions/provider digest；任意 path/argv/WASM 在 V1 固定拒绝。
- FlowMQ backpressure 只影响本地 provider stage，不让 CLI/Controller 误报执行成功。

## 迁移、兼容与回滚

### 实施阶段

1. 在 TurboParser 以 additive API 完成 non-exiting parse result、递归 command node、leaf metadata 和容量
   测试；旧 API 保持 ABI/行为。
2. 在 `meshctl` 提取 command core、renderer 和 client interface；现有命令仍由 legacy adapter 执行。
3. 首先开放 Controller read-only 的 contexts/devices/nodes/operations/audit 与 H2 pages/SSE。
4. 接入 plan 和低风险 mutation，再开放 network/route/service/release/placement/function。
5. 接入 M3 object streaming、release publish、withdraw/revoke/evict 和安全 GC operation。
6. 所有闭环和升级测试完成后，才把 product command 作为默认帮助首页；legacy commands 保留明确分组。

### 兼容性风险

- `HIGH`：直接改变现有 `turbo_cmd` 的 `exit()`、help 或 parse 行为会破坏已有 CLI。必须增加 `_ex` API，
  不替换 legacy wrapper。
- `HIGH`：把 `202`/transport send 当作节点成功会产生错误运维决策。所有 mutation 必须返回并展示
  operation ID。
- `HIGH`：selector plan/apply 不绑定 inventory generation 会把内容下发到操作者没看到的新节点。
- `HIGH`：将 delete 解释为立即物理擦除会误报数据治理结果。必须分 tombstone、revoke、evict、GC receipt。
- `MED`：新 product exit code、JSON schema 和 resource naming 是公开行为；启用前需要 golden tests 和
  versioned media type。
- `MED`：让 `meshctl` 直接依赖底层 HTTP/2 WebSocket 会扩大生命周期和协议维护面；V1 使用 facade SSE。
- `LOW`：legacy 单数/动词命名与新复数 resource 不一致；通过帮助分组和 alias 文档处理，不静默改名。

回滚时关闭 product command feature，保留 Controller desired state、operation/audit 和 agent reconcile；
CLI 二进制回退不能自动撤销已提交 mutation。协议/JSON 只做 additive version，新版本 command 不可用时
fail fast，不退化成 generic RPC。

## 一手资料与仓库依据

- [`examples/meshctl.c`](examples/meshctl.c)：当前命令、交互循环与 `cluster` 的 `turbo_cmd` 用法。
- [`tests/test_meshctl_rpc.c`](tests/test_meshctl_rpc.c)：现有 cluster/RPC 解析和调用测试。
- [`src/mesh_control_primitives.h`](src/mesh_control_primitives.h)：资源、权限、operation 和 envelope 原语。
- [`src/mesh_control_agent.c`](src/mesh_control_agent.c)：Controller transport/message 身份校验、信封期限和
  bounded shutdown drain。
- [`src/mesh_control_policy.c`](src/mesh_control_policy.c)：Controller permission、本地 policy、runtime 和
  exact provider 的权限求交。
- [`src/mesh_control_status.h`](src/mesh_control_status.h)：有界 status/event/receipt 格式。
- [`MESH_PRODUCT_CONTROL_PLANE.md`](MESH_PRODUCT_CONTROL_PLANE.md)：Controller、agent、H2/WS 和 provider
  权限边界。
- [TurboParser `turbo_parser.h`](../../turbo-parser/turbo_parser/include/turbo_parser.h)：当前 `turbo_cmd`
  public C API。
- [TurboParser `turbo_parser.c`](../../turbo-parser/turbo_parser/src/turbo_parser.c)：当前 parser ownership 与
  subcommand adapter。
- [TurboParser `turbo_selector.h`](../../turbo-parser/parser/selector/include/turbo_selector.h)：Selector V1
  grammar、硬上限、ownership、diagnostic、canonical 和 evaluation 契约。
- [TurboParser Selector tests](../../turbo-parser/parser/selector/test/test_turbo_selector.c)：source/string/list/
  depth 边界、Unicode round-trip、三值逻辑和 resolver failure 用例。
- [TurboHTTP `turbo_http.h`](../../../TurboHTTP/facade/include/turbo_http.h)：H1/H2 facade、mTLS、streaming、
  cancellation 与 response ownership。
- [TurboHTTP `http_client.h`](../../../TurboHTTP/http/include/http_client.h)：当前 request control 的 cancel
  token 边界。
- [CoroNet `turbo_coro_cancel.h`](../../turbonet/CoroNet/include/CoroNet/turbo_coro_cancel.h)：cancel source、
  token、registration 的线程与销毁契约。
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113)。
- [RFC 8441 — Bootstrapping WebSockets with HTTP/2](https://www.rfc-editor.org/rfc/rfc8441)。
- [WHATWG Server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html)。
- [re2c documentation](https://re2c.org/manual/manual_c.html)。
- [SQLite Lemon Parser Generator](https://sqlite.org/lemon.html)。

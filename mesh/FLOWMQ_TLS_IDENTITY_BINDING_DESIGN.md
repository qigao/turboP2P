# FlowMQ TLS 证书身份与 HELLO identity 绑定设计

## 文档状态与结论

状态：核心绑定路径已实现，并通过同进程真实 mTLS 正/负向、独立 server/client current/next leaf、
serverAuth/clientAuth EKU、current/next overlap、old pin 移除、listener restart 重认证以及有界子进程
往返测试。Mesh 使用 CoroNet 显式 TLS client config；该路径关闭客户端 session cache，因此每次重连
执行完整握手，不存在本 profile 的 TLS session resumption 路径。实际 agent/`meshd` 部署接线、生产
证书签发/安全存储/重载、撤销存量 session 和完整审计指标仍是 production 运维门槛。本文定义 FlowMQ
低层 endpoint 与 Mesh adapter 之间的认证契约；不改变 Mesh packet wire、`MeshNodeIPC/1` DATA payload
或业务授权模型。

`结论`：FlowMQ 不需要为 HELLO 再发明一套签名算法。TLS 1.3 握手已经证明对端持有叶证书对应的
私钥，TLS record 已保护同一连接上的 HELLO。缺少的安全属性是：**已验证证书是否被授权声明该条
HELLO identity**。V1 使用以下三项共同完成绑定：

1. CoroNet 只在 TLS/WSS 握手完成、证书链验证成功后导出叶证书 DER 的规范 SHA-256 指纹；
2. FlowMQ 在同一 socket 上读取 HELLO 后，执行 `(certificate_sha256, claimed_identity)` 精确策略；
3. 策略成功前不得注册 ROUTER route、发布 connected/ready、回放订阅或分发业务 frame。

绑定必须双向：BIND/ROUTER 验证 client certificate 与 client HELLO，CONNECT/DEALER 验证 server
certificate 与 server HELLO。任一方向缺失时，只能声称“TLS 与 HELLO 分别验证”，不能声称 identity
已与证书绑定。

`已解决的 HIGH`：standalone FlowMQ CONNECT endpoint 已增加对称 verifier，ROUTER/CONNECT 使用独立
verifier context；Mesh adapter 创建 immutable exact map 并强制双向安装。进程边界往返、重连重新认证、
真实双 leaf overlap、old pin 移除后的新连接拒绝和双向 EKU 错配拒绝均已验证；未完成的存量 session
fencing、生产证书生命周期、部署接线和审计门槛仍使 shared multi-tenant profile 保持 pre-production。

## 事实、推论与目标边界

### 仓库事实

- CoroNet 的 `coro_socket_tls_get_verified_peer_certificate_sha256()` 仅对 open TLS/WSS socket 成功；
  client 必须启用 peer verification，accepted server socket 必须要求 client certificate，且
  `SSL_get_verify_result()` 必须成功。结果格式是 `sha256:` 加 64 个小写十六进制字符。
- CoroNet 对 DER 编码的完整叶证书执行 SHA-256，不暴露 `X509 *`，失败时清空 caller buffer。
- CoroNet 还实现了 RFC 9266 `tls-exporter`，固定导出 32 bytes，且当前只允许 TLS 1.3。
- standalone FlowMQ ROUTER endpoint API v4 与 CONNECT endpoint API v3 均提供
  `verify_peer_identity(ctx, certificate_sha256, claimed_identity)`；ROUTER 在 route admission 前调用，
  CONNECT 在 subscription replay/READY 前调用。
- FlowMQ secure facade 的 credential-bearing HELLO 已把 auth secret 与 `tls-exporter` 放入同一 security
  envelope，并可在 BIND 侧调用 certificate verifier；Mesh 当前只链接 standalone low-level endpoint，
  不依赖该 facade。
- Mesh `mesh_node_ipc_flowmq` 要求 TLS 1.3-only loopback mTLS、exact expected HELLO identity、至少一个
  canonical certificate fingerprint、非零 policy generation、有限 timeout、heartbeat 和 bounded
  copied-send；ROUTER profile 还限制 `max_connections == 1`。
- CoroNet 显式 TLS client config 创建 endpoint 私有 `SSL_CTX` 并设置 `SSL_SESS_CACHE_OFF`；Mesh profile
  必须提供 CA/cert/key 和 `verify_peer=1`，因此不会进入只按 hostname 缓存 session 的默认 client 路径。

### 推论

- 因 HELLO 在完成后的同一 TLS connection 内发送，网络中间人不能在不破坏 TLS 的情况下修改 HELLO。
  因此证书指纹与 claimed identity 的 fail-closed policy check 已能构成密码学身份绑定；额外 HELLO
  signature 不增加 V1 所需的安全属性。
- `tls-exporter` 对 bearer credential 防跨连接转发有价值，但不能替代证书到 identity 的授权映射。
  一个 exporter 值只能说明“这是同一 TLS channel”，不能说明“此证书被允许声明 identity X”。
- 完整证书指纹会随证书续期变化，运维必须提供显式重叠窗口；这不是校验降级的理由。

### 目标

- 双向、同 socket、握手期完成证书与 HELLO identity 的精确绑定。
- 一个 session 只有一个不可变 authenticated principal，后续 frame 不再重复解释身份。
- 默认 fail closed，无 CN fallback、无 wildcard/prefix/Unicode normalization、无自动降级 transport。
- 保持现有 HELLO wire version 3；兼容旧 caller 的同时让 Mesh production profile 强制启用新能力。
- 明确 ownership、容量、timeout、重连、轮换、shutdown、审计和测试边界。

### 非目标

- 不用该绑定替代 command/resource authorization、Mesh membership ticket 或 MMP grant。
- 不在 FlowMQ callback 内查询数据库、HTTP、HSM 或远程策略服务。
- 不把 certificate fingerprint、exporter 或 HELLO identity 当作加密密钥。
- 不支持 TLS termination proxy 后继续保留原 peer identity；若代理终止 TLS，它就是 FlowMQ 的 TLS peer。
- V1 不解析 subject Common Name，也不引入自定义 ASN.1/OID、证书内 role DSL 或在线 OCSP owner。

## 威胁模型与安全属性

| 威胁 | V1 处理 | 剩余边界 |
|------|---------|----------|
| 持有受信 CA 下证书 A 的进程冒充 HELLO identity B | 精确 tuple policy 拒绝 | CA/策略 owner 被攻破不在本层解决 |
| 网络修改或重放 HELLO | TLS record 完整性；新连接重新握手并重新校验 | 不允许 TLS 0-RTT HELLO |
| bearer auth secret 被转发到另一 TLS connection | secure facade 使用 RFC 9266 exporter | low-level mTLS-only endpoint 不发送 bearer secret |
| 旧 route 在重连后继续发送 | 既有 endpoint/session generation fencing | 业务 operation 仍需自己的 dedupe/fencing |
| 证书轮换时 identity 短暂失配 | old/new 两条 tuple 显式重叠 | 配置分发错误仍会 fail closed |
| 同一证书跨角色使用 | 不同 fingerprint→identity tuple、独立 client/server leaf 与 EKU | 共享证书会扩大 blast radius，因此 production 禁止 |
| 私钥被盗 | 移除 tuple、吊销/替换证书并重启/热换策略 | 私钥存储、CA 与主机隔离由部署系统负责 |

V1 保证：只有成功通过 TLS peer verification、能够证明叶证书私钥持有，并且该叶证书指纹在当前
policy generation 中精确授权 claimed identity 的连接，才能进入 authenticated session。

V1 不保证：被授权进程行为良好，也不保证它有权执行任意 Mesh command。后续 DATA frame 仍必须经过
`MeshNodeIPC/1` scope、resource、generation、membership ticket 和 typed authorization。

## 候选方案与选择

| 方案 | 安全与运维特性 | V1 结论 |
|------|----------------|---------|
| 完整叶证书 DER SHA-256 → exact HELLO identity | 现有 CoroNet 已提供；无名称规范化歧义；轮换需双 pin | 采用 |
| SPKI SHA-256 → exact identity | 证书续期可不改 pin；同一 key 泄露/撤销的影响更长 | 后续可选，不作为 V1 fallback |
| URI SAN → exact identity | CA 可直接签发身份，适合大规模；需定义名称格式、解析与证书约束 | 后续独立 profile |
| subject CN / DN string | 自由文本、规范化和兼容行为含糊 | 禁止 |
| TLS exporter 直接当 identity | 只绑定 connection，不表达长期 identity | 禁止 |
| HELLO 自签名 | 重复 TLS possession proof，引入 nonce/key/算法/轮换协议 | 不采用 |
| 仅比较 configured HELLO identity | 与证书无关系，受信证书持有者可声明任意 identity | production 禁止 |

选择完整证书指纹不是把“hash 等同于身份”。权威身份仍是 policy 中的 tuple；指纹只是经过 TLS 验证的
证书 capability key。只有 TLS 验证结果、同 socket 证书指纹、HELLO claim 和 policy generation 四者
同时成立，session principal 才存在。

## 分层架构

```text
OpenSSL / TLS 1.3
  chain + hostname/EKU/time verification
  CertificateVerify private-key possession
                 │ verified leaf certificate on open socket
                 ▼
CoroNet TLS adapter
  sha256(DER leaf) -> fixed canonical fingerprint
  optional RFC 9266 tls-exporter for credential binding
                 │ pointer-free bounded snapshot
                 ▼
FlowMQ endpoint handshake owner
  parse HELLO -> exact tuple policy -> immutable session principal
                 │ authenticated identity only
                 ▼
Mesh FlowMQ adapter
  expected role/node + typed Mesh authorization
                 │ validated copied MeshNodeIPC/1 frame
                 ▼
Mesh command owner / reconciler
```

职责边界：

- CoroNet 拥有 `SSL`/`X509` 与握手生命周期，只导出固定指纹或 exporter bytes。
- FlowMQ 拥有 connection/session、HELLO 与 certificate mapping decision。
- Mesh adapter 只配置/强制 profile，并把已经认证的 identity 映射到 Mesh role；不读取 OpenSSL 对象。
- Mesh command owner 决定某 principal 能否执行具体资源操作；它不重新解释 TLS certificate。

## V1 规范身份与映射

### Certificate key

规范形式固定为：

```text
sha256:<64 lowercase hexadecimal characters>
```

digest 输入是 peer leaf certificate 的完整 DER bytes。禁止接受大写、缺少前缀、分隔符、空白、短 hash
或“尽量修复”输入。启动时先验证所有配置；运行时只做固定长度 exact compare。

### HELLO identity

FlowMQ wire 仍允许不超过 `FLOWMQ_PROTOCOL_MAX_IDENTITY_SIZE` 的合法 identity。Mesh production profile
进一步要求可打印 ASCII、无首尾空白，并采用既有 role-prefixed 命名，例如：

```text
meshd:node-01
mesh-agent:node-01
```

比较是 case-sensitive byte exact。V1 不做 URI decode、Unicode normalization、大小写折叠、glob、regex、
prefix 或 suffix match。

### Mapping invariant

策略由有界 tuple 集合组成：

```text
(certificate_sha256, hello_identity) -> ALLOW
otherwise                           -> DENY
```

- 同一 certificate fingerprint 在一个 policy generation 内最多映射一个 identity；冲突配置启动失败。
- 同一 identity 可以临时映射 old/new 两个 certificate fingerprint，用于轮换。
- 空映射在 `required` profile 下是配置错误，不代表“允许所有”。
- policy generation 是审计/状态字段，不参与密码学比较。

## FlowMQ 公共 API 演进

### 最小 release 路径

保留现有 ROUTER callback 语义，在 CONNECT endpoint 追加完全对称的 verifier：

```c
typedef int (*flowmq_connect_endpoint_peer_identity_fn)(
    void *ctx, const char *certificate_sha256, tstr_v claimed_identity);
```

`flowmq_connect_endpoint_config_t` 尾部新增该 callback 与独立的
`verify_peer_identity_ctx`。ROUTER 下一 API version 同样在尾部增加
`verify_peer_identity_ctx`，不再要求 verifier 与 frame/state/event callback 共用 `callback_ctx`。旧 ROUTER
v3 layout 中 verifier 继续接收原 `callback_ctx`，保证旧 caller 行为不变；新 layout 只使用专用 verifier
context。

CONNECT/ROUTER `create()` 必须按 `config.size` 识别已知旧布局，把缺失尾字段视为未配置，不能继续用
“必须等于最新 `sizeof`”破坏旧二进制 caller。Mesh required profile 会拒绝未配置 verifier 的旧 layout，
通用 FlowMQ endpoint 则保持既有行为。新 callback 的契约：

- 只在 endpoint owner 的 event-loop thread、TLS/WSS open 状态、server HELLO 完整解码后调用；
- 两个输入均 borrowed，仅在 callback 返回前有效；
- callback 必须无阻塞、无 I/O、无 endpoint lifecycle 调用；
- 非 `TURBO_OK` 一律转换为认证失败并关闭连接；不得 retry/fallback；
- 在 callback 成功前不得进入 READY、emit reconnect success、回放 subscription 或 drain send queue。

ROUTER 现有 callback 同样收紧为上述契约，并继续保证在 route registry admission 前执行。

### 推荐的安全 helper

为避免每个下游重写字符串校验，FlowMQ 提供可选、独立的 exact map helper；它不改变 wire：

```c
typedef struct flowmq_tls_identity_map_s flowmq_tls_identity_map_t;

typedef struct flowmq_tls_identity_binding_s {
  size_t size;
  const char *certificate_sha256;
  const char *hello_identity;
} flowmq_tls_identity_binding_t;

typedef struct flowmq_tls_identity_map_config_s {
  size_t size;
  const flowmq_tls_identity_binding_t *bindings;
  size_t binding_count;
  size_t max_total_string_bytes;
  uint64_t policy_generation;
} flowmq_tls_identity_map_config_t;

int flowmq_tls_identity_map_create(
    const flowmq_tls_identity_map_config_t *config,
    flowmq_tls_identity_map_t **out);

int flowmq_tls_identity_map_verify(
    void *map,
    const char *certificate_sha256,
    tstr_v claimed_identity);

void flowmq_tls_identity_map_destroy(flowmq_tls_identity_map_t *map);
```

`create()` copy 所有 tuple，验证重复/冲突后冻结。callback 只读 immutable map。大规模、动态 policy
provider 可以以后增加 versioned interface，但不得让首次 production profile 通过同步 callback 访问远端。

### Authenticated principal snapshot

FlowMQ session 内部保存 pointer-free、不可变摘要：

```c
typedef struct flowmq_authenticated_peer_s {
  size_t size;
  char certificate_sha256[72];
  char hello_identity[FLOWMQ_PROTOCOL_MAX_IDENTITY_SIZE + 1u];
  uint64_t policy_generation;
  uint64_t session_generation;
  uint8_t tls_verified;
  uint8_t identity_bound;
} flowmq_authenticated_peer_t;
```

V1 不必修改现有 frame callback ABI。ROUTER 可增加 route-fenced snapshot getter，CONNECT 可增加当前
generation snapshot getter；getter 返回 caller-owned copy。现有 callback 中的 `peer_identity` 只有在
`identity_bound == 1` 后才可被 Mesh production profile 接受。

## 双向状态机

### BIND / ROUTER

```text
ACCEPTED_SOCKET
  -> TLS_HANDSHAKE
  -> TLS_VERIFIED_CLIENT_CERT
  -> READ_AND_VALIDATE_HELLO
  -> GET_CERT_SHA256_FROM_SAME_SOCKET
  -> EXACT_TUPLE_POLICY
  -> COPY_IMMUTABLE_PRINCIPAL
  -> ROUTE_REGISTRY_ADMISSION
  -> SEND_SERVER_HELLO
  -> PEER_CONNECTED / DATA
```

任何失败都释放 HELLO frame、清空临时 fingerprint、关闭 peer；不能创建 route，也不能调用业务
`on_frame`。duplicate identity、capacity full 等 admission failure 同样不能留下可发送 route。

### CONNECT / DEALER

```text
TCP_CONNECTED
  -> TLS_HANDSHAKE_AND_SERVER_NAME_VERIFY
  -> TLS_VERIFIED_SERVER_CERT
  -> SEND_CLIENT_HELLO
  -> READ_AND_VALIDATE_SERVER_HELLO
  -> GET_CERT_SHA256_FROM_SAME_SOCKET
  -> EXACT_TUPLE_POLICY
  -> COPY_IMMUTABLE_PRINCIPAL
  -> REPLAY_SUBSCRIPTIONS / DRAIN_SEND_QUEUE
  -> READY
```

mapping mismatch 进入现有 reconnect/backoff 语义，但每次连接都必须重新握手、重新读取证书和重新校验；
不能因上一次成功而 cache identity decision。连续认证失败应遵循 bounded backoff，不能 busy-loop。

### TLS session resumption

resumed TLS session 仍必须满足 CoroNet 的 verified-peer query，并对当前连接重新执行 HELLO mapping。
OpenSSL 的 verify result 会随 session 恢复，但实现必须同时确认 peer certificate 存在；只有
`X509_V_OK` 不足以证明有证书。若 backend 无法在 resumption 后提供 verified peer certificate，required
profile 必须失败，不能复用旧 principal。

### HELLO channel binding

- mTLS-only low-level endpoint：不新增 wire 字段。HELLO 本身处于已认证 TLS record 中，tuple policy
  解决证书授权声明问题。
- credential-bearing secure facade：继续要求 RFC 9266 `tls-exporter` 同时出现在 client AUTH 与 server
  ACCEPTED 中，防止 credential 被转发到另一连接。
- 禁止用 exporter bytes 作为 secret、session ID、日志字段或长期 identity；每个 TLS connection 重新导出，
  使用后清零临时 buffer。

## 所有权、并发、容量与背压

| 对象 | owner | 生命周期/传递 |
|------|-------|---------------|
| `SSL` / peer `X509` | CoroNet TLS stream | 只在 open socket 内有效，不越过 CoroNet API |
| 临时 certificate fingerprint | FlowMQ handshake stack | caller-owned fixed buffer，mapping 后清零 |
| HELLO identity view | decoded frame | borrowed，frame cleanup 前有效 |
| exact map config strings | caller → map create | create 成功后 FlowMQ 独立 copy，失败仍归 caller |
| immutable map | endpoint/profile owner | callback 只读；所有 endpoint quiescent 后 destroy |
| verifier context | endpoint config caller | borrowed；必须比 endpoint 和所有 callback invocation 活得更久 |
| authenticated principal | FlowMQ session | session-owned immutable；callback borrow，getter copy |

V1 helper 同时限制 entry 和 retained string bytes：默认 retained byte budget 按 `64` 个 tuple 计算，
entry 硬上限为 `1024`；caller 可用 `max_total_string_bytes` 进一步收紧预算。超过任一上限启动失败。
Mesh 一对一 profile 正常为 1 条，轮换期最多 2 条。

`计算`：按 2 条 Mesh rotation tuple、每条 72-byte fingerprint、最多 256-byte identity 存储和不超过
32-byte metadata 估算，retained policy 上界为：

```text
2 * (72 + 256 + 32) = 720 bytes
```

这不含 allocator bookkeeping，但证明该 profile 不需要无界 map。通用 helper 的实际内存必须按 checked
multiply/add 计算，超出 `SIZE_MAX` 或 byte cap 返回 `TURBO_ERANGE`。

policy callback 不排队，也没有 blocking backpressure：它必须在本地有界内存中立即返回。若将来加入
动态 provider，只允许 `try`/deadline API；timeout、queue full 或 provider unavailable 都是 DENY，不能
临时接受未绑定 identity。

## Timeout、关闭与错误语义

TLS handshake、HELLO receive 和 identity mapping 共用一个明确的 endpoint handshake deadline；不能在
TLS 完成后重新获得无限 HELLO 等待。静态 map compare 应是确定性 CPU 操作，不单独延长 deadline。

建议内部区分以下 reason，公开调用仍可收敛为 `TURBO_EPERM` 或既有 transport error：

| reason | 外部语义 |
|--------|----------|
| `TLS_PEER_NOT_VERIFIED` | TLS profile/config 或证书链失败 |
| `TLS_PEER_CERT_MISSING` | required peer certificate 不存在 |
| `IDENTITY_POLICY_MISSING` | required profile 未配置 map/verifier |
| `IDENTITY_CLAIM_MALFORMED` | HELLO identity 非法或超长 |
| `IDENTITY_CERT_UNMAPPED` | 证书不在当前 policy generation |
| `IDENTITY_CLAIM_MISMATCH` | 证书存在，但 identity 不匹配 |
| `IDENTITY_POLICY_TIMEOUT` | 仅适用于未来有界 provider |
| `IDENTITY_BACKEND_UNSUPPORTED` | TLS backend 无法给出 verified principal |

关闭顺序：

```text
stop new accepts/reconnects
-> wake TLS/HELLO waits
-> prevent new verifier calls
-> wait active verifier callbacks return
-> remove routes / fence generations
-> release session principals and decoder buffers
-> close sockets/listener
-> stop managed CoroNet tasks/context
-> destroy immutable identity map
```

callback 中禁止调用 endpoint stop/destroy，避免 owner thread 自等待。shutdown 与 mapping race 时返回
shutdown/认证失败并关闭 socket；不得在 principal 未完整发布时发 connected event。

## 证书签发、轮换与撤销

production profile 要求：

- server/client 使用不同叶证书与私钥；server leaf 仅 serverAuth，client leaf 仅 clientAuth；
- 使用专用 channel CA 或受约束的 intermediate，不与通用 Web/API client certificate 混用；
- 私钥文件权限、有效期、chain、hostname/IP、EKU 由 TLS 层验证；tuple 是附加 authorization，不替代
  PKIX validation；
- Mesh config/status 只记录 fingerprint 和 policy generation，不读取或记录私钥；
- 不允许 CN fallback，也不允许“受信 CA 下任意证书”。

无中断轮换顺序：

1. 在验证端 policy 增加 `(new_fingerprint, same_identity)`，保留 old tuple，提高 generation；
2. 重载/重启验证端并确认新 generation 生效；
3. 在对端切换 leaf certificate/key 并建立新 session；
4. 从 authenticated session snapshot 确认 new fingerprint 已使用；
5. 删除 old tuple，再提高 generation；
6. 关闭仍使用 old fingerprint 的旧 session，完成撤销。

任一步失败都保留最近一个完整有效 generation。解析失败、重复冲突或空 required map 不得覆盖旧
snapshot。若没有安全的热重载 API，使用有序 endpoint restart；禁止自动退回 HELLO-only 校验。

## Mesh production profile 接入

### 配置

agent 与 `meshd` 各自需要对端证书 pin，命名保持角色清晰：

```yaml
network_control_expected_peer_identity: mesh-agent:node-01
network_control_expected_peer_certificate_sha256: sha256:<64 lowercase hex>
network_control_expected_peer_certificate_sha256_next: ""
network_control_identity_policy_generation: 7
```

`_next` 只用于显式轮换重叠；空值不创建 tuple。CONNECT 侧配置使用同样语义验证 `meshd` server。
上述配置已经接入 `meshd`：启用 network control 时，缺少 primary fingerprint、generation 为零或指纹
不是 canonical 格式都会在 listener 创建前 fail fast。旧配置需要补齐字段后才能重新启用该功能。

### Adapter enforcement

`mesh_node_ipc_flowmq_profile_validate_v1()` 在 production profile 中必须要求：

- transport 是 TLS，server 要求 client certificate，client `verify_peer == 1`；
- CoroNet TLS protocol mode 在创建任何 endpoint 前已固定为 `TURBO_TLS_PROTOCOL_TLS13_ONLY`；
- expected HELLO identity 与至少一个 canonical expected fingerprint 非空；
- BIND 和 CONNECT endpoint API version 都支持 peer identity verifier；
- adapter 安装自己的 exact tuple verifier，不允许 caller 用 permissive callback 覆盖；
- mismatch 在任何 Mesh frame 入队之前失败，且不触发 Pipe/TCP/WS fallback。

`事实`：CoroNet 当前 TLS protocol mode 是进程级设置，而不是 FlowMQ endpoint 私有字段。因此 Mesh
实现不得在 endpoint 运行期间切换该全局值。落地时必须二选一：由 `meshd` 启动阶段成为唯一 owner，
在任何 TLS socket 创建前设为 TLS 1.3-only 并校验同进程其他 TLS 使用者兼容；或先为 CoroNet 增加
per-context/per-endpoint TLS version profile。无法证明该不变量时 production profile 启动失败。

`mesh_node_ipc_flowmq` 可继续把 authenticated identity 映射到既有 `expected_peer_identity` 检查，形成
defense in depth；但证书 mapping 必须由 FlowMQ session handshake 执行，不能推迟到第一个 DATA frame。

## 可观测性与审计

每个 endpoint 至少提供累计 counter：

- `tls_peer_verified_total`
- `identity_binding_succeeded_total`
- `identity_certificate_unmapped_total`
- `identity_claim_mismatch_total`
- `identity_policy_error_total`
- `authenticated_connections_current`
- `identity_policy_generation`

审计事件包含 endpoint ID、route/session generation、policy generation、角色、failure reason 和 certificate
fingerprint；未认证 claimed identity 默认只记录 SHA-256 摘要或受限长度转义值，避免日志注入。禁止记录
private key、auth secret、exporter bytes、完整 certificate PEM 或未受限 HELLO payload。

认证失败在 connection boundary 记录一次，内部层只传播 reason/counter，避免 CoroNet、FlowMQ、Mesh
三层重复刷日志。连续攻击流量需要采样/rate limit，但 counter 不丢。

## 兼容性、迁移与回滚

### API/ABI

- CONNECT endpoint config 尾部追加 verifier 与专用 context，API version 升级；旧 struct 通过 `size`
  分支保持原行为。
- ROUTER endpoint API v4 已追加专用 verifier context；旧 v3-sized config 继续使用 `callback_ctx`，
  新 caller 不再混用业务 callback context。
- 默认通用 FlowMQ endpoint 可保持 binding disabled 以兼容旧应用；新的 Mesh production profile 必须
  required。兼容默认不能变成 Mesh 的隐式 fallback。
- HELLO wire v3 不变，因此旧 peer 仍能互通；required endpoint 会在缺少有效 mapping 时拒绝它。

### 分阶段迁移

1. **已完成**：CONNECT 对称 hook、ROUTER/CONNECT 专用 context、size-aware ABI 和 negative tests。
2. **部分完成**：有界 immutable exact map helper 已完成；authenticated principal snapshot getter 尚未完成。
3. **已完成**：Mesh adapter 双向 fingerprint config、TLS 1.3-only 强制 profile，以及 client/server
   unmapped-certificate 负向测试。
4. **部分完成**：独立 server/client current/next leaf、serverAuth/clientAuth EKU、真实 next leaf overlap、
   old pin 移除后的新连接拒绝、listener restart 后自动重连和进程边界 typed mTLS 往返已测试；显式
   TLS profile 已确认关闭 session cache。仍需删除 old 后主动关闭已建立的存量 session、生产证书
   签发/安全存储/重载/吊销、审计/状态字段，以及实际 `mesh-agent`↔`meshd` service 测试。
5. 上述运维门槛通过后再允许 shared multi-tenant production profile。

回滚只能回到上一个完整 policy generation 或关闭整个 optional FlowMQ IPC feature。不得回滚为相同端口
上的 plaintext、Pipe、HELLO-only 或“受信 CA 即允许任意 identity”。已建立 session 在 policy 撤销后应
主动断开；不能等待其自然重连才生效。

## 验证门槛

### 单元与属性测试

- canonical fingerprint：正确值、大小写、长度、前缀、空白、NUL、非 hex、容量边界。
- map：0/1/2/上限/上限+1、duplicate tuple、同 cert 冲突 identity、byte cap、checked overflow、OOM。
- exact identity：case、role、prefix/suffix、嵌入 NUL、最大 255 bytes 与 256 bytes。
- callback ownership：返回后立即污染 certificate/HELLO source，session snapshot 仍正确。

### TLS/FlowMQ 集成

- BIND：valid cert+identity 成功；trusted cert+wrong identity、wrong cert+right identity、无 cert 全拒绝。
- CONNECT：valid server cert+identity 成功；valid hostname cert+wrong HELLO identity 拒绝且不进入 READY。
- 过期、未生效、wrong CA、wrong hostname/IP、wrong EKU、`verify_peer=0`、client auth optional 全失败。
- `已覆盖`：显式 client config 禁用 session cache；listener restart 后客户端自动重连、重新完成 mapping
  并恢复发送。
- `已覆盖`：独立 server/client current/next leaf 在 overlap generation 中完成双向连接；删除 old pin 后，
  仍持有 old server 或 client leaf 的新连接分别在 READY/admission 前被拒绝。
- `已覆盖`：serverAuth-only leaf 用作 client、具有正确 `localhost` SAN 但只有 clientAuth 的 leaf 用作
  server 时均被 TLS 握手拒绝，证明角色 EKU 不由 HELLO mapping 替代。
- `未覆盖`：删除 old 后主动关闭使用 old leaf 的已建立 session；CRL/OCSP 或短证书 TTL 等生产吊销闭环。
- hook 失败前无 route registry、connected event、subscription replay、send drain 或 business callback。
- HELLO partial/oversize/malformed、handshake timeout、shutdown during verifier、callback return error。

### 安全与内存

- secure facade 的 AUTH/ACCEPTED exporter 相等，跨 TLS connection 转发失败；exporter 不进入日志。
- `已覆盖`：dedicated server/client leaf 与双向 EKU tests；共享 CA 下但 old pin 已移除的合法证书不能
  在新 session 中冒充。
- ASan/UBSan 覆盖 decoder cleanup、temporary fingerprint、map copy failure；TSan 覆盖 stop/reconnect/policy
  snapshot；CoroNet shutdown regressions 覆盖 pending recv/TLS close。
- fuzz HELLO/security envelope 与 map config；不自行 fuzz/解析 ASN.1，证书解析继续交给 OpenSSL。

当前组件级实现已经满足双向 certificate-bound FlowMQ identity 的核心定义，并完成独立 leaf/EKU、
真实 overlap/old-pin-removal、跨进程往返、重连与有界 shutdown 回归。只有存量 session fencing、生产
证书签发/安全存储/重载/吊销、审计以及实际 agent/meshd service gates 全部通过，才可进一步声明
shared multi-tenant production ready。

## 一手资料

- [RFC 9846: TLS 1.3](https://www.rfc-editor.org/rfc/rfc9846.html)：CertificateVerify 私钥持有证明、
  record protocol 与 exporter。
- [RFC 9266: TLS 1.3 channel binding](https://www.rfc-editor.org/rfc/rfc9266.html)：
  `EXPORTER-Channel-Binding`、32-byte 输出及用途限制。
- [RFC 5280: PKIX certificate profile](https://www.rfc-editor.org/rfc/rfc5280.html)：证书链、SAN、
  key usage 与 extended key usage。
- [RFC 9525: Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525.html)：应用协议必须定义
  reference identity 与匹配规则，并避免 Common Name 作为身份。
- [OpenSSL `SSL_get_verify_result`](https://docs.openssl.org/3.5/man3/SSL_get_verify_result/)：成功值本身
  不证明 peer 提供了 certificate，必须同时查询 peer certificate。
- [OpenSSL `SSL_export_keying_material`](https://docs.openssl.org/3.5/man3/SSL_export_keying_material/)：
  TLS exporter API。

# TurboP2P 生产级 Noise 身份认证设计

## 1. 文档状态

- **状态**：secure wire v2 基线已实现；发布安全闸门尚未全部完成，不能宣称已通过生产安全审计。
- **范围**：P2P TCP/CoroNet 会话的握手、节点身份认证、加密传输、资源治理和迁移。
- **目标版本**：P2P secure wire v2。
- **不改变的上层语义**：DHT、文件传输、Pub/Sub 和自定义消息仍是 P2P 上层能力；本设计只改变它们进入网络前的安全会话边界。
- **已批准的迁移策略**：第 18 节方案 A，全网 v2 硬切换；同端口不探测、不降级、不回退 legacy。

本文中的证据类型如下：

- **事实**：来自当前仓库实现、测试或官方规范。
- **目标**：v2 必须达到的行为。
- **推论**：由当前实现和威胁模型推导出的设计判断，实施时仍需测试验证。
- **常用做法**：行业通行方案，只作辅助理由。

## 2. 决策摘要

v2 采用固定协议名 `Noise_XX_25519_ChaChaPoly_BLAKE2s`。不得把当前自定义握手继续扩展后称为 Noise，也不得在同一连接上自动回退到旧协议。

核心决策：

1. 使用标准 Noise XX token 顺序和标准 transcript、chaining key、HKDF、CipherState；密码协议由薄适配层接入通过准入审计的实现。
2. Mesh 模式使用现有 Ed25519 管理证书，把 Noise 认证出的 X25519 静态公钥绑定到 `managed_node_id`、`mesh_id_hash`、角色、有效期和 epoch。
3. 原始 P2P 模式只支持显式静态公钥 pin；不提供生产环境的匿名接受或静默 TOFU。
4. Noise 握手、证书验证和双向 `SESSION_READY` 完成之前，不发布 peer、不回调连接成功、不接受任何应用消息。
5. Noise handshake hash 是会话 channel binding；MMP、M3 等上层逐步从“只比较静态公钥”迁移到“认证身份 + channel binding”。
6. CoroNet event loop 是每个 peer 安全状态的唯一 owner；所有 retained buffer、pending handshake 和发送队列均有硬上限；node 以每条 transport 的 send HWM 预留量作为聚合容量事实源。
7. 安全 preface、长度字段、应用 header，以及 PING/PONG、DHT、文件/块传输 payload 均使用规范化大端 codec；CUSTOM/未结构化 payload 只作为有界 bytes 传输，不再发送原生 C struct padding。
8. 入站 listener 在创建 peer、4 KiB peer receive buffer、Noise state 和整条 stream send reservation 前，先通过固定容量 gate 验证来源 IP、时间桶和 initiator preface 绑定的 HMAC-SHA256 cookie；cookie binding 进入 Noise prologue。

## 3. 当前事实与风险

### 3.1 当前实现

**事实**：`p2p/src/security/p2p_noise_backend.c` 已通过 opaque 适配层接入固定 commit 的 Noise-C，并固定为 `Noise_XX_25519_ChaChaPoly_BLAKE2s`；X25519 与操作系统 CSPRNG 由 `p2p_noise_c_platform.c` 接入 TurboNet Crypto。

**事实**：initiator 先发送 44 字节 v2 preface；listener 返回固定 48 字节 cookie challenge，验证 48 字节 response 后才创建完整 inbound peer，再发送 responder preface。双方把 initiator/responder preface、40 字节 cookie binding 与产品 domain 放入 Noise prologue。M2/M3 加密 payload 携带有界 credential，Split 后再交换加密 READY，READY 校验 principal、routing ID、credential digest 与 handshake-hash 派生 session ID。

**事实**：节点未配置 `p2p_node_configure_security_v2()` 或 pinned provider 时拒绝监听；peer 只有完成 credential 验证和 READY 后才进入 connected table、触发回调和接收应用消息。legacy handshake message 被保留为拒绝码位，不存在运行时 fallback。

**事实**：原始 P2P 已有静态公钥 allowlist provider，并可由 `p2p_node_update_pinned_trust_v2()` 在 owner thread 上复制替换最多 256 个 pin 后立即复验在线会话；空集合表示撤销全部远端。Mesh management provider 验证现有 354 字节证书的签名、Mesh ID、Noise static key、有效期、撤销 serial、最低 epoch 和远端角色。provider 可在 owner thread 上事务式替换远端 epoch/role/revocation snapshot，随后由 `p2p_node_revalidate_security_v2()` 逐个复验 established session 并关闭不再可信或身份结果变化的连接。M3 chunk v2 已校验 Noise channel binding；MMP/1.1 的签名 HELLO/ACK 也显式携带并校验同一 handshake hash。

**事实**：认证 identity 保留 32 字节 routing ID，但现有 Kademlia ABI 仍使用 20 字节 ID，因此当前路由表使用认证 routing ID 的前 20 字节。PING/PONG 只能声明相同的已认证 ID，不能覆盖 Noise 建立的身份。

**事实**：当前已覆盖 Noise-C 上游锁定版本的 XX 固定向量、cookie 固定向量/来源绑定/时间与轮换边界、application v2 canonical PING/DHT/transfer codec 固定字节与 round-trip、真实双节点 cookie+XX 会话、错误 network、未 pin static key、重放/乱序/计数耗尽、会话资源默认值/上界、Mesh 证书 key/签名/有效期/撤销/epoch/role，以及 DHT、MMP、M3 集成回归。独立实现互操作、持续 fuzz、Linux/TSan 与独立安全审查尚未完成。

**事实**：`mesh/src/mesh_mgmt_identity.h` 已定义 354 字节 v1 证书，绑定：

- Ed25519 `management_key`
- X25519 `transport_peer_id`
- `managed_node_id`
- `mesh_id_hash`
- roles、有效期、serial 和 `principal_epoch`

**事实**：`mesh_mgmt_session_accept_hello_v1()` 当前会验证证书签名、Mesh ID、时间窗口，并要求实际 P2P remote public key 等于证书中的 `transport_peer_id`。

**目标**：保留这条成熟的 Mesh 身份绑定，但将身份验证前移到 P2P 安全会话建立阶段，避免未认证 peer 先进入上层。

### 3.2 风险等级

| 等级 | 风险 | 影响 |
|---|---|---|
| HIGH | 缺少独立实现互操作、持续 fuzz 与独立安全审查 | 锁定的上游向量能发现实现漂移，但双方共享同一 backend bug 时，现有集成测试仍可能同时误判成功 |
| MED | cookie 验证前仍需操作系统/CoroNet 接受 TCP stream 并占用一个固定 gate slot | cookie 已阻止 peer/Noise/完整 send budget 放大，但不能替代内核 SYN 防护、边缘限速或容量规划 |
| MED | node 已按 per-stream HWM 做保守聚合预算，但 CoroNet 尚无跨 backend 一致的瞬时 retained-byte 指标 | 能限制最坏内存容量，仍不能精确观测慢接收端的当前 queued bytes |
| LOW | 32 字节认证 routing ID 被截为现有 20 字节 Kademlia ID | 保持 ABI，但审计和后续协议需明确全长 ID 与路由 ID 的区别 |

## 4. 目标与非目标

### 4.1 目标

- 双向认证、前向保密、transcript binding 和 key confirmation。
- 明确区分 transport key、管理 principal、managed node ID 和 routing ID，并给出唯一推导关系。
- Mesh 证书、pin trust store 和撤销/epoch 策略只有一个事实源。
- 任何认证、版本、网络、资源或状态不变量失败时 fail closed。
- Linux/Windows 上保持 CoroNet transport 和公开 P2P 数据能力。
- 为 MMP/M3 提供稳定 channel binding，防止把上层凭据搬到另一条会话重放。
- 受限内存、受限 pending 数、明确 backpressure、完整 shutdown 和可诊断错误。

### 4.2 非目标

- v2 首版不支持 0-RTT 应用数据。
- v2 首版不协商多个 Noise suite。
- v2 首版不支持同一连接上的 legacy fallback。
- 不在 P2P core 内实现 Controller、证书签发或网络策略存储。
- 不自行发明 DH、AEAD、hash 或签名算法。
- 不把 Noise 等同于授权；Noise 证明密钥持有，证书/pin 和策略决定是否准入。

## 5. 威胁模型

### 5.1 防御范围

v2 必须抵御：

- 被动窃听和流量内容篡改。
- 主动 MITM、静态密钥替换和握手 transcript 修改。
- 跨 Mesh 连接、协议版本/套件降级和 legacy 注入。
- transport ciphertext 重放、截断、乱序和伪造。
- 过期、未知签发者、错误 Mesh、错误 transport key、旧 epoch 和已撤销身份。
- 慢速握手、超长 frame、pending 表耗尽和来源地址洪泛。
- 连接同时拨号导致的重复 peer 状态分叉。
- shutdown、timeout 或错误路径上的密钥残留与悬挂回调。

### 5.2 明确不防御

- 已攻陷节点进程或被盗的有效私钥。
- 操作系统内核、随机数源或 Noise backend 被攻陷。
- 仅靠加密隐藏流量大小、时序和通信双方 IP。
- 没有 Controller/revocation snapshot 时的即时全网撤销。

私钥失窃必须通过证书 serial/epoch 撤销、静态 transport key 轮换和节点隔离处理，不能假设重连即可恢复安全。

## 6. 密码套件与依赖准入

### 6.1 固定 suite

首版固定：

```text
Noise_XX_25519_ChaChaPoly_BLAKE2s
```

选择理由：

- XX 在双方事先不知道对方静态 transport key 时提供双向静态身份交换，适合动态 Mesh peer。
- 25519 与当前 X25519 32 字节 key 配置兼容。
- ChaChaPoly 和 BLAKE2s 是 Noise 标准算法组合。
- 固定 suite 避免首版出现可降级的算法协商状态。

后续只有在已知 peer、pin/certificate 已分发且 XX 稳定后，才能将 IK 作为**新的明确协议版本**评估；不得在 v2 内隐式切换。

### 6.2 backend 边界

新增内部薄适配层：

```text
p2p/src/security/p2p_noise_backend.h
p2p/src/security/p2p_noise_backend.c
```

职责仅包括：

- 建立 initiator/responder handshake state。
- 设置 prologue、本地 static key 和 RNG。
- 严格按 XX 消息序列读写。
- 获取 remote static key 和 handshake hash。
- Split 为两个 CipherState，encrypt/decrypt/rekey/destroy。
- 把 backend 错误映射为项目错误；第三方类型不得进入公开头文件。

当前 C 实现是 Noise 官方实现列表链接的 `rweather/noise-c`，固定 commit `cfe25410979a87391bb9ac8d4d4bef64e9f268c6`，许可证为 MIT。构建只选择 XX 所需的 protocol、ChaChaPoly、BLAKE2s 代码，并通过本地薄适配层提供 X25519/RNG。以下准入门中，固定来源、许可证、Windows/MSVC 构建和真实会话测试已完成；其余仍是发布阻断项：

1. 固定上游 commit/tag，记录来源、许可证和本地补丁。
2. 核对最近维护状态、公开安全问题、release 策略和 CI。
3. 验证 Windows/MSVC、Linux、CMake、32/64 位和 sanitizer。
4. 跑通官方向量、交叉实现互操作和畸形输入 fuzz。
5. 审计随机数注入、constant-time 比较、密钥清零、allocator 和错误路径。
6. 不满足任一安全准入项时停止集成；不得降级为继续使用当前自定义握手。

**目标**：仓库只负责协议编排、身份策略和生命周期，不复制或改写成熟密码原语。

## 7. 身份模型与单一事实源

### 7.1 身份分层

| 名称 | 长度 | 事实源 | 用途 |
|---|---:|---|---|
| Noise transport key | 32 字节 X25519 public key | 本地安全 key source；远端由 Noise transcript 认证 | DH、会话认证、证书 transport 绑定 |
| management principal key | 32 字节 Ed25519 public key | Mesh 证书 | 签名管理消息与组织身份 |
| managed node ID | 32 字节 | Mesh 证书 | Controller、审计、策略和节点生命周期 |
| P2P routing ID v2 | identity 中 32 字节；当前 Kademlia 使用前 20 字节 | 从已认证 principal 确定性推导 | Kademlia 路由、重复连接仲裁；全长升级另行版本化 |
| channel binding | 32 字节 | Noise `GetHandshakeHash()` | 唯一本次安全会话绑定 |

Mesh 模式的 routing ID：

```text
SHA-256("turbo-p2p-routing-id-v2" || mesh_id_hash || managed_node_id)
```

Pinned-static 模式的 principal ID：

```text
SHA-256("turbo-p2p-static-principal-v2" || noise_static_public_key)
```

其 routing ID 使用同一 routing domain、network ID hash 和 principal ID 推导。所有 domain string 都按 ASCII 精确编码，并纳入测试向量。

**HIGH 目标**：v2 不接受网络上传来的任意 routing ID。PING 中若再次出现 node ID，必须与认证后推导值一致，否则立即关闭连接。

### 7.2 Mesh 证书模式

Noise XX 的加密 payload 携带现有 canonical `mesh_mgmt_certificate_v1_t` wire bytes。认证 provider 必须验证：

1. 证书格式和 Ed25519 issuer signature。
2. `mesh_id_hash` 等于本地配置。
3. `not_before <= now < expires_at`。
4. `transport_peer_id` 等于 Noise 认证出的 remote static key。
5. principal 类型、roles 和本地准入策略。
6. serial 未撤销，`principal_epoch` 不小于本地 committed trust snapshot。
7. managed node ID 非零且没有被另一有效 transport key 冲突占用。

证书验证成功只产生不可变 `p2p_authenticated_identity_v2_t`；peer core 不允许独立修改其中字段。

### 7.3 Pinned-static 模式

适合不使用 Mesh 管理面的 P2P 用户：

- trust store 显式列出允许的 X25519 static public key。
- remote key 必须由 Noise handshake 认证并命中 immutable trust snapshot。
- principal/routing ID 按第 7.1 节推导。
- trust store 更新是版本化配置替换，不在握手回调里修改。

生产 profile 不提供 accept-any。TOFU 只有在定义持久化、首次确认、原子写入、冲突和轮换语义后才能作为独立后续功能。

## 8. 认证 Provider 接口

P2P core 不包含 Mesh 证书类型。新增小型、版本化 C 接口，采用 caller-provided buffer，回调不得挂起或执行网络/磁盘 I/O：

```c
typedef struct p2p_identity_provider_v2 p2p_identity_provider_v2_t;

typedef struct {
    uint8_t principal_id[32];
    uint8_t routing_id[32];
    uint8_t credential_digest[32];
    uint64_t trust_epoch;
    uint64_t expires_at_ms;
    uint32_t flags;
} p2p_authenticated_identity_v2_t;

typedef struct {
    int (*build_local_credential)(
        void *context,
        const uint8_t local_noise_static[32],
        uint8_t *output,
        size_t output_capacity,
        size_t *out_len);
    int (*verify_remote_credential)(
        void *context,
        const uint8_t remote_noise_static[32],
        const uint8_t channel_binding[32],
        const uint8_t *credential,
        size_t credential_len,
        uint64_t now_ms,
        p2p_authenticated_identity_v2_t *out_identity);
    void *context;
} p2p_identity_provider_ops_v2_t;
```

接口约束：

- `context`、trust snapshot 和 provider 在 node stop 完成前由调用方保持有效。
- output 是 core 拥有的定长 buffer；provider 只在调用期间借用。
- remote credential 只在回调期间借用，不得保存指针。
- 回调成功必须完整初始化输出；失败时 core 清零输出并关闭连接。
- callback 是安全边界，只调用一次；禁止回调重入 node API。
- Mesh provider 使用预加载、不可变的 issuer/revocation/policy snapshot，配置更新以原子版本替换进入 event loop。

上述契约已由公开的 `p2p_node_configure_security_v2()`、
`p2p_node_configure_pinned_security_v2()` 和
`p2p_peer_get_security_info_v2()` 冻结为 v2 API；后续扩展必须依赖
`struct_size` 和新版本入口，不能原地改变字段语义。

### 8.1 公开 API 迁移原则

- 新增 `p2p_node_configure_security_v2()`，且只能在 `p2p_start*()` 前调用；运行中修改返回 `INVALID_STATE`。
- 配置包含 `struct_size`、固定 protocol profile、network ID、key source、identity provider、timeout 和容量上限，以便 ABI 扩展和启动时完整校验。
- 保留 `p2p_node_get_public_key()` / `p2p_peer_get_public_key()` 的 32 字节 Noise static key 语义，避免上层立即破坏；新代码使用安全快照 API 判断认证状态。
- 现有 `p2p_node_set_private_key()` 只作为内存 key source 的兼容入口；生产 profile 若未配置稳定 key 和认证 provider，启动直接返回 `AUTH_REQUIRED`。
- 不以环境变量或默认值暗中开启 legacy/accept-any。配置优先级、来源和有效 profile 必须能由只读诊断接口查询。
- 安全配置一旦成功安装，由 node security context 拷贝固定字段并借用 provider/trust snapshot；失败不部分更新 node。

## 9. Secure wire v2

### 9.1 Preface

双方在 Noise 前交换固定 44 字节 preface：

| Offset | Size | 字段 | 规则 |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `TPN2` |
| 4 | 1 | major | `2` |
| 5 | 1 | minor | `0` |
| 6 | 2 | suite | big-endian，`1 = XX_25519_ChaChaPoly_BLAKE2s` |
| 8 | 2 | flags | v2 必须为 `0` |
| 10 | 2 | reserved | 必须为 `0` |
| 12 | 32 | network ID hash | 本地配置的 canonical network ID digest |

入站 listener 只在固定 gate slot 中接收 initiator preface。未知 magic/version/suite、非零保留位或 network mismatch 直接关闭，不创建 `p2p_peer_t`。

### 9.2 Listener cookie

preface 通过后执行固定 wire challenge/response：

```text
Initiator -> Responder: initiator_preface[44]
Responder -> Initiator: cookie_challenge[48]
Initiator -> Responder: cookie_response[48]
Responder -> Initiator: responder_preface[44]
Initiator -> Responder: Noise message 1
```

48 字节 cookie packet 是 canonical 大端格式：

| Offset | Size | 字段 | 规则 |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `TPC2` |
| 4 | 2 | version | big-endian `2` |
| 6 | 1 | type | `1 = CHALLENGE`，`2 = RESPONSE` |
| 7 | 1 | reserved | 必须为 `0` |
| 8 | 8 | time bucket | 单调毫秒时钟除以 cookie lifetime，big-endian |
| 16 | 32 | MAC | HMAC-SHA256 |

server 启动配置时从操作系统 CSPRNG 生成 32 字节 process-local master secret。每个时间桶通过

```text
effective_key = HMAC-SHA256(
  master_secret,
  "turbo-p2p-cookie-key-v2" || key_epoch_be64)
```

派生轮换 key，其中 `key_epoch = time_bucket / buckets_per_rotation`。cookie MAC 是：

```text
HMAC-SHA256(
  effective_key,
  "turbo-p2p-cookie-v2" || address_family || exact_source_address ||
  time_bucket_be64 || initiator_preface)
```

IPv4 绑定完整 `/32`，IPv6 绑定完整 16 字节地址，不绑定临时 source port。验证只接受当前或前一个时间桶；未来、过旧、错误来源、错误 preface、错误类型/保留位或 MAC 均 fail closed。默认 lifetime 为 10 秒、derived-key rotation 为 5 分钟，rotation 必须是 lifetime 的整数倍。master secret 只属于 node security context，destroy 时清零，不进入日志、状态查询或 wire。

response 只把 type 改为 `RESPONSE`；成功后双方保存 `time_bucket || MAC` 这 40 字节作为 cookie binding。listener 此时才停止 gate callback、创建 inbound peer、预留完整 stream HWM、安装 peer receive callback 并初始化 Noise。challenge 本身由 CoroNet copy-send 持有；gate 不保留额外发送 payload。

Preface 本身不可信；双方完整 preface 与固定 product domain 一起作为 Noise prologue：

```text
"TurboP2P secure wire v2" || initiator_preface || responder_preface ||
cookie_binding
```

因此中间人修改 preface 或搬运 cookie 会导致 cookie 验证或 Noise transcript/key confirmation 失败。v2 listener 不识别 legacy bytes，也不尝试猜测协议。

### 9.3 Noise frame

每条握手和 transport frame 使用：

```text
uint16_be frame_length
byte[frame_length] frame
```

- Noise 官方上限是 65535 字节。
- 本项目握手 frame 上限固定为 4096 字节；credential 上限为 1024 字节。当前 354 字节 Mesh 证书可直接容纳。
- transport ciphertext 上限 65535，明文上限 65519（扣除 16 字节 AEAD tag）。上层 message 仍受更小的业务限制。
- length 为 0、超过当前状态上限、short read 或额外未消费字节均为协议错误。
- parser 使用显式大端读写函数，不接收 native struct。

### 9.4 XX 消息

```text
Initiator -> Responder: e
Responder -> Initiator: e, ee, s, es, encrypted(responder credential)
Initiator -> Responder: s, se, encrypted(initiator credential)
```

Responder 在 message 2 构建前验证本地 credential 与本地 static key 一致。Initiator 读完 message 2 后立即验证 responder credential；Responder 读完 message 3 后立即验证 initiator credential。

任何验证失败都不得继续 Split 或发送可区分的详细远端错误。详细原因只进入本地诊断计数。

### 9.5 Key confirmation 与 SESSION_READY

完成 Split 后，双方必须发送并接收第一条加密 control frame `SESSION_READY`。其 canonical 明文包含：

- control type 和 secure wire version。
- sender principal ID、routing ID。
- credential digest。
- `session_id = BLAKE2s("turbo-p2p-session-v2" || handshake_hash)`。
- P2P application protocol version、feature bitmap、最大 frame、keepalive 和 session 限额。

收到对端 READY 后验证所有身份字段和本地计算值。只有双方 READY 完成后才进入 `ESTABLISHED`。

### 9.6 Application protocol v2

READY 的 application protocol version 固定为 `2`。版本 `1` 的 native-layout application payload 不再接受，也没有按消息猜测旧布局的 fallback。

每条解密后的 application message 以以下 8 字节 header 开始：

| Offset | Size | 字段 | 规则 |
|---:|---:|---|---|
| 0 | 1 | message type | 必须是已定义且非 legacy-reserved 的类型 |
| 1 | 1 | flags | v2 必须为 `0` |
| 2 | 2 | encoded payload length | big-endian，且 header + payload 不超过 65519 字节 Noise 明文上限 |
| 4 | 4 | request ID | big-endian |

结构化 payload 不复制内存 struct，而由单一 codec adapter 显式编解码：

| 类型 | Canonical payload |
|---|---|
| PING/PONG | node ID、binary IP、port、timestamp、4 个坐标、height、error |
| DHT FIND/GET | 20 字节 target ID |
| DHT PUT | key、`u16_be data_len`、data |
| DHT RESPONSE | found、node count、逐项 binary address contact、`u16_be data_len`、data |
| FILE GET | 20 字节 file ID |
| FILE PUT/response | file ID、`u64_be file_size`、`u32_be total_chunks`、SHA-256 |
| CHUNK REQUEST | `u32_be transfer_id`、`u32_be chunk_index` |
| CHUNK DATA | transfer/chunk ID、`u16_be data_len`、hash、data |
| FILE ACK | `u32_be transfer_id`、0/1 success |
| CUSTOM/未结构化类型 | 原样有界 bytes，不解释宿主布局 |

IP 使用 `family = 0/4/6` 加 0/4/16 字节 binary address，因此 IPv6 的多种文本写法只有一个 wire 表示；反序列化后才通过系统地址 formatter 生成 host string。浮点值以 IEEE-754 binary64 bit pattern 按 big-endian 写入，并拒绝 NaN、Infinity、负 height、`error` 超出 `[0,1]` 或超出坐标资源边界的值。decoder 对 short input、额外字段、长度不一致、未知 type/flags、非法 address 和非 canonical success/found 值统一返回协议错误并关闭会话。

`p2p_message_t` 仍是进程内业务 view；其中 `header.payload_len` 在进程内表示解码后的逻辑 payload 范围，wire length 只由 codec 计算。任何调用方不得把 `offsetof`/`sizeof` 当作网络布局。

## 10. 状态机与发布边界

```text
TCP_CONNECTED
  -> INITIATOR_PREFACE
  -> COOKIE_CHALLENGE/COOKIE_RESPONSE
  -> RESPONDER_PREFACE
  -> NOISE_M1
  -> NOISE_M2
  -> VERIFY_RESPONDER
  -> NOISE_M3
  -> VERIFY_INITIATOR
  -> SPLIT
  -> READY_SENT/READY_WAIT
  -> ESTABLISHED
  -> DRAINING
  -> CLOSED
```

角色只影响 M1/M2/M3 的合法转移。任一错误从当前状态单向进入 `CLOSING/CLOSED`，不得返回早期状态或在同一连接重试。

发布不变量：

- `p2p_node_on_peer_authenticated()` 必须改为只在 `ESTABLISHED` 后执行。
- `peer->id`、remote static key、authenticated identity 和 channel binding 必须在发布前一次性安装。
- DHT bucket、连接回调、路由传播、PING、Pub/Sub、文件和 custom message 在发布前均不可见。
- 同时双向拨号只在认证出 routing ID 后仲裁；按有序 `(local_routing_id, remote_routing_id)` 确定保留 inbound 或 outbound，保证双方作同一选择。

## 11. Transport CipherState

- v2 直接使用 Noise Split 产生的发送/接收 CipherState。
- ChaChaPoly 使用 Noise 定义的隐式递增 nonce；wire 不再携带自定义 8 字节 counter。
- frame type 放在加密明文内部，不能由未认证外层字段控制业务分派。
- decrypt/tag/nonce/order/frame 错误均为 terminal，不跳过坏 frame。
- 禁止应用层自行复用 Noise key、nonce 或 handshake hash 作为加密 key。

当前固定的 Noise-C 接口没有暴露可依赖的 CipherState Rekey，基线因此采用更保守的硬限额：每个方向最多成功处理 `2^20` 个 transport frame；达到边界返回 `KEY_EXHAUSTED` 并关闭连接，不重置 nonce，也不自行发明 rekey。

**事实**：会话还受可配置但只能降低的单调时长与加密 wire bytes 上限约束，默认分别为 24 小时和 1 TiB/方向；达到任一边界即返回 `KEY_EXHAUSTED` 并 fail-closed 关闭。当前协议没有为 `GOAWAY` 预留独立 nonce/发送额度，因此不能在 key/byte 边界后安全承诺控制帧；有界优雅重连仍是后续版本化协议能力。若 backend 后续提供标准 rekey，它必须由消息计数确定，不能由双方不一致的 wall clock 触发，并需通过边界与独立实现互操作测试。

## 12. 内存、容量与 backpressure

### 12.1 所有权

- CoroNet event loop 单线程拥有 peer 的握手状态、CipherState、身份结果、frame parser 和发送顺序。
- 入站 cookie gate 是 node-owned 固定数组；每槽只拥有 accepted stream、来源 endpoint、deadline、44 字节 preface 和最多 48 字节当前接收数据。验证成功时 stream 所有权一次性转给新建 inbound peer；失败、超时、stop 或 destroy 时 gate 清空 user data、停止接收并销毁 stream。
- socket receive buffer 是 borrowed view；只在 CoroNet 允许的作用域内访问并按其 API 释放。
- 跨挂起点、入队或回调返回后仍需使用的数据，必须复制到 core-owned bounded buffer。
- credential/provider 输入是同步 borrow；provider 不得保存。
- node 配置和 trust snapshot 在 event loop 中只读，替换由明确 command 完成。

### 12.2 默认硬上限

| 资源 | 当前值/目标 | 状态与满载行为 |
|---|---:|---|
| 全局 pending handshake | 128 | 已实现；立即拒绝新连接 |
| listener cookie gate | 默认 128 槽，最大 128 | 已实现；node-owned 固定数组，满载立即拒绝，不分配 peer/Noise |
| gate retained protocol bytes | 92 字节/槽 | 已实现；44 字节 preface + 48 字节当前 packet，任何超额/合并恶意输入关闭 |
| gate queued send | 48 字节/stream | 已实现；验证前 CoroNet send HWM 固定为单个 challenge |
| cookie lifetime / key rotation | 10 秒 / 5 分钟 | 已实现且有界可配置；只接受当前/前一桶，rotation 必须是 lifetime 整数倍 |
| 单 IPv4 /32 pending | 8 | 已实现；关闭该来源的新连接 |
| 单 IPv6 /64 pending | 8 | 已实现；关闭该前缀的新连接 |
| 单来源 accept token bucket | burst 16、每秒恢复 4 | 已实现；IPv4 `/32`、IPv6 `/64`，耗尽立即拒绝 |
| 来源 token bucket table | 256 槽 | 已实现；固定 node-owned 数组，满载且无已补满桶可回收时立即拒绝 |
| preface + Noise timeout | 5 秒 | 已实现；terminal timeout |
| READY timeout | 2 秒 | 已实现；terminal timeout |
| 单 handshake frame | 4096 字节 | 已实现且可降低；超限关闭 |
| credential | 1024 字节 | 已实现且可降低；超限关闭 |
| 未认证 retained receive | 16 KiB/peer | 已实现；超限关闭 |
| 已认证 retained receive | 256 KiB/peer | 已实现；超限关闭 |
| 单 peer queued transport bytes | 1 MiB，最大可配置 64 MiB | 已实现；CoroNet send HWM，满时拒绝 |
| node admitted transport send capacity | 64 MiB | 已实现；按每条 transport 的 HWM 保守预留，额度不足即拒绝 |

已暴露的 frame、credential、timeout、单会话时长、单方向 byte limit、send HWM、node send budget、source burst/refill、bucket table limit、cookie gate/lifetime/rotation 都在启动时解析为有上限的固定配置；其中资源容量只允许选择默认值或更低值，cookie lifetime/rotation 还必须满足各自最大值和整数倍不变量。node budget 必须至少容纳一条 stream HWM；outbound transport 在 connect 前预留，inbound transport 只在 cookie 验证后预留，所有失败与 disconnect/destroy 路径幂等归还，满载返回 `RESOURCE_EXHAUSTED`。source bucket table 和 cookie gate 都是 node-owned 固定数组，不进行攻击者可驱动的动态分配；表满时拒绝。任何后续队列不得因重试而无界增长。

**计算**：gate 协议 payload 的硬上限是 `128 * (44 + 48) = 11,776` 字节；全部 gate 同时排队一个 challenge 时，P2P 配置的 CoroNet send 上限合计为 `128 * 48 = 6,144` 字节。该计算不包含操作系统 socket 和 CoroNet stream backend 的固定对象，因此公网容量规划仍需计入 accept backlog 与 backend 每连接开销。

**计算**：为每个 pending peer 预留最多 24 KiB（两个 4096 字节 frame、credential/codec scratch、backend state 和对齐余量），`128 * 24 KiB = 3 MiB`。node handshake arena 默认硬预算目标为 4 MiB；若 backend 实测对象使单 peer 预算超过 24 KiB，必须降低 pending 数或拒绝启动，不能突破总预算。默认 transport HWM 为 1 MiB、node send budget 为 64 MiB，因此同时拥有 transport 的 peer 最多 `floor(64 / 1) = 64` 个；把单流 HWM 调到 4 MiB 时，同一默认 node budget 自动把上限降为 16 个。

**事实**：CoroNet 公共 API 没有跨 backend 一致的“当前 retained send bytes”查询；内部 `send_queued` 在部分 backend 把 buffer 提交给内核后即扣减，不能作为 P2P 的跨平台事实源。因此当前 node budget 计量的是已接纳 transport 的最大可能发送容量，不冒充瞬时队列采样。它会保守拒绝大量空闲连接，但能避免“连接数 × 单流 HWM”无界增长。CoroNet `turbo_stream_destroy()` 是 transport 资源释放边界，P2P 在该边界后归还 reservation。

发送 backpressure：

- **事实**：`turbo_stream_send()` 成功时 CoroNet 拷贝并拥有 queued bytes；P2P 随后释放临时明文/密文，stream close 负责排空释放队列。
- **事实**：应用发送 API 在 HWM 满时立即返回 `RESOURCE_EXHAUSTED`。由于 Noise nonce 在 transport admission 前已经推进，该会话同时关闭，禁止在原 CipherState 上重试造成 nonce 错位。
- **目标**：若后续协议加入 `GOAWAY`，control frame 必须有独立的小型保留额度；若增加 awaitable send，必须有 deadline/cancel。
- handshake 不进入普通应用发送队列，单 peer 只保留当前状态所需的一个 inbound 和一个 outbound frame。

## 13. DoS 与公网暴露

**事实**：当前 accept 路径先执行 global pending、IPv4 `/32` / IPv6 `/64` pending 容量检查和跨连接 token bucket admission，再占用固定 cookie gate。验证 cookie 前不创建 accepted peer/4 KiB receive buffer、connection wrapper、Noise state，不预留 1 MiB 默认 stream HWM；只保留固定 gate slot，并把 gate stream send HWM 限为 48 字节。cookie 通过后再次检查 pending 容量并完成所有权转移。token bucket 使用单调毫秒时钟和整数额度，成功 accept 也消耗 token，不因认证成功返还。未知 version/suite/network、cookie 和证书失败均只对远端关闭，不发送详细原因。

**剩余公网目标**：

- 指标不记录完整 IP，日志按策略脱敏；同一来源失败采用有上限退避，成功认证不能无限增加 token。
- 在部署文档中明确操作系统 SYN backlog/SYN cookie、边缘防火墙与分布式限速责任；应用层 cookie 不冒充 TCP SYN flood 防护。
- 对 gate capacity、cookie protocol/expiry/auth、challenge 和成功验证建立采样指标与告警阈值。
- 未知 version/suite/network 的响应长度和处理路径保持不可用作高价值身份 oracle。

## 14. 密钥生命周期、轮换与撤销

### 14.1 本地密钥

- 生产配置不得在每次启动时生成新的静态身份。
- **事实**：`meshd` 的部署配置使用 `identity_private_key_file`；transport 与 management 私钥均经过同一严格适配器。POSIX 以 `lstat + O_NOFOLLOW + fstat` 拒绝链接/替换，要求 regular file、owner 等于 daemon euid 且 group/other 权限为零；Windows 对已打开 handle 拒绝 reparse/directory，并要求 owner 与所有 allow ACE 仅属于当前服务账户、LocalSystem 或 Administrators。无法判定的安全描述符 fail closed。
- **事实**：文件总输入上限为 4 KiB，只接受恰好 64 个 hex 字符（允许 ASCII 空白）；失败时输出清零。transport key 以借用的 32 字节缓冲传给 `mesh_create()`，P2P 完成复制后 daemon 立即擦除该缓冲，加载/复制失败不回退到临时身份。
- **兼容性**：management profile 已禁止 YAML 内联 `identity_secret_hex`；该字段仅保留给隔离开发/测试。`mesh_config_t` 新增 byte-key pointer/size，改变 C ABI 布局，所有 shared-library consumer 必须一起重编译。
- **事实**：`p2p_private_key_provider_v3_t` 已提供版本化的 opaque static-DH 边界：配置时查询 X25519 公钥，并用标准 basepoint 做一次 DH 自检以证明 provider 操作与声明公钥一致；握手时只提交远端公钥并接收 32 字节 shared secret。节点和每个 Noise-C handshake state 都不复制 provider 的私钥字节；provider context 由调用者拥有，直到 `p2p_destroy()` 返回。
- **事实**：provider 回调失败只允许保留 `CRYPTO`、`IO`、`TIMEOUT`、`RESOURCE_EXHAUSTED` 四类错误，其余值归一化为 `CRYPTO`；shared-secret 输出在失败和全零结果时清零。provider 安装失败保持旧身份不变，raw key、opaque provider、legacy inline key 在 Mesh 配置中严格互斥。
- **HIGH 约束**：当前 Noise-C `calculate` 是同步函数指针，调用发生在 CoroNet owner thread。V3 回调必须非阻塞且有确定上界，适合进程内 provider 和有界时延的 OS key service；阻塞式 TPM、网络 HSM 或用户确认流程不得接入 V3。
- **事实**：`p2p_blocking_private_key_provider_v4_t` 已实现阻塞 provider 边界：把包含 static DH 的完整 outgoing `write_message()` 转移给有界 worker，带 absolute deadline、cancel view、可选 SDK cancel、容量拒绝、owner-loop completion 和 shutdown drain；`p2p_node_get_private_key_executor_status_v4()` 提供容量与结果计数快照。Noise-C 本身仍没有异步 `calculate`/resume hook，因此没有在 owner thread 上等待 worker。
- **剩余 HIGH**：仍需至少一个真实 OS/TPM/HSM adapter、硬件 deadline/cancel/掉线演练、Linux/TSan 与独立安全审查；完成前不能对外宣称特定 TPM/HSM production-ready。
- raw-file 模式的私钥读入后只保存在必要的 node security context，禁止日志、core dump 字段和普通诊断 snapshot 暴露；opaque 模式的 provider 自行负责 context 的内存锁定、转储策略、访问审计与销毁。
- 所有 handshake ephemeral、chaining key、CipherState、本地 credential 临时缓冲在成功、失败、timeout 和 destroy 路径统一清零。

#### 14.1.1 Provider 所有权与状态转换

```text
UNCONFIGURED/raw ephemeral
  -> get_public_key() outside node mutex
  -> validate nonzero public key
  -> calculate_x25519(basepoint) outside node mutex and compare
  -> atomically replace node identity with copied ops + borrowed context
  -> CONFIGURED_OPAQUE
  -> per-handshake static DH callback on owner thread
  -> handshake success / typed terminal failure
  -> stop peers and drain managed coroutines
  -> wipe copied ops/public identity
  -> p2p_destroy() returns; caller may release context
```

配置只允许在 listener、peer 和 identity policy 尚未建立时发生。公钥查询不持 node mutex；查询后再次检查可变状态，避免回调期间启动网络导致半配置。回调不得保留 borrowed input/output，不得重入同一 node。V3 不拥有队列，也不接受无限 in-flight 工作；一个 handshake 同步占用 owner，故任何需要排队的 provider 必须直接返回 `RESOURCE_EXHAUSTED`，不能内部无界等待。

#### 14.1.2 V4 阻塞式 TPM/HSM executor

**事实**：当前 `turbo_stream` receive handler 是普通回调，`p2p_peer_on_data()` 在 owner thread 上同步解析并移动 peer receive buffer；它不是可以调用 `coro_when_*()` 的 coroutine。Noise-C 的 DH backend 也是同步函数指针，`noise_handshakestate_write_message()` 进入 static DH 后必须在同一调用中返回，错误会使该 handshake 进入 terminal failure，没有“返回 pending 后 resume token”的上游接口。

**推论**：只把 `calculate_x25519()` 丢到 worker、owner thread 等结果仍会阻塞事件循环；让 Noise-C 先返回再补 shared secret 则需要修改其内部 token/symmetric-state 状态机。两者都不能作为 V4。XX 模式每侧的长期 static private key 只用于本端最后一个 outgoing handshake message，因此可以把“整次 outgoing `write_message()`”作为独占 work item；该调用期间 handshake state 只归 worker，完成后才归还 owner。

V4 public provider 与 V3 分开版本化，没有改变 V3 的线程语义。当前公开契约为：

```c
typedef struct {
    size_t struct_size;
    int (*get_public_key)(void *context, uint8_t public_key_out[32]);
    int (*calculate_x25519)(void *context,
                            const uint8_t remote_public_key[32],
                            uint64_t monotonic_deadline_ms,
                            const p2p_private_key_cancel_v4_t *cancel,
                            uint8_t shared_key_out[32]);
    void (*request_cancel)(void *context);
    void *context;
    uint16_t executor_workers;
    uint16_t executor_capacity;
    uint32_t operation_timeout_ms;
} p2p_blocking_private_key_provider_v4_t;
```

`cancel` 是 P2P 拥有的只读取消视图，只提供原子查询，不把 node/peer 暴露给 provider。`request_cancel` 必须线程安全、幂等且非阻塞，用于打断支持取消的 TPM/HSM SDK；回调仍必须尊重 absolute monotonic deadline。P2P 无法安全终止任意阻塞线程，所以不接受“不保证返回”的 provider。超时后才返回的结果一律清零并转换为 `TIMEOUT`，不能提交已过期 handshake output。

每个 node 的 executor 是私钥状态与队列的唯一 owner：

```text
OWNER receives complete Noise frame
  -> run incoming Noise read on owner (does not use local static key)
  -> stop stream receive
  -> allocate one fixed-size operation and hold peer
  -> try_submit to bounded single-key worker
     queue full: wipe op -> release peer -> RESOURCE_EXHAUSTED -> close
  -> WORKER_OWNED_HANDSHAKE
  -> worker checks closing/cancel/deadline
  -> worker runs the complete outgoing Noise write_message
  -> wipe provider scratch
  -> coro_post(completion) to owner
  -> OWNER_COMPLETION
  -> reject stale generation / closing / timeout
  -> send bounded reply, advance noise_step, or close with typed error
  -> consume the exact input frame already retained by peer
  -> restart stream receive
  -> release peer and operation
```

同一 peer 最多一个 operation；peer 上的 operation pointer 与 `handshake_generation` 同时匹配才允许 completion 改状态，operation 另有单调 ID 用于诊断。worker 拥有 handshake state 时，owner 不得 split、destroy、timeout-cleanup 或再次解析该 peer；后到 socket bytes 由 `recv_stop` 留在 CoroNet/内核，不复制到另一条无界队列。completion 通过线程安全 `coro_post()` 回 owner；post queue 满时只重试到 operation deadline，最终拒绝则由 owner maintenance/shutdown pump 领取同一 completion，原子 owner-claim 防止重复提交。worker 不调用 stream、peer callback、identity policy 或日志 sink。

operation 在提交时固定捕获 handshake 指针，worker 不再从可变 peer 状态重新取指针。worker 必须先取得 completion-post 引用，再以 release store 发布 `completed`；否则 owner fallback pump 可能在两者之间释放 operation，形成 use-after-free。若 `coro_post()` 最终失败，worker 必须在记录 `completion_post_failures`、完成最后一次 node/operation 访问后才释放该引用，因为 owner fallback 可能并发释放 list 引用。owner 领取结果后同时校验 operation pointer、handshake generation 和 handshake pointer；任一不匹配都只丢弃旧 completion，不得发送旧帧，也不得 reset、split 或推进当前 handshake。

V4 默认资源 profile：

| 资源 | 默认/上限 | 满载行为 |
|---|---:|---|
| 每 node static-DH workers | 1 / 4 | 启动时拒绝越界配置；默认按单 key 串行 |
| queued + active operations | 64 / 128 | `try_submit` 失败并关闭该 handshake |
| 单 operation local credential | 1024 字节 | 复用 credential_limit；超限不提交 |
| 单 operation Noise output | 4096 字节 | 复用 handshake_frame_limit；超限失败 |
| 单 operation retained 总预算 | 6 KiB | 固定结构，不按远端长度增长 |
| 默认 operation deadline | 2 秒 | 复用或低于 handshake timeout |

**计算**：默认 `64 * 6 KiB = 384 KiB/node` retained operation payload，另加一个 worker stack 和 thread-pool 固定对象。若配置 128 个 operation，payload 上限为 768 KiB。实际结构一旦超过 6 KiB，必须降低容量或拒绝启动，不能只更新文档数字。worker pool 必须使用 `turbo_threadpool_create_with_config()` 和 `turbo_threadpool_try_submit()`；不得另写线程池或使用会等待队列空间的 submit。

Shutdown 顺序必须是：

```text
stop listener and new connects
-> mark executor closing
-> stop receive on peers with queued/active DH
-> reject queued-but-not-started operations without provider invocation
-> set every cancel token and call request_cancel once
-> drain/join workers (provider deadline is the hard upper bound)
-> consume or discard posted completions on owner
-> release peer holds and wipe operation buffers
-> destroy executor
-> destroy handshakes/peers/node/context
```

`turbo_threadpool_shutdown()` 会 drain，不能单独表达“取消尚未开始的业务任务”；因此 work item 开头必须检查 executor generation/closing，queued item 即使被 worker 取到也只完成取消清理。若 provider 超过声明 deadline 不返回，shutdown 可能无法完成，这是 provider 合同违约和发布阻断项，不得 detach thread 后释放 context。

V4 已完成的本地验证：

- fake blocking provider 的配置、自检 deadline、两端 XX static DH、运行期 deadline、active destroy cancel/drain 与容量拒绝；
- responder message 2 与 initiator message 3 分别覆盖 worker ownership；
- 默认容量的 64 个真实 Noise work item 全部接纳，第 65 个在 executor admission 边界返回 `RESOURCE_EXHAUSTED`；
- worker 完成后、owner dispatch 前替换 generation/handshake 的精确故障注入：旧 completion 不发送帧且不修改或清空替代 handshake；
- 填满 CoroNet post queue 后验证有界重试、fallback pump、late completion 转 `TIMEOUT`，不发送过期帧；
- CMake sanitizer 选项会实际传播到后续 vendor/product/test target；已核对 MSVC 编译命令包含 `/fsanitize=address`。加入 v3 security snapshot、Mesh 转发和 `meshd` JSON 回归后，本批重新通过 Windows Debug/ASan 全仓 67/67、Release 全仓 83/83，以及两种配置的 P2P 97/97（1418 assertions）、`test_mesh` 24/24（192 assertions）和 `test_meshd_runtime` 25/25（215 assertions）。`test_mesh` 曾暴露一个远端 TCP teardown 时序敏感断言，测试改为用公开 `mesh_disconnect_peer()` 驱动其真正要验证的 callback ordering 后，Release 过滤单例连续 10/10、Debug/ASan 与 Release 完整目标均通过。Windows 不支持 LeakSanitizer，此结果不包含 leak instrumentation；
- `submitted/completed/rejected/timed_out/cancelled/completion_post_failures`、active/queued/capacity/accepting 状态快照。

仍未通过的发布门：Linux epoll/ASan/TSan、真实 TPM/HSM 的 2 秒 deadline/cancel/设备掉线演练，以及独立审查。当前 Windows 主机未安装 WSL/Linux 发行版或 Docker；本地 Clang 21.1.1 的 target 是 `x86_64-pc-windows-msvc`，尝试构建三个 fuzz target 时由 CMake 按设计拒绝 clang-cl compiler-rt。因而 Linux sanitizer/libFuzzer 必须由 Linux CI 或独立构建机完成，不能用 Windows ASan 或 configure-time fail-fast 结果代替。V3 始终保持同步非阻塞语义；真实 adapter 通过这些门前，产品不得宣称“TPM/HSM production ready”。

### 14.2 轮换

Mesh principal ID 与 transport key 分离，因此 transport key 可以轮换而 managed node ID 不变：

1. Controller 提交新的 trust/policy epoch。
2. 为同一 managed node ID 签发绑定新 transport key、递增 serial/epoch 的证书。
3. 在有限重叠窗口内允许旧、新证书，但重复 peer 仲裁只保留新 epoch。
4. 节点切换 key 并建立 v2 session。
5. 确认全网收敛后撤销旧 serial/key；已有旧 session 收到 GOAWAY 并关闭。

任何时刻，一个 managed node ID 不得同时有两个相同 epoch 的有效 transport identity。

### 14.3 撤销

- Controller committed identity/policy epoch 是 Mesh trust 的事实源。
- 节点只消费签名、版本化的 immutable snapshot；Mesh provider 内的数组只是当前 snapshot 的有界本地副本，不是第二事实源。
- **事实**：raw P2P 的 owner thread 可调用 `p2p_node_update_pinned_trust_v2()`；新 key 数组在 swap 前完整复制，参数或分配失败不改变旧 snapshot，swap 后重验失败则断开全部 established session。
- **事实**：dedicated management runtime 的 owner thread 调用 `mesh_mgmt_agent_runtime_update_remote_trust_v2()`，在一个不可重入命令中完整替换远端 epoch/role/revocation 副本并立即调用 `p2p_node_revalidate_security_v2()`。P2P 对 peer 做有引用保护的 snapshot，不持 node mutex 调 provider，拒绝或身份变化均关闭会话并要求重新 Noise 握手；snapshot 分配失败时无分配地断开全部 established security session 后返回错误。
- **约束**：shared Mesh node 的策略归 Mesh runtime 所有，agent runtime 拒绝私自更新借用节点。issuer key 与 Mesh ID 在线不变，轮换它们需要协调重启。
- 时钟异常导致证书时间不可验证时 fail closed，并报告 clock health；不得忽略有效期。

## 15. Shutdown 与 drain

严格顺序：

```text
stop accepting new connections
-> reject new connect/send commands
-> wake/cancel blocked producers
-> close pending PREFACE/NOISE/READY sessions
-> mark established sessions DRAINING and send bounded GOAWAY
-> drain already accepted control writes until deadline
-> cancel pending recv and close CoroNet streams
-> release all borrowed receive buffers
-> wipe handshake/CipherState/private-key buffers
-> stop managed coroutines
-> destroy peer table, security provider snapshot and CoroNet context
```

- drain deadline 到期后强制关闭，不延长总 shutdown 时间。
- 回调中不得同步 destroy 自己仍在使用的 peer；沿用 event-loop command 延后释放。
- 每个状态都必须有独立 teardown fault-injection 测试，尤其是 pending recv、timeout 与跨线程 wake。

## 16. 错误语义与可观测性

### 16.1 类型化错误

内部安全错误至少区分：

```text
UNSUPPORTED_VERSION
UNSUPPORTED_SUITE
NETWORK_MISMATCH
DOWNGRADE_REJECTED
HANDSHAKE_TIMEOUT
BAD_HANDSHAKE
BAD_CREDENTIAL
UNTRUSTED_IDENTITY
REVOKED_IDENTITY
IDENTITY_CONFLICT
KEY_EXHAUSTED
FRAME_TOO_LARGE
AUTH_REQUIRED
RESOURCE_EXHAUSTED
CRYPTO_BACKEND_FAILURE
SHUTTING_DOWN
```

对未认证远端统一 close，避免错误 oracle；本地 API、metrics 和受控日志保留 stage 与映射后的原因。中间层不能恢复时直接向上返回，禁止记录错误后返回成功。

### 16.2 指标

- `p2p_security_handshake_total{role,result,stage,reason}`
- `p2p_security_handshake_duration_ms{role,stage}` P50/P95/P99
- `p2p_security_pending{scope}` 和拒绝计数
- `p2p_security_sessions{suite,auth_mode}`
- `p2p_security_rekey_total{direction,result}`
- `p2p_security_session_bytes/messages`
- `p2p_security_legacy_rejected_total`
- `p2p_security_trust_epoch` 与过期/撤销 session 数
- node send capacity budget、当前 reservation、可用量与拒绝次数
- source token bucket 配置、当前占用 bucket 数，以及 pending、rate、bucket capacity、send budget、handshake/session failure 和在线重验结果的类型化拒绝计数
- cookie gate 配置、当前占用槽、challenge/验证成功计数，以及 gate capacity/protocol/expired/auth 类型化拒绝计数
- 精确 send queue 当前/峰值 bytes（待 CoroNet 提供跨 backend 一致的 retained-byte 语义后接入）

**事实**：node 已按 initiator/responder 与 COOKIE/PREFACE/NOISE/READY 保存固定大小的
`count/sum/max + 12 buckets` 累计量；桶上界为 1、5、10、25、50、100、250、500、
1000、2500、5000 ms 和 `+Inf`。计数使用饱和加法，不保留逐次样本、peer ID、IP、
credential 或 handshake hash。peer/cookie gate 只保留当前阶段的单个 monotonic 起点，
阶段完成后由 node mutex 下的唯一累计事实源更新。`p2p_node_get_security_status_v3()`
现在在同一次 node mutex 临界区内复制 v2 capacity/rejection、可选 V4 executor 状态、桶
上界与全部 role/stage 累计量；调用者只得到不含指针的值快照。`mesh_get_security_status_v3()`
只做版本化转发和错误映射，`meshd` status-file 与 `/v1/status` 均导出同一有界 `security`
对象。

**计算**：累计量固定占用 `2 roles × 4 stages × (3 summary + 12 buckets) × 8 bytes =
960 bytes/node`；每个 peer 和每个 cookie gate 各增加一个 8-byte 起点。默认最多 128 个
cookie gate，因此 gate 起点预算为 1024 bytes/node。该容量与握手次数无关，没有队列、
逐请求 allocation 或 drain 工作；node 销毁时随 owner 一次释放。

日志只允许 principal/routing ID 的短 hash、role、state、版本、错误码和可操作建议；不得记录私钥、完整 credential、certificate body、session key 或完整 handshake hash。

### 16.3 查询 API

新增只读安全快照，至少提供：

- secure wire version 和 Noise suite。
- authenticated 标志和 auth mode。
- remote Noise static public key。
- principal ID、routing ID、credential digest、trust epoch、expiry。
- 32 字节 channel binding。
- session 建立时间、rekey count 和限额余量。

**事实**：`p2p_node_get_security_status_v2()` 已提供 node send budget、当前保守 reservation、可用 reservation、transport 数、source bucket 配置/占用、cookie gate 配置/占用/challenge/验证计数和类型化 admission 拒绝计数的值拷贝；`p2p_peer_get_security_info_v2()` 已提供 established peer 的会话身份、channel binding、frame/byte 计数与开始时间。精确 rekey count/限额余量仍待协议化 rekey 支持。

**事实**：新增的 `p2p_node_get_security_status_v3()` 保留 v2 API/布局不变，并把 v2
状态、V4 executor availability/status 与 960-byte 固定握手时延累计量组成一次原子值
快照。公开结构只包含配置、容量和聚合计数，不包含 private/shared/ephemeral key、credential、
principal/routing ID、IP、remote static key、channel binding 或逐握手样本。`meshd`
`snapshot_version=2` 表示新增顶层 `security`；原有 JSON 字段保持原名和语义。

调用者获得值拷贝，不获得 peer 内部指针。MMP/M3 必须在使用前要求 `authenticated == true`。

## 17. 与 Mesh/MMP/M3 的集成

### 17.1 MMP

当前 MMP 在 P2P 认证完成后发送签名 HELLO，并从同一次 authenticated security snapshot 取得远端 Noise static key 与 handshake hash：

1. Mesh identity provider 在 Noise message 2/3 payload 中完成相同证书验证。
2. P2P 只在验证成功后发布 peer。
3. MMP HELLO 暂时保留，作为应用协议版本、role、limits 和 signed management envelope 的确认；它必须与 P2P authenticated identity 完全一致。
4. MMP/1.1 HELLO 与 HELLO_ACK 都显式携带 Noise channel binding；它们受 payload hash 和 Ed25519 签名覆盖，并必须等于当前连接的 handshake hash，防止有效帧被转移到另一条连接。
5. 稳定后可删除 HELLO 中重复的完整证书，但这属于单独 MMP wire 版本变更，不与 Noise v2 首次上线捆绑。

### 17.2 M3 与其他上层

- M3 receipt、claims 和对象 CID 语义不变。
- M3/Mesh transport adapter 从 `p2p_peer_get_security_info_v2()` 读取已认证 principal、transport key 和 channel binding。
- 上层授权仍由 Mesh policy/MMP 决定；P2P 不把“证书有效”自动解释为可读写所有文件、对象或网络。
- relay 必须保持端到端 Noise session，或建立明确的逐跳身份模型；中继节点不得伪装成最终 peer。

## 18. 迁移、兼容性与回滚

### 18.1 不兼容项

- v2 preface、Noise frame 和 transport frame 与当前 wire 不兼容。
- v2 listener cookie challenge/response 是 mandatory wire 步骤，旧 v2 pre-cookie dialer 也不能连接；cookie binding 改变 Noise prologue 和 handshake hash。
- transport ciphertext 从显式 XChaCha counter 改为 Noise ChaChaPoly CipherState。
- peer 只有完成证书/pin 和 READY 后才会 connected，回调时序改变。
- routing ID 改为认证身份的确定性推导，现有 DHT bucket 会重建。
- 生产 node 必须配置稳定 private key、network ID 和 identity provider/trust snapshot。
- MMP/1.1 与 M3 adapter 都读取 channel binding；MMP/1.0 不含该字段，硬切换后不接受。
- MMP fixed prefix minor 从 0 切到 1；HELLO/ACK 分别新增必填 32-byte binding TLV，混合
  1.0/1.1 集群无法建立管理 session，必须和 secure-wire v2 一起协调升级或全网回滚。
- 本次 hard cut 扩展了公开 `p2p_security_config_v2_t`、`p2p_node_security_status_v2_t` 和 rejection reason 数组；依赖 exact `struct_size` 的旧 binary 会 fail fast，所有 C consumer 必须与新头文件一起重编译。

DHT value key、文件内容 hash 和 M3 CID 不因 routing ID 变化而改变；但 DHT placement/replication 会重新收敛，切换前必须预热或允许可控重发布窗口。

### 18.2 已选迁移策略

#### A. 全网 v2 硬切换（已批准并实现）

- 一个 release 将 listener 和 dialer 全部切到 v2。
- 升级前分发 key、证书、network ID 和 trust snapshot。
- 维护窗口内停止旧节点、升级全体、重建 DHT/连接。
- 任一旧节点连接都会得到 legacy rejected；无协议降级。
- 回滚必须全网回滚到旧版本，并恢复旧配置快照。

优点是代码和安全边界最简单；代价是需要协调停机窗口。

#### B. 双 listener/独立网络灰度（未采用）

- v2 使用独立端口或明确的 network profile；旧协议保留在旧端口。
- 两个 listener、peer table 和路由域逻辑隔离，禁止把 v2 凭据转给 legacy peer。
- 配置明确指定拨号协议，不探测、不 fallback。
- legacy 端口有删除日期、独立告警和流量指标；达到门槛后关闭。

优点是可逐节点灰度；代价是部署、路由和运维复杂度更高，过渡期仍保留旧协议风险。

### 18.3 明确禁止

- 同一端口读失败后“试试 legacy”。
- v2 认证失败后自动新建旧连接。
- 为兼容旧节点而在 v2 中 accept-any。
- 两种协议共享同一个“已认证”标志或上层安全等级。

## 19. 验证门槛

### 19.1 单元与向量

- Noise 官方/选定 backend 的 XX 固定向量。
- prologue、routing ID、session ID 和 canonical codec 固定向量。
- cookie HMAC 固定向量、IPv4/IPv6 来源绑定、preface/MAC 篡改、当前/前一/过期/未来时间桶和 derived-key rotation 边界。
- 每个 M1/M2/M3 byte bit-flip 均失败。
- static substitution、wrong role、wrong network、wrong suite/version 均失败。
- credential 空/短/长/畸形、证书 key mismatch、签名错误、过期、撤销、旧 epoch 均失败。
- READY 缺失、篡改、身份不一致和 channel binding 不一致均失败。
- nonce/rekey 前一帧、边界帧、后一帧和 exhaustion。

### 19.2 状态与资源

- 所有合法/非法状态转移，重复调用和重入拒绝。
- partial/coalesced read，0/1/max/max+1 frame。
- global/per-source pending 上限、token bucket、timeout 和 queue full。
- cookie gate 满载、partial/oversized packet、验证前 peer/send-budget 零占用、timeout/stop/destroy drain。
- 任何阶段断开、allocator failure、RNG failure、backend failure。
- 每个失败路径验证 borrow 已释放、secret 已 wipe、peer 未发布。
- 三节点同时双向拨号按 routing ID 顺序收敛为每对一个 surviving connection；断开并双向重连后仍无重复身份，且新 Noise transcript 产生不同 channel binding。
- trust snapshot 更新关闭 revoked session。

**事实**：`test_p2p_three_node_hard_cut_simultaneous_dial_and_reconnect` 使用三个真实 loopback listener，在两个相邻节点对上先排队双向拨号再驱动各自 CoroNet owner loop；Windows Debug/ASan 与 Release 均通过。该测试还保持第三条独立会话在线，验证一对节点断开、双向重连和精确身份计数。

### 19.3 集成与安全

- Linux 与 Windows 两节点互操作。
- DHT put/get、文件 transfer/resume、Pub/Sub/custom message 全回归。
- Mesh MMP certificate/channel binding、M3 chunk/receipt、relay 路径回归。
- legacy client 到 v2 listener 必须拒绝，且无 fallback；仓库 fixture 会通过独立 CoroNet TCP coroutine 发送旧版原生 8 字节 header、legacy handshake type 和 32 字节 M1，断言无响应、cookie protocol rejection、零 gate 泄漏及零 peer 发布。
- 对 preface、frame codec、Noise payload wrapper 和 credential decoder 持续 fuzz。
- ASan、UBSan（支持平台）、TSan 和 CoroNet shutdown regression。
- 与独立 Noise 实现交叉互操作，避免双方共享同一 bug 仍通过测试。

仓库提供互斥的 Linux Clang sanitizer presets。Linux 构建机必须提供
`VCPKG_ROOT`，并通过 `CMAKE_PREFIX_PATH` 或 configure 参数
`-DTURBO_UTILS_ROOT=... -DTURBO_NET_ROOT=... -DTURBO_HTTP_ROOT=...` 指向已构建的
TurboUtils、TurboNet 与 TurboHttp；preset 不下载或猜测这些内部依赖：

```bash
cmake --preset security-linux-clang-asan
cmake --build --preset build-security-linux-clang-asan
ctest --preset test-security-linux-clang-asan

cmake --preset security-linux-clang-tsan
cmake --build --preset build-security-linux-clang-tsan
ctest --preset test-security-linux-clang-tsan
```

ASan preset 固定启用 ASan、UBSan 与 LSan；TSan preset 只启用 TSan。CMake 在
configure 阶段拒绝 TSan+ASan/LSan/MSan、MSan+其他 sanitizer、非 Clang
MSan，以及 MSVC 上除 ASan 外的 sanitizer 请求，禁止产生名称与实际
instrumentation 不一致的构建。

当前仓库提供三个 opt-in libFuzzer target：

- `fuzz_p2p_cookie`：覆盖 secure preface、cookie challenge/response codec、来源地址、时间和轮换配置边界，单输入硬上限 256 字节；
- `fuzz_p2p_message`：覆盖 application v2 header、所有结构化 payload decoder 和 decode→encode canonical byte identity，单输入硬上限 65519 字节；
- `fuzz_p2p_noise_read`：每轮从固定密钥重建完整 XX 状态，分别把输入送入 M1/M2/M3 read 边界，单输入硬上限 `P2P_SECURITY_HANDSHAKE_FRAME_MAX + 1`。

target 只在 `TURBOP2P_BUILD_FUZZERS=ON` 时创建，并要求 Linux/Unix Clang；默认 Windows/MSVC/clang-cl 构建不携带 fuzz instrumentation。可复验入口为：

```bash
cmake --preset security-linux-clang-fuzz
cmake --build --preset build-security-linux-clang-fuzz
cmake -E make_directory \
  build/linux-clang-fuzz/corpus/cookie \
  build/linux-clang-fuzz/corpus/message \
  build/linux-clang-fuzz/corpus/noise-read \
  build/linux-clang-fuzz/artifacts
build/linux-clang-fuzz/bin/fuzz_p2p_cookie \
  -max_len=256 \
  -max_total_time=600 -timeout=10 -rss_limit_mb=2048 \
  -artifact_prefix=build/linux-clang-fuzz/artifacts/ \
  build/linux-clang-fuzz/corpus/cookie
build/linux-clang-fuzz/bin/fuzz_p2p_message \
  -max_len=65519 \
  -max_total_time=600 -timeout=10 -rss_limit_mb=2048 \
  -artifact_prefix=build/linux-clang-fuzz/artifacts/ \
  build/linux-clang-fuzz/corpus/message
build/linux-clang-fuzz/bin/fuzz_p2p_noise_read \
  -max_len=4097 \
  -max_total_time=600 -timeout=10 -rss_limit_mb=2048 \
  -artifact_prefix=build/linux-clang-fuzz/artifacts/ \
  build/linux-clang-fuzz/corpus/noise-read
```

fuzz support library、Noise-C 和 target 均使用 `fuzzer-no-link,address` instrumentation，最终 executable 以 `fuzzer,address` 链接。一次固定 `-runs=N` smoke 只证明 target 可执行，不满足“持续 fuzz”发布闸门；CI 必须持久化/合并 corpus、设置时间预算、保存 crash artifact，并把任何 crash、timeout 或 OOM 作为失败。

### 19.4 发布闸门

以下条件全部满足前，README 和产品计划不得宣称“生产级身份认证”：

- backend 依赖准入完成并固定版本。
- 官方向量、互操作、fuzz、sanitizer、跨平台测试通过。
- 两种身份模式的失败语义和运维手册完成。
- key 初始化、权限、轮换、撤销和恢复演练完成。
- 选定迁移策略经过至少三节点、同时拨号、断网重连和旧节点测试；仓库 fixture 通过后，发布环境还必须用归档旧版 binary 复验真实部署与运维行为。
- 独立安全审查关闭所有 HIGH 问题。

## 20. 实施状态与后续阶段

1. **N0：依赖固定——部分完成**
   suite、commit、许可证、Windows/MSVC 构建和 Noise-C 上游锁定版本固定向量已完成；Linux sanitizer 与独立审计未完成。
2. **N1：内部 backend——完成基线**
   opaque adapter、平台 X25519/RNG、密钥清零、CipherState 边界测试和 XX 固定向量已接入。
3. **N2：secure wire v2——完成基线**
   preface、bounded handshake frame、XX、CipherState、READY 和 legacy 拒绝已硬启用，无 feature flag/fallback。
4. **N3：身份 provider——完成基线**
   pinned 与 Mesh certificate provider、认证后 peer 发布、routing ID 和重复身份仲裁已接入。
5. **N4：上层绑定——完成基线**
   MMP/1.1 HELLO/ACK 与 M3 chunk v2 都使用 Noise channel binding；MMP adapter 从单一认证快照注入 signer/session，跨会话 HELLO/ACK replay 和旧 schema 均有 fail-closed 回归测试。
6. **N5：资源与可观测性——部分完成**
   fixed listener cookie gate、source-bound HMAC cookie/derived-key rotation/Noise prologue binding、per-source pending 与 token bucket、单流 send HWM、node 聚合 send-capacity reservation、会话 frame/age/byte limits、只读会话计数、node capacity snapshot、类型化 cookie/admission/handshake/session/revalidation 原因计数、按角色/阶段的固定桶握手时延聚合、原子 v3 security/executor snapshot、Mesh 转发和 `meshd` JSON、严格 daemon 私钥文件边界、同步 opaque X25519 provider API、有界 blocking provider executor/status，以及 dedicated runtime 在线 trust update/revalidation command 已完成；仍需完成公网 SYN/backlog/边缘限速运维基线和具体 OS/TPM/HSM adapter。
7. **N6：验证与部署——部分完成**
   已加入 cookie、application v2 message 与 Noise M1/M2/M3 read 的有界 libFuzzer target，以及互斥、带单测 timeout 的 Linux Clang ASan/UBSan/LSan、TSan 和 fuzz presets；MSVC 对不支持 sanitizer 及冲突组合的 configure-time fail-fast 已验证。Windows 本地三节点同时双向拨号、断线重连、唯一身份收敛、新 channel binding，以及旧 wire M1 到 v2 listener 的静默拒绝均已通过 Debug/ASan 与 Release。当前主机没有 Linux 环境，因此 Linux presets 尚无运行结果；仍需在 Linux CI 建立持续 corpus 运行，并完成归档旧版 binary 部署演练、跨平台/独立实现互操作和独立安全审查。

## 21. 回滚方案

- secure wire v2 已硬启用，不存在进程内 feature flag 或 legacy listener 回滚。
- 只能协调全网回滚到切换前 binary 与配置快照；任何已建立 v2 连接都不能原地降级。
- transport key 文件不得被回滚流程隐式覆盖；迁移工具只做显式、可审计复制。
- routing ID 重建失败不影响内容 hash/CID，但需要恢复旧节点配置和重新发布 DHT provider records。

部署前置检查、信任/身份轮换、撤销、告警、事件处置、停机与发布证据包见
[`SECURITY_OPERATIONS.md`](SECURITY_OPERATIONS.md)。该手册只描述当前 API 可执行的
流程；`meshd` 已接入的聚合安全 snapshot 与尚未完成的外部验证仍明确分开。

## 22. 官方参考

- [Noise Protocol Framework, Revision 34](https://noiseprotocol.org/noise.html)
- [Noise Protocol Framework 主页与实现列表](https://noiseprotocol.org/)
- [NoiseSocket specification](https://noiseprotocol.org/specs/noisesocket.html)
- [libp2p Noise specification](https://github.com/libp2p/specs/blob/master/noise/README.md)
- [Noise-C reference implementation](https://github.com/rweather/noise-c)
- [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)

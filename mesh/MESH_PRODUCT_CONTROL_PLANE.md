# Mesh 产品控制面、身份与 Grants 设计

## 文档状态

本文定义面向用户的目标产品层，不表示当前代码已经实现这些能力。当前实现状态仍以
[`MESH_STATUS.md`](MESH_STATUS.md) 为准；网络平台边界见
[`MESH_PLATFORM_DESIGN.md`](MESH_PLATFORM_DESIGN.md)；节点间管理协议见
[`MESH_MANAGEMENT_PROTOCOL.md`](MESH_MANAGEMENT_PROTOCOL.md)。

本文不修改当前 `mesh_config_t`、packet wire format 或 MMP/1 wire format。所有新接口和
格式在实现前仍需独立 API/protocol review。

## 产品定义

目标产品是身份驱动、策略控制、可审计的 Mesh overlay：

- Controller 提供用户、设备、策略、审批、API、CLI 和审计查询。
- `mesh-agent` 负责节点注册、证书、MMP、期望状态和 `meshd` supervisor。
- `meshd`/Mesh core 负责 TUN、path、route、packet policy 和本地执行。
- 数据流不经过 Controller；Controller 故障不能成为已建立数据流的转发依赖。
- Gossip 用于成员和已签名状态的最终收敛，不承担用户认证或 consensus。

这属于 SDN-like control/data plane 分离，但不是 OpenFlow 式中央逐流编程。Controller
发布身份和网络意图，各节点在本地编译快照约束下选择路径并执行策略。

## 候选方案与取舍

| 方案 | 优点 | 主要问题 | 结论 |
|------|------|----------|------|
| 把用户、OIDC、策略和 UI 全部嵌入 `meshd` | 部署单元少 | 数据面与产品状态耦合；`meshd` 停止后无法管理；扩大 privileged attack surface | 不采用 |
| 只有中央 Controller，没有独立 agent/MMP | 全局状态和 UI 简单 | Controller/网络分区时无法恢复 `meshd`；边缘节点没有自治管理入口 | 不采用 |
| 完全分布式 Gossip 管理，无 Controller 事实源 | 无中央服务 | user/group、审批、policy epoch 和审计查询难以给出单一事实；Gossip 不是 consensus | 不采用 |
| TurboP2P 仓库同时实现 Controller/UI/database | 单仓库交付 | 破坏 networking-only 边界，引入 HTTP/OIDC/storage 类型和发布周期耦合 | 不采用 |
| 独立产品 Controller + `mesh-agent`/MMP + 本地 enforcement | 数据路径无中央瓶颈；可管理；分区时保留自治；仓库边界清楚 | 新增服务、证书、数据库和部署运维 | 采用 |

权衡如下：

- **性能**：packet 热路径只读取预编译 immutable snapshot；Controller、selector 展开、签名
  和 audit export 不在 owner-loop packet path。代价是节点持有额外 agent 和有界 cache。
- **复杂度**：增加 Controller、signer、agent 和两阶段 policy rollout；通过单一事实源、类型化
  模块和明确状态机约束复杂度，不建立通用 workflow/plugin engine。
- **可维护性**：TurboP2P 只维护网络安全语义和协议；产品服务维护用户/API/UI。typed schema
  和 golden vectors 是两者契约，第三方 HTTP/database 类型不穿透 Mesh core。
- **迁移成本**：中高。需要新 executable/service、secure storage、证书、policy compiler、
  Controller 和审计 sink，但可以从 read-only inventory 与 shadow policy 分阶段上线。

## 用户可见行为

### 首次加入

1. 用户安装并启动 `mesh-agent`。
2. agent 本地生成 machine、management、management-transport 和 data-node key；private
   key 不离开节点。
3. 用户通过一次性 enrollment URL/code 完成 OIDC 登录，或服务器使用有 scope、TTL 和
   single-use 约束的 deployment token。
4. Controller 创建 `PENDING_APPROVAL` device，不向其签发 ACTIVE node certificate。
5. 管理员或预审批规则批准 device，Controller 签发有 expiry、roles、tags 和 mesh binding
   的 certificate。
6. agent 收到当前 policy bundle 和允许可见的 peer descriptors，验证后进入 ACTIVE。
7. `meshd` 只有在 agent ACTIVE 且 production policy 有效时才加入 production Mesh。

用户不复制 peer 公钥、不编辑每台机器的路由，也不需要为普通节点开放公网入站端口。

### 日常管理

用户至少能完成：

- 查看 device 的 owner、tags、虚拟 IP、版本、key expiry、last seen 和当前状态。
- 区分 direct、relay、exit 和 subnet-router path，并看到选择原因。
- 批准、暂停、撤销、重新认证或轮换 device identity。
- validate、test、diff、发布和回滚 policy。
- 分别批准“发布 subnet/exit”和“使用 subnet/exit”。
- 查询谁在何时改变了 policy、设备或服务，以及节点离线是命令结果还是故障检测。
- 导出 configuration audit 和 flow metadata 到外部 append-only/SIEM sink。

### 状态不能混用

| 维度 | 状态 | 含义 |
|------|------|------|
| enrollment | PENDING、ACTIVE、EXPIRED、REVOKED | 是否被授权加入 |
| liveness | ONLINE、SUSPECT、OFFLINE、LEFT | agent 可达性观测 |
| service | RUNNING、STOPPED、DEGRADED、UNKNOWN | `meshd` 实际状态 |
| policy | CURRENT、STALE、REJECTED、MISSING | 本地执行快照状态 |
| path | DIRECT、RELAY、UNAVAILABLE | 当前数据路径 |

例如 OFFLINE 不等于 REVOKED，STOPPED 不等于 agent 离线。故障探测不能自动撤销设备，
证书撤销也不能伪造“某管理员关闭了节点”的审计结论。

## 总体架构与依赖方向

```text
OIDC / CI / GitOps
        │
        ▼
┌──────────────── Product Controller ────────────────┐
│ identity registry │ policy authoring │ approvals   │
│ API/CLI/UI        │ audit index      │ signer/HSM  │
└───────────────────────┬────────────────────────────┘
                        │ signed immutable bundles / RPC
                        ▼
┌──────────────── MMP management overlay ────────────┐
│ mesh-agent ─ mesh-agent ─ mesh-agent ─ mesh-agent  │
│ membership │ anti-entropy │ command │ audit anchor │
└────────┬────────────┬────────────┬────────────┬─────┘
         │ local IPC  │            │            │
         ▼            ▼            ▼            ▼
       meshd        meshd        meshd        meshd
         └──────── encrypted Mesh data plane ────────┘
```

依赖方向固定为：

```text
Controller/UI -> product API adapter -> signed policy/enrollment protocol
mesh-agent -> MMP codec + policy verifier + supervisor adapter
meshd -> compiled policy snapshot + Mesh core
Mesh core -X-> Controller database/UI/OIDC/HTTP types
```

TurboP2P 仓库负责 MMP schema、identity verifier、policy semantics/compiler、执行快照和
agent integration contract。OIDC、Web UI、Controller database、HTTP API hosting 和 SIEM
connector 属于独立产品服务，可复用 TurboHTTP，但不成为 `TurboP2P::Mesh` 依赖。

## 单一事实源

| 状态 | 唯一事实源 | 节点侧派生数据 |
|------|------------|----------------|
| user/group | configured IdP；Controller 保存带 sync generation 的只读快照 | bundle 中已展开 selector |
| device tags/owner | Controller device registry | certificate 与 selector snapshot |
| device enrollment | Controller device registry | signed node certificate |
| trust root | 本机部署配置 | verified issuer view |
| node private keys | 对应节点 secure storage | public certificate/descriptor |
| policy source | Controller policy store | signed compiled policy bundle |
| policy execution | `meshd` immutable snapshot | decision、counter、audit event |
| membership | 各 agent self record + SWIM observations | Controller/UI device view |
| `meshd` process state | OS service manager | agent reconcile result |
| audit entry | 产生事件的节点/Controller | index、export、signed checkpoint |

Controller 不能根据 UI cache 反写 device 或 policy；agent 不能独立修改 policy epoch；Mesh
core 不能从日志重建授权状态。

## 密钥与身份层级

### Key hierarchy

| key | 算法/用途 | 生命周期 | 是否分发 |
|-----|-----------|----------|----------|
| offline root | Ed25519 trust anchor | 年级；离线/硬件保护 | 只分发 public root |
| enrollment issuer | Ed25519 签发 node/operator cert | 月级；可轮换/撤销 | public chain |
| machine key | Ed25519 device continuity proof | 安装级；secure storage | public key 给 Controller |
| management key | Ed25519 MMP 端到端签名 | node cert 生命周期 | certificate 中选择性分发 |
| management transport key | X25519 adjacent channel identity | node cert 生命周期 | certificate 中选择性分发 |
| data node key | X25519 端到端数据身份 | 可轮换 node epoch | 只给允许通信的 peer/relay |
| ephemeral handshake key | X25519 每连接临时 ECDH | session 级 | 仅 handshake public key |
| traffic keys | KDF 派生 tx/rx AEAD key | session/path epoch | 永不分发 |

machine key 证明“仍是同一安装实例”，不直接加密业务流量。management 和 data key 分离，
避免 management compromise 自动变成数据面 impersonation。session 建立只交换 public
material；private key、traffic key、deployment token 和 disablement secret 禁止进入
Gossip、日志、状态 API 或 crash report。

当前 P2P identity 和 ephemeral handshake key 已切换为 TurboUtils checked OS CSPRNG；
熵源失败会终止 identity 创建或握手，不再静默留下未初始化 key。Controller、agent 和未来
signer 也必须复用同一 CSPRNG 失败语义，禁止自行增加 time/PID/`rand()` fallback。

当前 DHT join-ring 的 bootstrap 临时路由 ID 已由 endpoint 稳定派生，而非弱随机数
（[`node.c`](../p2p/src/core/node.c#L417)）。该 ID 只用于认证完成前的临时路由定位，不能作为
节点身份、授权主体或证书 binding；控制面必须继续以已认证 public key/node certificate 为准。

production enrollment issuer 必须在独立 signer/HSM 或等价隔离边界内，Controller 只能
提交有审计的 signing request，不能读取 issuer private key。仅攻陷 Controller API、但未
攻陷 signer policy 时，攻击者不能签发任意节点；若 online issuer 本身失陷，系统不能声称
仍安全，必须依靠 issuer revoke、短证书 TTL、节点侧 trusted-signer policy 和可选 quorum
限制影响范围。

### Public-key distribution

裸公钥不是授权事实。可连接描述符必须包含：

```text
mesh_id + managed_node_id + virtual_ip + public_keys + key_epoch +
roles/tags + allowed_scopes + endpoints + issued_at + expires_at +
issuer + certificate_signature
```

Controller 只向策略允许的节点分发 data-plane peer descriptor。relay 只获得完成下一跳
转发所需的 descriptor，不获得端到端 traffic key。MMP agent membership 可以知道节点存在，
但“存在”不自动授予 data-plane public key、路由或连接权限。

Gossip 可以转发完整、已签名 certificate/record，但接收端必须从本机 trust root 验证；
DHT 命中、裸 key、hostname、虚拟 IP 或低 RTT 都不能成为信任依据。

### Session establishment

目标握手流程：

```text
resolve signed peer descriptor
-> validate mesh/node/key epoch and policy visibility
-> authenticated ephemeral X25519 handshake
-> bind origin + destination + protocol + capability + session epoch
-> KDF derives independent tx/rx keys
-> key confirmation
-> enable replay window
-> publish usable path
```

握手失败、证书过期、key epoch 不一致或 capability downgrade 必须 fail closed。不能回退到
未认证 raw selected-pair transport。重连、node key rotation、path security context 重建，
以及配置的 time/byte limit 都会建立新 session epoch；旧 epoch packet 不能进入新 session。

### Rotation 与 revocation

- node rotation request 同时包含 old-key proof 和 new public key；Controller 签发更高
  `node_epoch`，旧 key 在有界 overlap 后失效。
- old key 丢失时必须重新 enrollment，不能只凭 node name 或 virtual IP 恢复身份。
- revoke 是 immutable signed record，包含 node/key epoch、reason code、effective time 和
  authority signature。
- Controller 对在线 agent 使用 targeted push/RPC，MMP Gossip/anti-entropy 负责遗漏补齐。
- 本地收到有效 revoke 后立即停止新 session、删除 peer descriptor，并按 policy
  terminate 或 drain 既有 flow。
- 管理分区期间无法保证全网瞬时撤销；UI 必须显示每个节点确认的 policy/revocation epoch，
  不能只显示“revoked”而隐藏 enforcement lag。

## Grants 与安全策略

### 分层模型

策略不是单一万能规则表，而是四个类型化层次：

1. **Enrollment policy**：谁能注册、是否需要审批、可取得哪些 tags/roles、证书 TTL。
2. **Network grants**：source identity 可以访问哪些 node/service/CIDR、protocol 和 port。
3. **Route grants**：谁能 advertise subnet/exit，谁能通过哪个 route/exit。
4. **Management grants**：谁能 observe、restart、reconcile、发布 policy 或管理 exit。

硬安全 guardrail 位于所有 grant 之前，不能被普通 allow 覆盖：identity/source binding、
anti-replay、metadata/management range、invalid fragment、capability 和 local break-glass policy。

### 决策语义

- production policy 使用 allow-only Grants；无匹配 grant 即 deny。
- deny guardrail 优先于所有 grant，不依赖文件顺序。
- 同类 grant 是集合并集，不使用跨文件 first-match；冲突或歧义在编译期拒绝。
- direction 是单向的；`A -> B` 不隐含 `B -> A`。
- advertise route、use route 和 administer route 是三个独立 capability。
- user/group/tag 只在 Controller 编译时解析；packet 热路径只比较稳定 node ID、prefix、
  protocol、port 和预编译 rule ID。
- domain policy 由受控 DNS resolver 产生带 flow correlation 的派生 decision，不能只靠
  观察 UDP/TCP 53 或 SNI 猜测授权。

### Authoring example

以下 JSON 是目标 authoring schema 示例，不是当前 `mesh_config_t` 输入：

```json
{
  "schema_version": 1,
  "mesh_id": "production",
  "base_epoch": 42,
  "security_profile": "production",
  "groups": {
    "media-operators": ["user:alice@example.com"],
    "network-admins": ["user:netops@example.com"]
  },
  "network_grants": [
    {
      "id": "media-control",
      "src": ["group:media-operators"],
      "dst": ["service:turbomedia-control"],
      "ip": ["tcp:8443"]
    }
  ],
  "route_grants": [
    {
      "id": "use-eu-exit",
      "src": ["tag:managed-client"],
      "via": ["node:eu-exit"],
      "dst": ["cidr:0.0.0.0/0"],
      "capabilities": ["route.use"]
    }
  ],
  "management_grants": [
    {
      "id": "media-observe",
      "src": ["group:media-operators"],
      "target": ["tag:media-node"],
      "capabilities": ["mesh.observe", "mesh.diagnostics"]
    }
  ],
  "tests": [
    {
      "name": "media operators reach control only",
      "src": "user:alice@example.com",
      "accept": ["service:turbomedia-control:tcp:8443"],
      "deny": ["service:turbomedia-control:tcp:22"]
    }
  ]
}
```

所有 selector 必须解析为至少一个对象，除非规则显式声明 `allow_empty = true`。未知字段、
未知 capability、重复 rule ID、非法 CIDR/port、循环 group、无 owner tag 和空 production
policy 都是编译错误。

### Compile and publish transaction

```text
parse external format
-> normalize typed document
-> resolve identity/group/tag snapshot
-> apply immutable guardrails
-> compile network/route/management tables
-> static analysis and policy tests
-> calculate canonical hash and create PREPARED candidate
-> isolated signer signs candidate hash + proposed next epoch
-> compare-and-swap base epoch
-> atomically install signed bundle + new current epoch + audit diff
-> distribute desired state
-> agents verify and stage
-> activate at not_before/epoch
-> report applied/rejected status
```

signing 不能发生在持有数据库锁的事务内。若 compare-and-swap 发现 base epoch 已变化，
PREPARED candidate 和其签名不成为 current，调用方必须重新 diff/compile；签名不能套用到
其他 epoch 或 payload。Controller database transaction 是 policy source、epoch 和 audit diff
的唯一提交点。任何节点拒绝 bundle 都不会让 Controller 悄悄改写 bundle；UI 显示 partial
rollout，并允许发布新的更高 epoch 修复或回滚。回滚是重新发布旧语义内容的新 epoch，
不倒退 epoch。

### Existing policy compatibility

当前 `mesh_packet_policy_allows()` 在完全无规则或当前 direction 无规则时保持 allow；配置了
当前 direction 后，无匹配规则才 deny（[`mesh.c`](src/mesh.c#L1076)）；公开配置仍是
有顺序的 rule array（[`turbo_mesh.h`](include/turbo_mesh.h#L101)），并有方向/端口回归测试
（[`test_mesh_paths.c`](tests/test_mesh_paths.c#L1818)）。目标迁移不能静默改变旧用户：

- `security_profile = compat` 保留当前 `mesh_config_t`、first-match 和 permissive empty 行为。
- `security_profile = production` 要求有效 signed compiled bundle，并默认 deny。
- 每个 profile 只允许一个 policy 事实源：compat 使用本机静态配置；production 使用 signed
  bundle，本机只保留 trust root、不可放宽的 guardrail 和 break-glass 设置。production
  同时配置静态 packet/peer/route allow 与 signed bundle 时启动失败，不做隐式合并。
- Controller compiler 可以把 Grants 编译为内部 snapshot，但不能依赖旧数组顺序表达
  guardrail。
- production bundle 先以 observe-only 计算 shadow decision，再显式切 active。
- 旧 API 保持不变；新 snapshot/decision API 采用 additive capability 和版本化 opaque handle。

## Controller 产品接口

### Authentication 与 RBAC

- 人类用户通过外部 OIDC/OAuth2/SAML IdP 登录；Controller 不保存用户密码。
- CI 使用短期 workload credential，不使用永久管理员 API key。
- API authorization 使用独立 product roles：viewer、device-admin、network-admin、auditor、
  owner；它们再映射到 management capabilities。
- 所有 mutation 必须携带 actor、request ID、idempotency key 和 expected/base epoch。
- owner/trust operation 要求 step-up authentication；MMP/1 仍不提供远程 trust-root 修改。

### Resource API

目标资源边界：

| resource | read | mutation |
|----------|------|----------|
| `/v1/meshes/{mesh}/devices` | list/detail/status/epochs | approve、expire、revoke、retag |
| `/v1/meshes/{mesh}/network` | IPv4/IPv6 prefix、DNS suffix、IPAM 状态 | 更新网络参数、保留地址 |
| `/v1/meshes/{mesh}/dns` | A/AAAA/PTR/alias 记录与 rollout | validate、publish、remove alias |
| `/v1/meshes/{mesh}/policy` | source/compiled/diff/status | validate、publish、rollback |
| `/v1/meshes/{mesh}/routes` | advertised/approved/active | approve/revoke advertise/use |
| `/v1/meshes/{mesh}/services` | registry/health | publish policy intent |
| `/v1/meshes/{mesh}/operations` | command/result | restart、reconcile、diagnostics |
| `/v1/meshes/{mesh}/audit` | filter/page/export status | configure authorized export |

mutation 使用 `If-Match`/base epoch 防止并发覆盖；重复 idempotency key 返回相同结果。API
返回 stable error code、field path、current epoch 和 correlation ID，不依赖日志文本表达失败。
Controller 只向 agent 发送类型化 MMP command，永不拼装 shell/argv。

### CLI surface

```text
meshctl devices list
meshctl devices approve <device>
meshctl devices revoke <device> --reason <reason-code>
meshctl network show
meshctl network set-prefix --ipv4 <cidr> --ipv6 <cidr>
meshctl dns assign <device> --name <name> [--ipv4 auto] [--ipv6 auto]
meshctl dns records
meshctl policy validate <file>
meshctl policy test <file>
meshctl policy diff <file>
meshctl policy apply <file> --base-epoch <epoch>
meshctl routes list
meshctl exit approve <node>
meshctl exit grant-use <selector> --node <node>
meshctl audit tail --actor <id> --action <action>
meshctl diagnose <node> --profile network-basic
```

CLI 默认显示 plan/diff，高风险操作要求显式确认或 CI 的 `--non-interactive` + expected epoch。
secret、private key 和 token 不出现在命令行参数、process list 或 shell history；登录 token
通过 OS credential store 或受限 stdin/file descriptor 传递。

### Device view

Device 页面至少展示：

- stable device ID、managed node ID、owner、tags、虚拟 IP。
- 主名称、别名、IPv4/IPv6 lease、地址和 DNS snapshot epoch。
- enrollment/liveness/service/policy/path 五个独立状态。
- certificate expiry、node key epoch、last rotation 和 revoke status。
- client/agent/meshd 版本与 platform。
- direct/relay path、relay identity、exit/subnet capabilities。
- applied policy/revocation epoch 与 Controller current epoch 的 lag。
- last seen、last signed LEFT、last command 和可验证离线原因。

UI 不显示“online”来替代 policy/security health，也不把 probe timeout 表述为某个用户关闭
节点。

## 虚拟网络、IPAM 与 MagicDNS

### 当前兼容边界

当前 `mesh_config_t` 已提供本机静态 `magic_dns_domain` 和 `magic_dns_records`，
`mesh_resolve_magic_dns()` / `mesh_reverse_magic_dns()` 可做进程内正反向查询；这层兼容行为继续
保留。它目前不是 DNS server，也不会配置操作系统 resolver；记录使用 16 字节 IPv4 字符串，
反向查询依赖 IPv4 parser，因此不能宣称支持 IPv6、AAAA 或双栈 IPAM
（[`turbo_mesh.h`](include/turbo_mesh.h#L92)、[`mesh.c`](src/mesh.c#L4616)）。

### 目标资源模型

Controller 把一个 Mesh network 建模为版本化资源：

```text
Network {
  mesh_id, ipv4_prefix?, ipv6_prefix?, dns_suffix,
  reserved_ranges, dns_service_addresses,
  address_epoch, dns_epoch
}

AddressLease {
  lease_id, managed_node_id, node_key_epoch,
  family, binary_address, state, issued_at, expires_at?
}

DnsRecord {
  record_id, owner_node_id?, canonical_name, type, value,
  ttl, record_epoch, not_after?, aliases?, service_id?
}
```

network prefix、lease 和 DNS record 的唯一写入事实源是 Controller database transaction。
agent/`meshd` 只安装验签后的 immutable snapshot；本地 DNS table、路由和 UI 列表都是派生
视图，不能经 Gossip 各自推进。节点 enrollment 可在同一 Controller 事务中原子分配主名称、
IPv4/IPv6 lease 和证书 binding；其中任一步失败都不发布半配置节点。

地址租约必须绑定 `(mesh_id, managed_node_id, node_key_epoch)`。节点名、A/AAAA 地址、低延迟
路径和 endpoint 都不是认证身份；连接最终仍验证 node certificate/public key。节点撤销或重新
enrollment 时，旧 lease/record 进入明确的 revoked/quarantine 状态，不能被另一个同名节点
立即继承。

### 名称解析数据流

每个节点运行本地权威 stub resolver，平台层只为该 Mesh suffix 安装 split-DNS/search domain：

```text
application query db.prod.mesh
-> OS split-DNS routes suffix to local mesh resolver
-> resolver reads current verified DNS snapshot
-> returns A/AAAA with bounded TTL
-> application connects virtual address
-> data plane independently authenticates destination node identity
```

DNS service address由 network 资源显式保留。可使用每节点本地拦截的 Mesh anycast 地址，
但不得和 node lease、exit route 或业务 subnet 重叠。默认只接管受管 suffix；不全局劫持 DNS，
也不使用 `.local`，以免与 mDNS 语义冲突。full-tunnel/exit profile 的公网 DNS 模式仍遵循
平台文档的独立 leak/kill-switch 约束，不能把 MagicDNS 当作公网 resolver。

Controller 通过 targeted push/MMP desired state 发布签名 snapshot 或受基线 epoch 约束的
delta；Gossip 只负责补齐已签名记录，不决定冲突。节点原子切换完整 snapshot，并保留一个
已验证的 rollback snapshot。签名、mesh ID、epoch、有效期或地址族校验失败时拒绝整次更新；
Controller 暂时不可用时，未过期 snapshot 继续解析，过期后新查询返回明确失败，不回退到
未经授权的公共 DNS。

首版 DNS record 支持 A、AAAA、PTR 和 CNAME-like alias；SRV/TXT 只在 TurboMedia 等业务
确有服务发现需求时加入。canonical node name 必须在 Mesh 内唯一、规范化且不可用 display
name 冒充；重复名称、地址冲突、prefix 缩小导致活跃 lease 越界、同一地址族多 owner 都在
publish 前 fail fast。

### 双栈兼容迁移

IPv6 不能通过把现有 `char virtual_ip[16]` 就地扩容实现，因为这会破坏公开结构 ABI。迁移采用
additive v2 类型：`address_family + 16-byte binary address + prefix`，新增 v2 record/snapshot
getter；旧 IPv4 API 继续返回原行为。内部路由、packet parser、policy CIDR、TUN 配置、PTR
生成和审计字段全部支持地址族后，才允许 Controller 发布 IPv6 network capability。未声明
双栈 capability 的节点不接收 IPv6 lease/route，不能静默降级为 IPv4 同名记录。

### 安全与可观测性

- DNS snapshot 只含 public descriptor，不含 private/session key、token 或用户凭据。
- resolver 对单节点/来源设置 QPS、并发、record count、name length 和 response size 上限。
- audit 记录 record/lease mutation、actor、前后 hash、epoch 和 rollout；不记录完整 DNS body。
- 指标包含 snapshot age、签名失败、A/AAAA/PTR hit/miss、stale refusal、冲突和 rollout lag。
- 验证覆盖 A/AAAA/PTR、重名/重址、撤销、epoch 回放、离线 TTL、split-DNS、不泄漏公网 query、
  IPv4-only 节点与双栈节点协商，以及 DNS 结果与握手 node identity 不一致时 fail closed。

## 审计模型

### Event classes

| class | producer | 示例 |
|-------|----------|------|
| configuration | Controller | policy diff、route approval、tag change |
| identity | Controller/agent | enrollment、approval、rotation、revocation |
| management | agent | restart/reconcile/diagnostics result |
| flow | `meshd` | flow start/end、bytes、rule/path/exit epoch |
| security | agent/`meshd` | replay、spoof、route injection、downgrade、sink failure |

统一 event envelope：

```text
schema_version + event_id + event_class + event_type + producer_sequence +
wall_time + monotonic_time? + producer_node + actor + target +
request/command/flow_id + policy_epoch + action + reason_code +
before_hash? + after_hash? + canonical_details + previous_event_hash + event_hash
```

正文禁止包含 private/session key、token、payload、完整 DNS body 或凭据。flow audit 默认是
metadata/aggregate；PCAP 是独立、显式授权、有时限和字节上限的诊断操作。

普通 flow event 不逐条做非对称签名；producer 对 event hash chain 的周期 checkpoint 签名，
在保持篡改检测能力的同时避免把签名操作放进 packet 热路径。

### Integrity 与 export

- producer 本地 append-only segment 使用 hash chain。
- segment checkpoint 由 management key 签名并通过 MMP 发布 audit anchor。
- Controller 验证 chain continuity，写入独立 append-only storage。
- export worker 使用有界 queue、重试和 dead-letter 状态；不能阻塞 packet owner loop。
- `best-effort` 与 `required` audit mode 是显式 deployment policy，不能静默互换。
- required spool 达上限时只拒绝新 flow，并产生本地安全告警；不能无限增长磁盘。

本地 chain 只能检测已有 segment 被修改，不能证明整段存储未被本机管理员删除；合规场景
必须配置外部 checkpoint/storage。

## Availability 与分区语义

| 故障 | 用户可见行为 |
|------|--------------|
| Controller 暂时不可用 | 既有 flow 和未过期 policy 继续；新 enrollment/policy mutation 失败 |
| MMP 分区 | 节点显示 stale/lag；不自动停止健康数据面 |
| policy 过期 | 停止新授权动作；按 profile drain 或拒绝新 flow，不采用旧 policy fallback |
| revoke 尚未确认 | UI 显示 pending enforcement 和未确认节点集合 |
| agent 离线、`meshd` 在线 | 数据面可继续，管理状态 unknown/stale |
| `meshd` 离线、agent 在线 | 可查询原因并执行受权 restart/reconcile |
| audit sink 中断 | 按显式 best-effort/required 模式处理并告警 |

Controller 高可用只保护产品 API 和事实源；不通过多 Controller 各自递增 policy epoch。
HA 实现必须使用单一事务事实源或明确 leader/consensus，MMP Gossip 不能替代 Controller
database consistency。

## 模块边界

目标内部模块保持小接口和 opaque ownership：

| module | 职责 | 不负责 |
|--------|------|--------|
| identity verifier | certificate、binding、expiry、revocation | OIDC、UI、database |
| policy parser adapter | JSON/TOML 到 typed document | 授权 decision |
| policy compiler | selector snapshot 到 compiled tables/tests | network I/O、持久化 |
| policy store | current/staged immutable bundle | packet evaluation |
| policy evaluator | packet/route/management decision | 日志格式、Controller API |
| MMP adapter | signed bundle/command transport | policy semantic merge |
| audit sink adapter | bounded event export | packet allow/deny decision |

policy compiler 和 evaluator 共享版本化 typed schema，不共享可变 map。平台、storage、HTTP
和 crypto 通过薄 ops/adapter 注入；不使用全局 service locator。所有 create 有对应 destroy，
compile/apply 返回结构化 Result，snapshot 所有权与 owner-loop 约束必须写入 API 文档。

## 错误语义

| code | 用户含义 |
|------|----------|
| INVALID_DOCUMENT | schema、类型或字段格式错误 |
| UNKNOWN_SELECTOR | user/group/tag/node/service 不存在 |
| EMPTY_SELECTOR | selector 意外解析为空 |
| POLICY_TEST_FAILED | 内置 policy test 与期望不符 |
| EPOCH_CONFLICT | base epoch 已过期，需重新 diff |
| APPROVAL_REQUIRED | device 尚未批准 |
| CERTIFICATE_EXPIRED | node/operator certificate 过期 |
| REVOKED | device/key 已撤销 |
| PERMISSION_DENIED | product role 或 Mesh capability 不满足 |
| PARTIAL_ROLLOUT | bundle 已发布但部分节点拒绝/未确认 |
| STALE_ENFORCEMENT | 节点 policy/revoke epoch 落后 |
| AUDIT_UNAVAILABLE | required audit 无法安全接受新 flow/action |
| CONTROLLER_UNAVAILABLE | 事实源不可达；不自动切换到本地写入 |

错误必须携带 operation、stage、target、current/expected epoch 和 correlation ID。UI 可以翻译
文案，但 stable code 是自动化和测试契约。

## 迁移与兼容性

### 影响

- 现有 `mesh_config_t` 和静态测试继续保留，默认属于 compat profile。
- production policy 引入新 signed bundle、policy epoch、decision reason 和 status surface。
- agent 需要 secure storage、enrollment certificate、revocation cache 和 applied-epoch journal。
- Controller 是新部署单元，但不进入数据路径；数据面仍可在 Controller 短时不可用时运行。
- user/group/OIDC/HTTP/database 类型不会进入 Mesh public header。

### 实施阶段

1. **P0 事实基线（已完成）**：permissive-empty、ordered first-match、peer CIDR/node-id/
   protocol-major admission、learned-route rejection，以及 local egress 的目的 CIDR、认证源
   CIDR 和源地址防冒充回归均已固化。所有 array/count 配置对也会在负数 count 或正数
   count 配 NULL array 时 fail fast，避免安全策略因配置不完整退回空策略。
2. **P1 identity core**：machine continuity、node certificate、secure storage、rotation/revoke
   golden vectors；先 observer-only。
3. **P2 read-only inventory**：Controller/CLI 展示 device 五维状态、key/policy epoch、path、
   address lease 和 DNS epoch。
4. **P3 network/IPAM/MagicDNS**：先接入 IPv4 signed snapshot 与 split-DNS，再以 additive v2
   API 引入 IPv6 A/AAAA/PTR；静态 MagicDNS 保持 compat。
5. **P4 policy compiler**：typed Grants、selector resolution、static analysis、policy tests 和
   shadow decision；不改变 packet action。
6. **P5 production enforcement**：显式 production profile、atomic snapshot、default deny、
   signed rollout/rollback 和 lag 状态。
7. **P6 audit closure**：configuration/identity/management/flow/security event、external sink、
   canary-secret 和 spool failure tests。
8. **P7 route/exit product**：advertise/use/admin 三权分离、quorum、kill-switch 和多出口状态。
9. **P8 UI/GitOps**：approval、policy diff/test、audit search、API tokens/workload identity。

每阶段通过 feature/capability 和 profile 显式启用。不能从 production 自动回退到 compat；
回滚通过新 epoch 发布已验证的旧语义 bundle。

部署层回滚遵循阶段边界：P1-P3 可停用 Controller/agent 新 feature 并保留现有 compat 配置；
P4 production enforcement 启用后，只能用更高 epoch 的签名 bundle 回滚策略。若要卸载 agent
或退回 compat，必须由本机管理员显式迁移配置、撤销 production enrollment 并验证不会把
default-deny 静默变成 permissive；不能由远程失败路径自动完成。

## 验证范围

### Identity 与 key

- private/traffic key 从不出现在 wire capture、日志、status、crash dump 和 audit export。
- new device pending/approve/reject、single-use token replay、old/new key proof 和 lost-key reenroll。
- expiry、revoke、issuer rotation、node epoch、partition/heal 和 selective descriptor distribution。
- 仅 Controller API 被攻陷而隔离 signer policy 未被攻陷时，不能注入有效 node descriptor；
  issuer compromise 按明确的高风险恢复流程测试。
- replay window、session epoch、path rebuild 和 relay 不可读取端到端 payload。

### Policy

- JSON schema、unknown field、循环 group、empty selector、duplicate ID 和容量上限。
- default deny、direction、protocol/port、CIDR、service、via、advertise/use/admin separation。
- guardrail 始终优先；rule reordering 不改变 Grants 语义。
- policy unit tests、shadow/active decision diff、staged rollout、partial failure 和 rollback epoch。
- compat profile 保持现有测试结果；production 缺 policy 启动失败。

### Controller 与 API

- OIDC role mapping、step-up、API idempotency、If-Match/base epoch 和 concurrent mutation。
- Controller restart/HA leader change 不重复 epoch、command 或 audit event。
- Controller outage 不影响既有数据转发；新 enrollment/mutation 明确失败。
- device view 不混淆 enrollment、liveness、service、policy 和 path 状态。

### Audit

- actor/target/before-after/policy epoch/reason/correlation 可查询且完整。
- duplicate、乱序、clock skew、segment rotation、checkpoint、collector outage 和 disk full。
- 日志/状态测试植入 canary secret，断言所有 sink 不包含 secret/payload/session key。
- audit 开关前后测量 packet path p50/p95/p99、CPU、内存和 dropped-event counter。

### 跨区验收

- eu/bj/sh/local enrollment、批准、rotation、revoke 和 partition/heal。
- 只向允许通信的节点下发 descriptor；relay 无业务 plaintext。
- policy 发布显示每节点 applied epoch；离线节点恢复后先收敛 revoke/policy 再接收新 flow。
- eu 作为 management relay 不自动成为 exit；exit advertise/use 分别批准。
- 停止 `meshd` 后 agent 仍可查询并恢复；远程不能停止 agent 自身。

## 产品完成条件

只有同时满足以下条件，才能从“Mesh library”称为“可管理的安全网络产品”：

- 用户无需手工交换 key、编辑 peer 列表或逐台 SSH。
- private key 永不离开设备，public descriptor 有授权签名、scope、epoch、expiry 和 revoke。
- production 无有效 policy 时 default deny，compat 行为不会被静默带入 production。
- policy 可以 validate、test、diff、原子发布、查看 lag 并用新 epoch 回滚。
- subnet/exit 的 advertise、use 和 administer 权限相互独立。
- configuration 与 flow audit 可关联 actor、rule、policy/path epoch 和稳定 reason。
- Controller 故障不成为数据面瓶颈，管理分区不会伪造全局同步成功。
- 所有高风险状态都能在 UI/API/CLI 中区分事实、检测结果和未知状态。

## 一手资料

- [Tailscale control and data planes](https://tailscale.com/docs/concepts/control-data-planes)：
  集中协调与节点本地数据面的产品边界参考。
- [Tailscale node keys](https://tailscale.com/docs/concepts/node-keys)：device/node key 分层、
  public-key distribution 和 rotation 参考。
- [Tailscale Tailnet Lock](https://tailscale.com/docs/features/tailnet-lock)：节点侧验证受信
  signer 对 node key 的授权参考。
- [Tailscale access control](https://tailscale.com/docs/features/access-control)：声明式、
  direction-aware、device-local enforcement 参考。
- [Tailscale configuration audit logging](https://tailscale.com/docs/features/logging/audit-logging)
  与 [network flow logs](https://tailscale.com/docs/features/logging/network-flow-logs)：配置审计
  与不记录 payload 的 flow metadata 参考。

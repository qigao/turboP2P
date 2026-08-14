# TurboP2P secure wire v2 运维手册

## 1. 适用范围与状态

本文定义 secure wire v2 的部署、信任变更、事件处置和回滚契约，适用于直接嵌入
P2P 的程序以及通过 Mesh management provider 使用 P2P 的进程。协议与实现边界见
[`NOISE_IDENTITY_DESIGN.md`](NOISE_IDENTITY_DESIGN.md)。

- **事实**：v2 是硬切协议；同一 listener 不探测、不降级、不回退旧 wire。
- **事实**：未安装稳定身份和 identity provider/trust snapshot 的 listener 拒绝启动。
- **事实**：认证、双向加密 READY 和 channel binding 完成前不会发布 peer。
- **发布约束**：Linux sanitizer、持续 fuzz、独立实现互操作、真实 TPM/HSM 演练和独立
  安全审查尚未全部完成，因此本手册不能替代发布安全签字。

## 2. 状态归属与职责

| 状态 | 唯一事实源 | 变更边界 |
|---|---|---|
| 本地 X25519 身份 | owner-only key file 或 opaque provider | 启动前安装；运行中不替换 |
| 原始 P2P 远端信任 | node 内复制的 pinned-key snapshot | CoroNet owner thread 上调用 `p2p_node_update_pinned_trust_v2()` |
| Mesh 远端信任 | Mesh provider 的 epoch/role/revocation snapshot | 使用 runtime 组合命令更新并立即重验 |
| 已建立会话身份 | Noise transcript、credential 与 READY 绑定结果 | 每次完整握手生成；不能由 PING 或应用消息覆盖 |
| 容量与拒绝计数 | P2P node / V4 executor snapshot | 只读查询，不由监控系统回写 |

调用方拥有 provider context，并须保持其有效直到 `p2p_destroy()` 返回。CoroNet owner
thread 拥有 peer 安全状态；运维线程不得并发调用标注为 owner-thread-only 的信任更新或
重验 API。私钥、credential 原文和 channel key 不进入日志、状态文件或告警标签。

## 3. 上线前清单

### 3.1 每个节点

1. 生成独立且稳定的 32 字节 X25519 私钥；禁止复制同一私钥给多个节点。
2. 将私钥放入部署平台的 secret store。`meshd` 文件模式只接受 64 个十六进制字符，
   总输入不超过 4 KiB。
3. POSIX 使用 daemon uid 拥有的普通、非符号链接文件，且 group/other 权限为零；
   Windows 使用非 reparse 普通文件，owner 和所有 allow ACE 只能属于服务账户、
   LocalSystem 或 Administrators。
4. 固定非零 network ID hash；同一逻辑网络所有节点必须一致，不同网络不得复用。
5. 预先分发完整 trust snapshot。原始 P2P 使用 X25519 public-key pins；Mesh 模式还需
   固定 issuer、Mesh ID、最低 epoch、允许角色和 revoked serials。
6. 使用 `meshd doctor` 或嵌入程序等价的 fail-fast preflight 验证密钥、配置、监听端口
   与依赖。任何失败必须阻止网络启动，不得生成临时身份继续运行。

### 3.2 集群硬切换

1. 冻结成员、证书、network ID 和 endpoint 清单，并保存可审计的旧 binary 与配置快照。
2. 在隔离环境用至少三个节点验证同时双向拨号、断线重连、DHT/文件/管理数据面和旧
   客户端拒绝。
3. 停止旧节点；确认没有写入或控制面操作仍依赖旧连接。
4. 在所有节点安装 v2 binary、稳定私钥和完整 trust snapshot，再按 bootstrap 节点、
   普通节点的顺序启动。
5. 只有第 4 节健康条件全部满足后才恢复业务流量。混合 v1/v2 集群不是受支持状态。

## 4. 启动与日常健康判定

库级集成应周期性读取 `p2p_node_get_security_status_v3()`；它在一次 node lock 下返回
v2 capacity/rejection、V4 executor availability/status 和固定握手时延累计量。既有
consumer 可继续分别读取 `p2p_node_get_security_status_v2()` 与
`p2p_node_get_private_key_executor_status_v4()`，但不得把两次查询之间的中间状态解释为
一个原子节点视图。任何节点快照都不是原子集群视图。

健康节点同时满足：

- configured send/node budget 与预期 profile 一致；reserved capacity 不超过总预算；
- `active_cookie_gates`、pending handshakes 和 active transports 均未超过配置上限；
- 对预期成员能取得 `p2p_peer_get_security_info_v2()`，且 `authenticated` 为真；
- remote principal、routing ID、transport public key、trust epoch/roles 与控制面记录一致；
- rejection counter、executor timeout/cancel/post-failure counter 没有无法解释的持续增量；
- DHT、文件传输或 Mesh 管理的端到端探针成功，不能只用 TCP connect 代替认证探针。

`meshd` status-file 和 `/v1/status` 已导出顶层 `security`：wire/suite、send budget、
source admission、cookie gate、类型化 rejection、可选 private-key executor，以及
initiator/responder × COOKIE/PREFACE/NOISE/READY 的固定 12 桶累计量。status-file 的
`snapshot_version=2`；既有字段未改名。C API 的最后一个桶上界为 `UINT64_MAX`，JSON
将同一 `+Inf` 哨兵序列化为 `null`，避免超出常见 JSON number 的精确整数范围；每次完成
只进入一个不重叠区间桶。该 JSON 不含私钥、credential、peer identity、地址、
remote static、channel binding 或逐握手样本；仍不能用普通 peer count 推断认证健康。

## 5. 信任更新与撤销

### 5.1 原始 P2P pin 模式

在 node 的 CoroNet owner thread 上执行：

```text
validate and copy new pin set
-> atomically replace trust snapshot
-> revalidate every established session
-> disconnect rejected or identity-changing sessions
-> publish revalidation result and audit event
```

使用 `p2p_node_update_pinned_trust_v2()` 完成上述序列。空 pin 集合表示撤销所有远端，
不是“接受所有”。分配或输入校验在 swap 前失败时旧 snapshot 保持不变；swap 后若无法
完整重验，所有已建立安全会话 fail closed 断开。

### 5.2 Mesh certificate 模式

专用 management runtime 使用
`mesh_mgmt_agent_runtime_update_remote_trust_v2()`，一次 owner-thread command 更新远端
最低 epoch、角色和撤销 serial，再立即调用 P2P 重验。不要把 provider update 和
revalidation 拆到两个调度周期。

直接组合 provider 的嵌入程序必须在同一 owner-thread 临界流程中依次调用：

```text
mesh_mgmt_p2p_security_provider_update_remote_trust_v2()
-> p2p_node_revalidate_security_v2()
```

issuer public key 与 Mesh ID 在 provider 生命周期内不可变；轮换它们需要协调重启。
本地证书更新同样需要重启，以保证 local credential 与 READY 只来自一个快照。

## 6. 身份密钥轮换

本地 transport key 轮换会改变 public node identity 和 routing ID，不能当作透明文件替换。
正确顺序是：

1. 生成新密钥并记录旧、新 public identity；私钥永不进入工单、日志或聊天系统。
2. 在所有授权对端先加入新 public key，保留旧 key，完成 trust snapshot 更新与重验。
3. 停止目标节点，原子安装新私钥，重新启动并完成全新 Noise/READY。
4. 验证新 identity 的连接、路由重收敛、DHT 重发布和上层授权。
5. 从所有对端移除旧 public key并再次重验；确认旧身份的所有 session 已断开。
6. 按 secret-store 策略销毁旧私钥，保留不含秘密的审计证据。

任一步失败都停止后续步骤。若新身份尚未启动，恢复旧私钥与旧配置；若新身份已产生
业务写入，先评估上层状态和路由收敛，不能仅替换 key 文件强行回退。

## 7. 告警与审计

### 7.1 指标告警

counter 必须按采样差值告警，进程重启导致的归零需单独处理。标签只允许低基数的
`stage`、`role`、`reason` 和 deployment ID；禁止用 peer ID、公钥、IP 或 credential
作为无界指标标签。

| 信号 | 建议触发条件 | 立即动作 |
|---|---|---|
| cookie gate / source rate rejection | 基线以上持续增长或 gate 长时间接近上限 | 保留样本，检查入口流量、backlog 与边缘限速；不要扩大 gate 掩盖攻击 |
| handshake protocol/crypto rejection | 新版本发布后增长，或单一来源重复出现 | 隔离来源，核对 wire/network ID，保存不含 secret 的 stage/reason |
| identity/revalidation rejection | 任意意外增量 | 视为信任配置或凭据事件，停止扩大部署并核对 epoch/role/revocation |
| send budget/resource exhausted | 可用预算持续接近零或拒绝增长 | 检查慢接收端和 transport 数；先限流/隔离，不无界提高 HWM |
| executor timeout/cancel/post failure | 任意非演练增量 | 停止使用硬件 profile，检查 SDK deadline、设备健康和 owner-loop dispatch |
| session key/age/byte limit | 正常轮换频率之外增长 | 确认客户端会完整重连；不得恢复旧 CipherState counter |

### 7.2 审计事件

以下低频状态迁移记录 INFO/WARN 审计事件：操作者/自动化身份、deployment、操作类型、
旧/新 snapshot 版本摘要、结果、受检与断开会话数。不得记录 private key、shared secret、
完整 credential、cookie secret、Noise chaining key 或 CipherState。

- key/certificate 安装、轮换和销毁；
- pin、epoch、role、revocation snapshot 更新；
- revalidation 结果与 fail-closed 全断开；
- hard-cut 开始/完成/回滚；
- HSM profile 启停、deadline/cancel 和设备掉线演练。

高频 handshake/frame 路径只更新有界 counter/latency histogram，不逐包写 INFO 日志。

## 8. 故障处置

| 症状 | 判定 | 处置 |
|---|---|---|
| listener 启动返回 `AUTH_REQUIRED` | 身份策略未完整安装 | 阻止启动，修复 key/provider/trust；禁止 accept-any |
| 全部对端 `COOKIE_PROTOCOL` | wire 版本、network ID 或流量入口错误 | 核对 binary/profile；不启用 legacy fallback |
| `UNTRUSTED_IDENTITY` | pin/cert/role/epoch/revocation 不匹配 | 隔离节点，校验证书链和信任快照；不要临时放宽角色 |
| `KEY_EXHAUSTED` | frame、age 或 byte 上限到达 | 建立全新 Noise 会话；禁止重置原会话 counter |
| V4 executor `RESOURCE_EXHAUSTED` | worker/operation 容量已满 | 对新握手背压，检查 HSM 延迟；禁止无界排队 |
| trust update 后重验失败 | 新 snapshot 已是事实源但无法完整重验 | 确认所有 established session 已 fail closed，修复资源后重新连接 |
| 私钥疑似泄露 | 身份完整性不可再信任 | 立即撤销 pin/serial、断开会话、轮换 key/cert，并调查上层授权影响 |

## 9. 停机、恢复与回滚

安全停机顺序：停止 listener 与新 connect，取消/拒绝新握手，令 V4 executor 停止接纳并
drain/cancel，断开 peer，停止 managed coroutine，销毁 node，最后释放 provider context。
provider 超过声明 deadline 不返回是合同违约；不得 detach worker 后释放 context。

崩溃恢复不得持久化或恢复 Noise handshake、CipherState nonce、cookie derived key 或
channel binding。进程重启后从稳定身份和最新 trust snapshot 建立全新会话。

secure wire v2 没有进程内 rollback flag。协议回滚只能在维护窗口停止全网，恢复归档的
旧 binary 与匹配配置。transport 私钥不随 binary 自动回滚；任何 key 变更必须单独、
显式、可审计。混合版本连接失败是预期 fail-closed 行为。

## 10. 发布证据包

每次生产候选至少归档：

- binary、依赖锁定版本、构建 preset 和配置摘要；
- Windows 与 Linux 的单测、ASan/UBSan/LSan、TSan 结果；
- 三节点同时拨号/重连、旧 binary 拒绝和全网 rollback 演练；
- 持续 fuzz corpus 摘要、时间预算和所有 crash artifact 处置结果；
- 独立 Noise 实现互操作结果；
- key/cert 初始化、轮换、撤销、恢复演练记录；
- 若启用 TPM/HSM，真实设备的 deadline、cancel、队列满、掉线和 shutdown drain 结果；
- 独立安全审查结论及所有 HIGH 问题的关闭证据。

缺少任一适用证据时，发布记录必须明确标为未通过，不能以 Windows ASan、固定向量或
模拟 provider 结果代替 Linux TSan、独立互操作或真实硬件验证。

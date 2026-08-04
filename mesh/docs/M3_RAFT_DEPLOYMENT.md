# M3 Raft 三进程部署实施清单（Phase 2b-ii/2c）

状态：实施计划（组件 API 与 wire 边界已验证，见 M3_DISTRIBUTED_STORAGE_DESIGN.md §20.4/20.5/20.6）。
目标：三个独立进程运行 M3 raft 元数据节点，经 CoroNet TCP/TLS 互联，验证跨进程 quorum 提交收敛。

## 0. 已验证前提（事实）

- TurboRaft `raft_coronet_transport` 组件 API 可用：确定性拨号方向、peer manager 配置校验、`sha256:` 证书身份解析（`test_m3_raft_coronet_transport`，18 断言）。
- wire 序列化边界正确：三 voter 经 `tr_raft_wire_codec` 编解码仍收敛（`test_m3_raft_wirecodec`，9 断言）。
- **mTLS 握手已验证**（`test_m3_raft_tls_handshake`，12 断言）：CoroNet TLS + `tr_raft_coronet_handshake_exchange` + 指纹身份注册表，node1<->node2 HELLO/ACK 完成。
- **session 帧协议已验证**（`test_m3_raft_coronet_session`，410 断言）：长度前缀帧编码/字节流重组/跨 session 投递。
- **两节点真实 CoroNet TLS raft 部署已验证**（`test_m3_raft_coronet_node`）：进程内双节点 mTLS 连接 → 选举 → leader propose PUT → 双节点 applied_index 收敛 → leader 线性化读回；follower 拒绝读（EPROTO）。
- **两进程部署已验证**：`m3_raft_node_main --listen/--peer` 双进程跑通 mTLS 连接与选举（node2 当选 leader）。
- **三进程部署已验证**：`run_m3_raft_cluster.ps1` 三进程 mTLS 互联，选举 + leader 提交 probe + 三进程 applied_index 收敛（连续 6 次通过）。
- **网关 leader 读路由已验证**（`test_m3_gateway_raft_node`，34 断言，10/10）：双网关各嵌一个 2-voter raft 节点；leader 网关 PUT 收敛、线性化读回；follower 网关拒绝写/读/列（NOT_LEADER + 当前 leader id）。
- **网关 HTTP 端到端已验证**（`test_m3_gateway_http`，28 断言）：真实 Iris 服务器 + http_client + 签名 S3 请求走单 voter node 后端 —— PUT/GET/HEAD/ListObjects/DELETE/404/篡改签名 403 全链路。修复了 HEAD 响应的重复 `Content-Length` 头（RFC 7230 禁止重复）。
- **多进程网关部署已验证**（`run_m3_gateway_cluster.ps1`）：3 个 `m3_gateway_main --raft-node` 进程，后台泵线程持续驱动内嵌 raft 节点 → 无需任何 HTTP 请求即自动选举 leader；三个 S3 HTTP 端点全部响应。修复了此前节点仅在请求时被泵、进程空闲时冻结导致无法选举的部署缺陷。
- **硬约束**：
  - `tr_raft_coronet_handshake_exchange` 要求 **verified TLS socket**（证书 `sha256:` 指纹 → node id）；非 TLS 连接不受支持。
  - `tr_raft_coronet_session_config.handshake` 对 connected socket 必填。
  - `read_index` **仅 leader**（follower 返回 EPROTO）→ 读请求路由到 leader。
  - 自签证书必须携带 `subjectAltName=IP:127.0.0.1,DNS:localhost`，否则客户端校验报 `X509_V_ERR_IP_ADDRESS_MISMATCH`。
  - 选举超时必须**随机化**：`m3_gateway_raft` 每个 tick 在 [election_min, election_max] 内随机取 `next_election_timeout_ticks`；固定值会让同步启动的节点同时发起选举、互相拒票而死锁。

## 1. TLS 证书生成（本机已验证，openssl 3.0.15）

```powershell
# 需指定 openssl 配置（anaconda 的 openssl 不读默认 cnf）
$conf = 'C:\Users\lockg\scoop\apps\anaconda3\2024.10-1\App\Library\ssl\openssl.cnf'
New-Item -ItemType Directory -Force -Path build\Msvc-Release\m3tls | Out-Null
Set-Location build\Msvc-Release\m3tls
foreach ($n in @('node1','node2','node3')) {
  # CoroNet 客户端在 verify_peer=1 时按 IP/DNS SAN 校验对端证书（BoringSSL/OpenSSL 3.x
  # 不再回退 CN），因此自签证书必须携带 subjectAltName，否则握手报
  # X509_V_ERR_IP_ADDRESS_MISMATCH (verify=64)。
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$($n).key" -out "$($n).crt" `
    -days 365 -subj "/CN=$n" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" -config $conf
  $fp = openssl x509 -in "$($n).crt" -noout -fingerprint -sha256 |
        Select-String -Pattern 'SHA256 Fingerprint=([0-9A-F:]+)'
  Write-Output ("{0} -> sha256:{1}" -f $n, ($fp.Matches[0].Groups[1].Value -replace ':','').ToLowerInvariant())
}
# 汇总 CA bundle：mTLS 双方用同一 bundle 作为信任根，互相验证对端自签证书。
Get-Content node1.crt,node2.crt,node3.crt | Set-Content m3ca.crt
Set-Location ..\..\..
```

生产建议：改用 CA 签发（`openssl ca`/`req -x509` CA 自签 + 节点 CSR），并把 CA 证书配置进 CoroNet TLS client 信任；`sha256:` 指纹注册到 `tr_raft_coronet_identity_registry`。

## 2. 节点结构（每个进程）

```
m3_raft_node_main
 ├─ CoroNet coro_context（事件循环）
 ├─ tr_raft_sqlite_storage（log/snapshot 持久化）
 ├─ m3_namespace_local_store（状态机目标）
 ├─ m3_namespace_raft_adapter（state machine + propose + read-index）
 ├─ tr_raft_service（core + storage + transport + state_machine）
 ├─ TLS 证书（nodeN.key/.crt）
 ├─ identity_registry（对端证书指纹 → node id）
 ├─ peer_manager（对端 session 路由）
 └─ inbound：coro_socket_listen + tls server 握手 + session 接入
      outbound：dial_scheduler + coro_socket_connect + tls client 握手
```

## 3. 实施步骤（建议顺序）

1. **[完成] 节点骨架**：`mesh/examples/m3_raft_node_main.c` —— 解析参数（node id、listen port、peer endpoints、证书路径、sqlite 路径），`--self-test` 单 voter 自检通过。
2. **[完成] TLS 接入**：`m3_raft_node`（`mesh/src/m3_raft_node.{c,h}`）建立 CoroNet TLS 连接；`tr_raft_coronet_handshake_exchange` HELLO/ACK；`identity_registry` 校验对端指纹；`test_m3_raft_tls_handshake` 验证。
3. **[完成] session 接入**：`tr_raft_coronet_peer_service`（session 绑定 + handshake + on_message → `tr_raft_service_step`）；`test_m3_raft_coronet_session` + `test_m3_raft_coronet_node` 验证。
4. **[完成] service transport 接线**：`m3_gateway_raft_config_v1_t.transport` 注入 peer service enqueue；`transport.enqueue` 按 `message.to` 路由。
5. **[完成] 三进程编排**：`mesh/scripts/run_m3_raft_cluster.ps1` 起 3 个 `m3_raft_node_main` 进程（`--probe-put` 由 leader 提交固定 probe 对象）；脚本断言：选举产生 leader → PROBE-COMMITTED → 三进程 applied_index 收敛到同一已提交索引。本机连续 6 次全绿（~4s/次）。
6. **[完成] leader 读路由 + Phase 2c 故障测试**：
   - `m3_raft_node_leader()` / `m3_gateway_raft_leader_v1()` 暴露当前 leader id（read-index leader-only 的路由原语）；`m3_raft_node_status` 暴露 `raft_faulted/raft_fault_cause/dropped_messages` 供可观测性。
   - **Phase 2c crash/leader 切换/瞬断分区已验证**（`test_m3_raft_coronet_node`，4 用例，10/10 稳定）：① 三 voter 提交 → crash leader → 幸存 2 节点（quorum=2）选出新 leader → 新任期提交 → 已提交条目不丢失；② 瞬断分区（`m3_raft_node_disconnect_peer` 切断 node1↔node2）→ 分区期间 leader 无法提交（无 quorum）→ 自愈重连后 follower 追平，已提交条目不丢失。
   - 新 leader 需先在新任期提交一条（raft 线性化读不变式）才能服务 read-index；对端不可达不再 fault raft service（见风险节）。
   - **网关多节点元数据后端**（`m3_gateway_init_node_v1`）：网关内嵌 `m3_raft_node` 作为 voter；PUT/TOMBSTONE 经 raft 复制（非阻塞 `_start` + `m3_gateway_poll_v1` 驱动），读走线性化 read-index；follower 网关对写/读返回 NOT_LEADER + leader id（HTTP 层 503 + `X-M3-Leader-Node`，可由部署层 307 转发）。`m3_gateway_main --raft-node` 以 voter 形态运行。
   - **ListObjects（node 模式已接）**：`m3_raft_node_list` 枚举 raft 复制后的节点内 store；`m3_handle_list_objects` 经 `gateway_meta_list` leader 路由（follower 返回 503 + `X-M3-Leader-Node`）；`test_m3_gateway_raft_node` 验证 leader 列出对象、follower 返回 NOT_LEADER。
   - **ListBuckets（已接枚举）**：`m3_handle_list_buckets` 经 `gateway_meta_list` leader 路由枚举 bucket 并生成 S3 XML（follower 返回 503 + `X-M3-Leader-Node`）；测试验证 leader 列出 `bkt`、follower NOT_LEADER。
   - **多进程网关节点泵修复**：`m3_gateway_main --raft-node` 后台线程持续 `m3_gateway_poll_v1`（选举/心跳无需请求即推进）；网关 node 模式 handler 改为 sleep-poll（避免与泵线程竞争节点上下文）；新增 `--sqlite` 参数解析。
   - **已知缺口（后续）**：对象 chunk 数据仍按节点本地存放（数据面复制属独立子系统，元数据面已复制）。

## 4. 验证门禁

- 单进程内：`test_m3_raft_cluster`、`test_m3_raft_wirecodec`（已绿）。
- 三进程 e2e：启动脚本断言「三进程 applied_index 收敛到同一 PUT」。
- 故障：kill leader → 新 leader 选举 → 未提交条目不丢失（Phase 2c）。

## 5. 风险与依赖

- CoroNet TLS 握手/事件循环集成已接入并独立验证（连通性 → 握手 → 消息 → 收敛，见第 0 节）。
- TLS 证书有效期/轮换策略需定义（V1 用自签 + 指纹白名单；`mesh/tests/data/m3tls/` 为提交的测试证书，生产用 CA 签发）。
- read-index leader-only：若需 follower 读，需 TurboRaft 上游增加 read-index 转发（或网关只从 leader 读）。
- **对端长时间不可达**：节点按 10ms 真实时间节拍推进 raft tick（避免事件循环速度洪水），outbound 队列有界（2048/peer）。队列满时 transport enqueue 返回 ENOSPC，`m3_raft_node` 的 enqueue 包装器**丢弃并计数**（raft 依赖重传，丢消息安全）而非让 raft service fault —— 对端 crash/重启不再打挂存活节点。`dropped_messages` 状态暴露丢弃量。

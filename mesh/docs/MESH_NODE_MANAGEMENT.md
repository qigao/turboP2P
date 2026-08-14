# Mesh 节点管理手册

本文档汇总 turbo-p2p mesh 的节点管理能力：生命周期、状态查询、准入/访问控制、
身份安全、成员管理、控制面（raft）、分布式执行与服务发现，并给出可复现的端到端
用法（CLI 命令与脚本）。所有命令以本仓库构建产物为准（`build\Msvc-Release\bin`）。

## 1. 节点生命周期与配置

### 1.1 生成密钥与初始化配置

```powershell
# 生成 transport X25519 身份材料，输出 identity_secret_hex 与公开 node_id
meshctl genkey

# 生成启动配置 mesh.yaml
meshctl init -o mesh.yaml --node-name node-a --network-id mymesh `
    --virtual-ip 10.42.0.1 --virtual-prefix 8 --listen-port 7878 `
    --bootstrap 10.42.0.2:7878 --ice-enabled false
```

`init` 当前仍写入 `identity_secret_hex`，仅适合作为隔离开发起点；`--bootstrap`
可重复添加，`--stun` 可重复添加。部署 `meshd` 时必须把该 64 字符私钥值迁入
owner-only 的独立文件，并在 YAML 中改用：

```yaml
identity_private_key_file: C:\ProgramData\meshd\transport.key
```

Linux 文件必须属于 daemon uid 且无 group/other 权限；Windows ACL 的 allow ACE
只能属于当前服务账户、LocalSystem 或 Administrators。`meshd doctor` 会在启动网络前
检查文件类型、链接/reparse、owner、权限/ACL 与精确编码。management mode 不接受
YAML 内联私钥，也不会在文件失败时回退到临时身份。

### 1.2 启动 / 自检 / 停止

```powershell
meshctl doctor -c mesh.yaml   # 配置自检（不启动网络）
meshctl up -c mesh.yaml       # 启动 mesh 节点 + 交互控制台（status/health/dht/peers/routes/policy/admission/dump/ping）
meshctl rpc --node 10.42.0.1 shutdown   # 远程关闭节点（POST /v1/shutdown）
```

对应库级 API（`mesh/include/turbo_mesh.h`）：
`mesh_create/mesh_start/mesh_stop/mesh_destroy`、`mesh_ice_setup/enable/disable`、
`mesh_connect_peer/mesh_disconnect_peer/mesh_find_peer`。

## 2. 状态查询与可观测性

| 入口 | 命令 / API | 说明 |
|---|---|---|
| 交互控制台 | `status` `health` `peers` `routes` `dht` `policy` `admission` `dump/diag` `ping` | `meshctl up` 后的控制台命令 |
| 远程 RPC | `meshctl rpc --node <ip[:port]> status \| v1-status \| health \| ping \| task-model \| resolve <node-id>` | `meshctl.c` 的 `meshctl_run_rpc` |
| 库 API | `mesh_get_node_id` `mesh_get_peer_count/info` `mesh_get_route_count/info` `mesh_get_route_rule_*` `mesh_get_stats` `mesh_get_diag_info` `mesh_get_path_trace_v1` `mesh_get_cached_dht_value` `mesh_reset_stats` `mesh_error_string` | `turbo_mesh.h` |

示例：

```powershell
meshctl rpc --node 10.42.0.1 status
meshctl rpc --node 10.42.0.1 resolve 101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
```

测试覆盖：`test_meshd_runtime`、`test_meshctl_rpc`。

## 3. 多节点管理（meshctl cluster，基于 turbo_cmd）

`meshctl cluster` 使用 TurboUtils 的 `turbo_cmd`（`turbo_parser.h`）做参数解析，
对一组节点 RPC 端点批量查询并聚合。

```powershell
# 列出配置的节点清单
meshctl cluster list --node 10.42.0.1:7878,10.42.0.2:7878

# 批量查询状态：逐节点打印 UP/DOWN，末尾输出汇总；任一 DOWN 返回非 0
meshctl cluster status --node 10.42.0.1:7878,10.42.0.2:7878 --token <token> [--raw]
```

输出示例：

```
NODE 10.42.0.1:7878: UP
NODE 10.42.0.2:7878: DOWN
CLUSTER STATUS nodes=2 up=1 down=1
```

`--node` 接受逗号分隔的多个 `host:port`；解析由 `meshctl_cluster_parse` 完成
（`mesh/examples/meshctl.c`），测试见 `test_meshctl_rpc.c` 的 `cluster (turbo_cmd)` 用例
（含真实 HTTP 端点的聚合验证）。

## 4. 准入 / 访问控制 / 策略

- 流准入开关：`mesh_stream_admission_enable / mesh_stream_admission_disable`（`mesh.c`）
- 允许列表查询：`mesh_get_peer_allow_count/info`、`mesh_get_peer_allow_node_id_count/info`
- 数据面策略：`mesh_get_packet_policy_*`、`mesh_get_local_egress_allow_*`
- **QoS 规则集**：`mesh_flow_ruleset`（L3/L4 allow/deny），运行时热更新
  `mesh_flow_ruleset_raft`（epoch + applied_index）；决策含 peer identity 审计
- 管理 agent 准入回调 `mesh_mgmt_agent_admit_peer_fn`（外部成员策略，NULL 即 fail-closed）

示例（C）：

```c
mesh_flow_ruleset_v1_t ruleset;          /* 调用方需先 zero-init */
mesh_flow_rule_v1_t rules[1] = {0};
mesh_flow_ruleset_init_v1(&ruleset, 4u, MESH_FLOW_ACTION_ALLOW);
rules[0].rule_id = 1u;
rules[0].src_network_ip = 0x0a630000u;   /* 10.99.0.0/16 */
rules[0].src_prefix_len = 16u;
rules[0].directions = MESH_FLOW_DIRECTION_ANY;
rules[0].action = MESH_FLOW_ACTION_DENY;
mesh_flow_ruleset_apply_replace_v1(&ruleset, 1u, 1u, MESH_FLOW_ACTION_ALLOW, rules, 1u);
```

测试：`test_mesh_flow_ruleset`、`test_mesh_flow_ruleset_raft`、`test_mesh_stream_cluster`。

## 5. 身份 / 证书 / 安全

- `mesh_mgmt_identity`：Ed25519/X25519 身份；`meshctl genkey` 生成节点密钥
- `mesh_mgmt_peer_signer`：对端身份签名；`mesh_mgmt_envelope`：签名信封（mesh id 哈希、
  origin node id、epoch、incarnation、序列号）
- `mesh_mgmt_replay`：防重放（origin_sequence 单调）
- `mesh_mgmt_session` + `mesh_stream_coronet_adapter`：TLS 1.3 identity bind /
  channel binding（RFC 9266 导出器）
- 传输加密：CoroNet TLS 1.3；KCP 支持 PSK（`turbo_kcp_config_t.pre_shared_key`）

测试：`test_mesh_mgmt_identity`、`test_mesh_mgmt_peer_signer`、`test_mesh_mgmt_envelope`、
`test_mesh_mgmt_replay`、`test_mesh_stream_coronet`。

## 6. 成员与对等管理

- `mesh_mgmt_agent_runtime`：单事件循环组合根，含 `endpoint_pool`、`endpoint_publisher`、
  `service_publisher`、bootstrap 连接、peer 断开/失败回调、`admit_peer` 回调
- `mesh_mgmt_peer` / `mesh_mgmt_p2p_peer` / `mesh_mgmt_p2p_adapter`：p2p 对等适配
- `mesh_mgmt_endpoint_record` + `mesh_mgmt_record_epoch`：端点记录与 epoch 分配

测试：`test_mesh_mgmt_p2p_adapter`、`test_mesh_mgmt_endpoint_pool`、`test_mesh_mgmt_endpoint_record`。

## 7. 控制面（raft 元数据）

- `m3_raft_node`：`m3_raft_node_create/poll/run_until`、`propose_put/tombstone/update_placement`、
  `is_leader/leader`、`disconnect_peer`、`status/list/lookup`（`mesh/src/m3_raft_node.h`）
- `mesh_control_raft_service`：控制服务 `open/tick/step/poll`
- 多节点 raft 部署脚本：`mesh/scripts/run_m3_raft_cluster.ps1`

测试：`test_m3_raft_cluster`、`test_m3_gateway_raft`、`test_mesh_control_raft_service`。

## 8. 分布式执行 / 任务管理

- `mesh_mgmt_execution_*`：orchestrator / runner / worker / store / result / wire /
  rpc registry + control（远程执行调度）
- `mesh_task_lease` / `mesh_task_lease_raft` / `mesh_task_execution_guard`：任务租约与执行护栏
- `mesh_control_*`：类型化 desired-state 资源、签名 MMP、agent WAL/checkpoint、operation/receipt
  和有界 provider reconcile
- `mesh_node_control_flowmq_network_provider`：把 Network APPLY/DELETE 从 `mesh-agent` 通过本机
  FlowMQ/mTLS 交给唯一持有 fabric 的 `meshd`
- `mesh_control_execution_provider` + `mesh_mgmt_execution_process`：把预部署且 digest 绑定的
  Native/TurboWASM assignment 交给独立子进程，并强制 durable claim、deadline、输出上限、
  lost-ACK replay、重启 indeterminate fencing 和进程树清理

### 8.1 当前可执行的生产链原语

`事实`：当前代码已经能用类型化原语定义 Network desired state，并触发节点上的预注册功能：

```text
operator / product API
  -> Controller durable outbox
  -> agent outbound H2/mTLS typed sync
  -> agent authenticated WAL + policy admission
  -> Network: FlowMQ/mTLS -> meshd -> userspace fabric reconcile
     Function: bounded provider -> isolated Native/TurboWASM child
  -> retained RESULT -> result WAL -> observed state -> exact ACK
```

这不是通用 `map/reduce`，也不是把命令作为 `pub/sub` 广播。资源/operation 是控制语义，H2 和
FlowMQ 只负责有界传输；调度可以在 Controller 端把 selector 展开为多个独立、可审计 operation，
节点端仍逐个执行带 generation、precondition、provider ID 和 digest 的确定性命令。控制消息不接受
shell、任意 argv、宿主路径、下载后执行或未预注册 native binary。

`边界`：当前 Network 执行落在 userspace multi-Network fabric，尚不等于完整 OS TUN/route/DNS/IPAM
事务；Function 只允许本机预部署的 Native/TurboWASM deployment。产品级用户/审批与 Grant 签发、
Controller 数据库、跨节点 observation/audit 汇总、service-manager 安装、平台 keystore 和自动证书轮换
仍是发布门槛。因此可以称为“原语和进程链已接通”，不能称为多租户控制产品已经完成。

RPC 动作：`meshctl rpc ... task-model`（查询任务模型）。

测试：`test_mesh_mgmt_execution_*`、`test_mesh_task_lease`、`test_mesh_task_lease_raft`、
`test_mesh_task_execution_guard`、`test_mesh_mgmt_execution_rpc_registry`。

## 9. 服务发布与发现

- `mesh_mgmt_service_record`：规范服务记录（dns_name / virtual-ip / port / epoch / TTL），
  DHT key 形如 `mgmt:<mesh>:node:<node>:service:rpc`
- `mesh_mgmt_service_publisher`：服务发布；`mesh_stream_discovery`：mesh-stream/mesh-sync
  服务注册表（`mesh-stream-<hex>` / `mesh-sync-<hex>`，长 id 拆双 DNS label）
- 跨进程验证：`mesh/scripts/run_mesh_stream_cluster.ps1`（节点 A/B 分别 announce
  stream/sync，节点 C decode 发现 + QoS + 带宽统计，断言 `CLUSTER OK`）

## 10. 端到端速览（最小流程）

```powershell
# 1) 生成身份与配置
meshctl genkey
meshctl init -o node-a.yaml --node-name node-a --network-id demo --virtual-ip 10.42.0.1
meshctl init -o node-b.yaml --node-name node-b --network-id demo --virtual-ip 10.42.0.2 `
    --bootstrap 10.42.0.1:7878

# 2) 两个终端分别启动
meshctl up -c node-a.yaml
meshctl up -c node-b.yaml

# 3) 查询与多节点聚合
meshctl rpc --node 10.42.0.1 status
meshctl cluster status --node 10.42.0.1:7878,10.42.0.2:7878
```

## 相关文件

- `mesh/include/turbo_mesh.h`（mesh 网络公共 API）
- `mesh/examples/meshctl.c`（CLI：genkey/init/doctor/up/rpc/cluster + 控制台）
- `mesh/examples/mesh_config.c`、`mesh/examples/mesh_runtime_health.c`（配置与健康）
- `mesh/src/mesh_mgmt_*.h`（身份/会话/执行/服务/端点管理）
- `mesh/src/mesh_flow_ruleset.h`、`mesh/src/mesh_stream_discovery.h`
- `mesh/scripts/run_m3_raft_cluster.ps1`、`run_m3_gateway_cluster.ps1`、`run_mesh_stream_cluster.ps1`
- TurboUtils CLI 解析：`turbo_parser.h` 的 `turbo_cmd_*`（TurboUtils 安装头）

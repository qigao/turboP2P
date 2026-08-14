# `meshd`

`meshd` is the config-driven long-running `mesh + TUN` process.

It is not a full OS service manager yet. It is the first sane step away from ad-hoc example binaries.

## Commands

```text
meshd doctor -c mesh.yaml
meshd run -c mesh.yaml [--status-file status.json] [--pid-file meshd.pid] [--status-interval-ms 1000]
      [--network-control] [--network-control-port 24443]
```

## Config

`meshd` uses the same basic mesh config keys as `meshctl`.

```yaml
node_name: eu-node
network_id: dev-mesh
virtual_ip: 10.42.0.1
virtual_prefix: 16
identity_private_key_file: /etc/meshd/transport.key
listen_port: 9993
advertise_ip: 161.97.65.129
bootstrap_peers: []
status_file: /var/run/meshd/status.json
pid_file: /var/run/meshd/meshd.pid
status_interval_ms: 1000
network_control_enabled: false
mgmt_private_key_file: /etc/meshd/management.key
mgmt_certificate_file: /etc/meshd/management.cert
mgmt_trusted_issuer_key_file: /etc/meshd/management.issuer
mgmt_execution_grant_issuer_key_file: /etc/meshd/execution-grant.issuer
mgmt_mesh_id_hex: 4242424242424242424242424242424242424242424242424242424242424242
mgmt_first_record_epoch: 1
mgmt_record_epoch_file: /var/lib/meshd/management.epoch
ice_enabled: true
ice_allow_loopback: true
stun_servers:
  - stun:161.97.65.129:3479
route_rules:
  - 10.42.0.3/32=10.42.0.1,pin
local_egress_cidrs:
  - 192.168.50.0/24
local_egress_allow_cidrs:
  - 10.42.0.0/16
magic_dns_domain: dev-mesh.mesh
magic_dns_names:
  - eu-node=10.42.0.1
  - local-dev=10.42.0.2
packet_policy:
  - allow,in,src=10.42.0.2/32,dst=10.42.0.1/32,proto=tcp,dport=443
peer_allow_cidrs:
  - 10.42.0.2/32
peer_allow_node_ids:
  - 1b...<64 hex chars>...
```

Optional runtime flags can override:

- `status_file`
- `pid_file`
- `status_interval_ms`
- `network_control_enabled` via `--network-control`
- `network_control_port` via `--network-control-port`

Stable identity notes:

- deployable `meshd` profiles use `identity_private_key_file`; the file contains
  exactly one 32-byte X25519 private key encoded as 64 hexadecimal characters
- Linux requires a regular, non-symlink file owned by the daemon uid with no
  group/other permission bits (`chmod 600` is the normal profile)
- Windows requires a regular, non-reparse file whose owner and every allow ACE
  are limited to the current service account, LocalSystem or Administrators;
  unrecognized allow ACE forms fail closed
- `identity_secret_hex` remains only for isolated development/test profiles and
  is mutually exclusive with `identity_private_key_file`; management mode
  rejects inline identity secrets
- `meshctl genkey` can generate the X25519 material, but provisioning must put
  only the 64-character private value in the protected file and keep the public
  `node_id` in `peer_allow_node_ids`
- `meshctl init` still emits an inline development config; migrate it before
  using `meshd` management mode
- when configured, the node keeps the same mesh identity across restarts
- status output reports `identity_configured`, but does not expose the secret value

Shared management identity notes:

- all six `mgmt_*` settings are optional as a group; partial configuration is rejected
- management mode requires a stable `identity_private_key_file`
- key and issuer files contain exactly 32 bytes encoded as 64 hexadecimal characters
- `mgmt_execution_grant_issuer_key_file` is optional and must be distinct from the
  management certificate issuer; when present it enables targeted node execution
- node execution startup requires the local management certificate to include the
  Operator role and advertises `TARGETED_RPC` plus `NODE_EXECUTION`
- the certificate file contains exactly 354 bytes encoded as 708 hexadecimal characters
- whitespace is allowed in those files; other characters and incorrect lengths are rejected
- startup verifies certificate signature, mesh id, management key and the live P2P transport identity
- both the transport private key and `mgmt_private_key_file` use the strict
  private-file checks above; certificate and issuer files are public material
- private-key parsing has a 4 KiB total input cap and retains only the fixed
  decode buffer; oversized input is rejected even when it contains only whitespace
- temporary 32-byte transport key storage is wiped immediately after
  `mesh_create()` copies it into the P2P identity owner; failures never fall
  back to an ephemeral identity
- `mgmt_first_record_epoch` initializes `mgmt_record_epoch_file` only when the state file does not
  exist; once created, the state file is the sole source of the next signed record sequence
- each endpoint or RPC service sequence is atomically reserved and fsynced before signing; an
  invalid, exhausted or unwritable state file prevents management startup or publication
- `meshd` holds a non-blocking exclusive lock on `<mgmt_record_epoch_file>.lock` for the complete
  management runtime lifetime; a second process using the same state fails during startup
- management and mesh traffic share the mesh listener, P2P identity and `mesh_poll()` event loop
- when RPC is enabled, `meshd` republishes its signed virtual RPC service every 10 seconds

FlowMQ Network control:

`network_control_enabled` is default-off. A build with
`TURBOP2P_ENABLE_FLOWMQ_IPC` may enable the typed local Network control owner
with the following flat keys (the existing config reader does not interpret
nested YAML objects):

```yaml
network_control_enabled: true
network_control_port: 24443
network_control_certificate_file: /etc/meshd/network-control-server.pem
network_control_private_key_file: /etc/meshd/network-control-server.key
network_control_client_ca_file: /etc/meshd/network-control-client-ca.pem
network_control_identity: meshd:node-01
network_control_expected_peer_identity: mesh-agent:node-01
network_control_expected_peer_certificate_sha256: sha256:<64 lowercase hex characters>
network_control_expected_peer_certificate_sha256_next: ""
network_control_identity_policy_generation: 1
network_control_mesh_id_hex: <sha256(network_id), 64 hex characters>
network_control_provider_id_hex: <stable provider id, 64 hex characters>
network_control_membership_issuer_id_hex: <issuer key id, 64 hex characters>
network_control_membership_issuer_key_file: /etc/meshd/network-membership.issuer
network_control_network_capacity: 16
network_control_operation_capacity: 256
network_control_channel_capacity: 256
network_control_channel_max_retained_bytes: 16777216
network_control_command_budget: 32
network_control_send_budget: 32
network_control_io_timeout_ms: 1000
network_control_heartbeat_interval_ms: 1000
network_control_heartbeat_timeout_ms: 5000
network_control_delete_drain_timeout_ms: 5000
network_control_shutdown_drain_timeout_ms: 5000
```

- the listener is fixed to `127.0.0.1`, TLS/mTLS, one connection,
  `/mesh-node-control`, and `mesh.node.control`; Pipe, raw TCP and automatic
  fallback are rejected
- all credential paths and exact identities are required when enabled;
  `identity_private_key_file` is also required so the shared Mesh underlay has
  a stable node identity
- the issuer file contains exactly one 32-byte Ed25519 public key encoded as
  64 hexadecimal characters; the configured issuer id selects that key for
  signed membership-ticket verification
- `network_control_mesh_id_hex` must equal SHA-256 of `network_id`; a mismatch
  fails before the listener starts
- `mesh_fabric_t` becomes the single underlay owner. Existing TUN, management,
  stream and RPC code borrow its compatibility handle and must not stop or
  destroy it directly
- normal shutdown stops command admission, waits for exact RESULT ACKs, detaches
  all controlled Networks, then stops the underlay. On deadline expiry `meshd`
  explicitly reports abandoned volatile results and exits nonzero
- `meshd` 启动时在创建 endpoint 前固定进程级 TLS 1.3-only profile；FlowMQ ROUTER/CONNECT 在
  admission/READY 前分别验证 client/server certificate 与 HELLO identity 的 current/next exact map
- 同进程真实 mTLS 测试已覆盖独立 server/client current/next leaf、双方未映射或 old-pin 证书拒绝、
  双向 EKU 错配、真实 overlap 和 listener restart 重认证；有界父/子进程测试也已使用不同端证书完成
  typed mTLS 往返。显式 client TLS config 禁用 session cache，核心链路可称为 certificate-bound
  identity。远程 H2 agent composition 已实现 current/next client leaf reload、证书/HELLO exact binding
  和存量 session fencing；`mesh-agent` 也已将有界 Network provider 接到该 FlowMQ endpoint，并在
  result WAL durable、observed state 更新后才 exact-ACK `meshd` 的 retained result。shared multi-tenant
  production profile 仍需本地通道无停机自动换证、生产签发/平台私钥存储、service-manager 与审计门槛，详见
  [`FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md`](../FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md)

对应的 `mesh-agent` 必须使用独立 client leaf，并固定 `meshd` 的 HELLO identity 与 current/next leaf。
启用项是 all-or-nothing；endpoint 不可达或身份校验失败时 agent 启动 fail closed，不回退 Pipe/plain：

```powershell
mesh-agent <required-controller-and-state-options> `
  --network-control-port 24443 `
  --network-control-ca C:\ProgramData\TurboP2P\pki\meshd-ca.pem `
  --network-control-cert C:\ProgramData\TurboP2P\pki\mesh-agent-flowmq.pem `
  --network-control-key C:\ProgramData\TurboP2P\pki\mesh-agent-flowmq.key `
  --network-control-identity mesh-agent:node-01 `
  --network-control-peer-identity meshd:node-01 `
  --network-control-peer-cert-sha256 sha256:<64-lowercase-hex> `
  --network-control-provider-id <64-hex-provider-id> `
  --network-control-policy-generation 1
```

Node execution RPC:

- `POST /v1/executions` accepts one canonical binary `COMMAND_REQUEST` body
- `GET /v1/executions/{correlation_id}` accepts an exact 64-character hexadecimal id
- both endpoints require `X-Meshd-Token` and never expose a physical peer address
- duplicate immutable bindings are idempotent and are not sent twice
- definitive pre-send failures are removed; ambiguous sends remain pending until a
  verified response or deadline timeout
- nodes without a configured execution worker return an authenticated
  `COMMAND_STATUS` with `STATUS_DISABLED`; they never silently discard a request

Local isolated execution is disabled unless the same YAML file contains a
complete policy. A mixed Native/TurboWASM catalog uses:

```yaml
mgmt_execution_mode: prestaged_isolated
mgmt_execution_store_file: C:/ProgramData/TurboP2P/execution.journal
mgmt_execution_worker_program: C:/Program Files/TurboP2P/mesh-execution-worker.exe
mgmt_execution_worker_sha256: <64 lowercase hex characters>
mgmt_execution_sandbox_program: C:/Program Files/TurboP2P/mesh-sandbox.exe
mgmt_execution_sandbox_sha256: <64 lowercase hex characters>
mgmt_execution_sandbox_args: --profile,C:/ProgramData/TurboP2P/sandbox.json,--
mgmt_execution_max_worker_bytes: 67108864
mgmt_execution_max_output_bytes: 65536
mgmt_execution_worker_queue_capacity: 64
mgmt_execution_egress_capacity: 64
mgmt_execution_capabilities: core,utils,app
mgmt_execution_module_bytes: 67108864
mgmt_execution_stack_bytes: 1048576
mgmt_execution_linear_memory_bytes: 67108864
mgmt_execution_timeout_ms: 30000
mgmt_execution_control_flow_steps: 10000000
mgmt_execution_host_calls: 1024
mgmt_execution_copied_guest_bytes: 16777216
mgmt_execution_input_bytes: 4096
mgmt_execution_stdout_bytes: 65536
mgmt_execution_stderr_bytes: 65536
mgmt_execution_deployments:
  - "wasm,<32-hex-deployment-id>,1,<64-hex-sha256>,C:/apps/task.wasm"
  - "native,<32-hex-deployment-id>,1,<64-hex-sha256>,C:/apps/task.exe"
```

- The four-field legacy deployment form remains WASM-compatible; the tagged
  five-field form is required for Native and recommended for both runtimes.
- Deployment IDs are exactly 16 bytes/32 hexadecimal characters. Older local
  examples that used 64 characters relied on an invalid decoder and must be
  corrected before enabling execution.
- `meshd` verifies the worker and sandbox-launcher SHA-256 before every spawn.
  Production initialization fails without a sandbox launcher; direct child
  execution exists only behind the explicit test flag in the internal API.
- Sandbox arguments are a comma-separated list of at most eight arguments,
  each smaller than 1024 bytes. They are passed as argv entries without a
  shell, deep-copied by the process owner, and followed by the exact worker or
  Native module path. A launcher must treat the final path as an executable,
  not as a shell command. On Linux this boundary can pin a reviewed
  `bubblewrap` profile; Windows deployments need an equivalently reviewed
  restricted-token/AppContainer launcher.
- Native and WASM runtime kinds must match the signed Grant operation. Native
  receives only the configured exact capability profile; it is never loaded
  into `meshd`. TurboWASM runs in the dedicated child and receives only its
  bounded runtime capabilities. The raw-WASM loader currently requires exactly
  `core,utils,app`; partial profiles and extra HTTP/file capabilities fail at
  initialization because no immutable application manifest is bound yet.
- The parent retains Grant verification, durable state transitions, result
  signing and terminal commit. Worker stdin/stdout/stderr, timeout and retained
  output are bounded, and the process group/Windows Job Object is reaped on
  timeout or shutdown.
- `mesh-agent` derives provider-exclusive `<mgmt_execution_store_file>.wasm-control`
  and `.native-control` journals. The configured base path must therefore be
  absolute and its parent directory must already exist. Claims are persisted
  before child start; lost terminal ACKs replay the signed result, while a
  recovered RUNNING claim fails indeterminate and is never executed again.

ICE-related config notes:

- `ice_enabled`: turns on ICE signaling and connectivity checks
- `ice_allow_loopback`: useful for local validation on one host
- `stun_servers`: list of `stun:host:port`
- `route_rules`: optional operator-pinned route policy entries in `DEST_CIDR=NEXT_HOP_VIRTUAL_IP,pin` form
- `local_egress_cidrs`: optional router-side local egress CIDRs; use `0.0.0.0/0` for an exit-node role
- `local_egress_allow_cidrs`: optional source virtual CIDRs allowed to use configured local egress
- `magic_dns_domain`: optional suffix for local static mesh-name records
- `magic_dns_names`: optional `name=virtual_ip` records; IPs must be inside the mesh virtual prefix
- `packet_policy`: optional static packet rules by direction, CIDR, protocol, and port
- `peer_allow_cidrs`: optional direct-peer admission allowlist by virtual IP/CIDR
- `peer_allow_node_ids`: secure-wire trust store of stable node identities; required for multi-node operation
- `peer_protocol_major`: optional direct-peer admission policy by mesh protocol major

Current EU-hosted STUN endpoint used by mesh examples:

- `stun:161.97.65.129:3479`

That endpoint is served by the same `turbo-webrtc/ice/examples/stun_service.c`
codepath, not by a third-party STUN provider.

## What It Does

- starts the TUN device in raw packet mode
- starts the mesh node from YAML config
- bridges `TUN -> mesh` and `mesh -> TUN`
- writes a machine-readable JSON status snapshot periodically
- status JSON now includes a compact `health` section for automation
- status JSON exposes bounded `network_control` lifecycle, attached-Network,
  retained-operation, queue-byte and transport counters without credential data
- writes a pid file while the process is alive
- handles shutdown signals by letting the main loop stop mesh and tunnel cleanly
- on POSIX, `SIGHUP` requests an immediate status-file refresh without restarting the node

Signal behavior:

- `SIGINT` / `SIGTERM`: request shutdown; cleanup runs in the main loop
- `SIGHUP` on POSIX: flush the status snapshot now
- Windows console close / Ctrl-C / Ctrl-Break: request shutdown; cleanup runs in the main loop

## Doctor

`meshd doctor` is no longer just a YAML syntax check.

It now verifies:

- config parses and validates
- the configured transport private-key file type, owner, permissions/ACL and exact encoding
- `listen_port` can bind on `0.0.0.0`
- tunnel prerequisites are present
- each configured bootstrap peer is reachable over TCP
- `status_file` path is writable when configured
- `pid_file` path is writable when configured

Platform behavior:

- Linux: checks `/dev/net/tun` access and requires root
- Windows: checks `wintun.dll` is discoverable and reminds you that an elevated shell is still required

## First Start

For a first two-node bring-up, use one node as the bootstrap node and keep its
`bootstrap_peers: []`. Point the joining node at that bootstrap listener.

Recommended order:

1. Generate a stable identity for each node, provision its 64-character private
   value into an owner-only `identity_private_key_file`, and distribute only the
   corresponding public `node_id` to peer trust configuration.
2. Run `meshd doctor` on the bootstrap node config, then start that node with
   `meshd run`.
3. Run `meshd doctor` on the joining node config only after the bootstrap node
   is already listening, because `meshd doctor` checks each configured
   bootstrap peer for TCP reachability.
4. Start the joining node with `meshd run`.
5. Confirm that the status JSON shows a connected direct peer.

## Identity Migration

This is a hard configuration migration for managed daemon profiles:

1. Stop the node; do not rotate the key during this migration.
2. Copy the exact old `identity_secret_hex` value into a newly protected key
   file, without the YAML key name or other text.
3. On POSIX, set the owner to the daemon uid and mode to `0600`. On Windows,
   grant allow ACEs only to the service account, LocalSystem and Administrators.
4. Replace `identity_secret_hex` in YAML with `identity_private_key_file`.
5. Run `meshd doctor`; any unreadable, linked, broadly accessible or malformed
   file must fail before network startup.
6. Start the node and verify that its public `node_id` is unchanged.

The public `mesh_config_t` layout also gained the borrowed
`identity_private_key`, `identity_private_key_size`,
`identity_private_key_provider`, and
`identity_blocking_private_key_provider` fields. This changes the C ABI layout; all
consumers of the shared Mesh library must be rebuilt together. Raw bytes are
borrowed only for `mesh_create()`. The provider structure is also borrowed only
during create because P2P copies its operations, but its context must remain
valid until `mesh_destroy()` returns.

`meshd` currently exposes the strict private-key file mode. An embedding may
set `identity_private_key_provider` to a non-blocking, bounded-time
`p2p_private_key_provider_v3_t`, or set
`identity_blocking_private_key_provider` to a
`p2p_blocking_private_key_provider_v4_t`. All raw/inline/provider identity
sources are mutually exclusive. V4 supplies the bounded worker, deadline,
cancel and drain boundary needed by a blocking TPM or network HSM SDK; a
concrete hardware adapter and hardware fault-injection suite are still required
before claiming that deployment profile is production-ready.

## Status File

The status file is written atomically through a temp file replacement.

Current JSON sections:

- `snapshot_version`
- `node`
- `runtime`
- `security`
- `mesh`
- `control_plane`
- `dht`
- `diagnostics`
- `health`
- `tunnel`
- `direct_peers`
- `relay_routes`
- `route_policy`
- `peer_admission`

Example:

```json
{
  "snapshot_version": 2,
  "node": {
    "name": "meshd-test",
    "network_id": "meshd-test",
    "virtual_ip": "10.42.9.1",
    "virtual_prefix": 16,
    "advertise_ip": "",
    "node_id": "<64 hex chars>",
    "protocol_major": 1,
    "protocol_minor": 0,
    "listen_port": 10993
  },
  "runtime": {
    "running": true,
    "uptime_ms": 1532
  },
  "security": {
    "available": true,
    "wire_version": 2,
    "noise_suite": "Noise_XX_25519_ChaChaPoly_BLAKE2s",
    "send_budget": {
      "limit_bytes": 67108864,
      "reserved_bytes": 0,
      "available_bytes": 67108864
    },
    "private_key_executor": {
      "available": false
    },
    "handshake_latency": {
      "bucket_upper_bounds_ms": [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, null]
    }
  },
  "control_plane": {
    "summary": {
      "direct_peers": 0,
      "relay_routes": 0,
      "route_policy": 0,
      "peer_admission": 0,
      "peer_identity_admission": 0,
      "peer_protocol_major_policy": 0,
      "dht_entries": 2
    }
  },
  "mesh": {
    "direct_peers": 0,
    "relay_routes": 0,
    "route_policy": 0,
    "peer_admission": 0,
    "peer_identity_admission": 0,
    "peer_protocol_major_policy": 0,
    "peer_count": 0
  },
  "dht": {
    "entry_count": 2
  },
  "health": {
    "state": "degraded",
    "reason": "awaiting_peers",
    "summary": "node is listening and waiting for peers"
  },
  "diagnostics": {
    "path_mode": "isolated",
    "bootstrap_connect_attempts": 0,
    "direct_connect_attempts": 0,
    "last_reconnect_reason": "",
    "last_direct_attempt_endpoint": "",
    "ice": {
      "enabled": true,
      "peer_count": 0,
      "connected_peer_count": 0,
      "auth_tx": 0,
      "auth_rx": 0,
      "candidate_tx": 0,
      "candidate_rx": 0,
      "last_state": "",
      "last_selected_local_endpoint": "",
      "last_selected_remote_endpoint": ""
    },
    "last_active_relay_next_hop": {
      "virtual_ip": "",
      "real_endpoint": ""
    }
  }
}
```

## Verified

Verified on EU Linux build:

```text
meshd doctor -c /tmp/meshd-test.yaml
meshd run -c /tmp/meshd-test.yaml --status-file /tmp/meshd-status.json --pid-file /tmp/meshd.pid --status-interval-ms 500
```

For a repeatable remote TUN/status-file check on the EU host, use:

```text
bash /root/code/turbo-p2p/run_meshd_remote_status_check.sh
```

From Windows PowerShell, the matching routed entrypoint is:

```text
.\run_meshd_status_check.ps1 -Target Remote -Action Run
.\run_meshd_status_check.ps1 -Target Remote -Action Status
```

That helper runs `meshd` inside `tmux`, waits for the status file, and verifies:

- `snapshot_version`
- `node.node_id`
- `node.protocol_major`
- `node.protocol_minor`
- `control_plane.summary.dht_entries`
- `control_plane.health.state`
- `tunnel.rx_packets`

Current `direct_peers[]` fields in the status file:

- `virtual_ip`
- `real_endpoint`
- `node_id`
- `protocol_major`
- `protocol_minor`

Current `node` identity/version fields in the status file:

- `node_id`
- `protocol_major`
- `protocol_minor`

Current `peer_admission` status-file fields:

- `cidrs[]`
- `node_ids[]`
- `protocol_major`

For a repeatable remote two-node bring-up check on the same host, use:

```text
bash /root/code/turbo-p2p/run_meshd_remote_pair_check.sh
```

From Windows PowerShell, the matching routed entrypoint is:

```text
.\run_meshd_pair_check.ps1 -Action Run
.\run_meshd_pair_check.ps1 -Action Status
```

That pair helper starts `mesh.eu.yaml` first, then `mesh.local.yaml`, and verifies:

- both status files parse as JSON
- both nodes report `snapshot_version=2`
- bootstrap sees connected peer `10.42.0.2`
- joiner sees connected peer `10.42.0.1`
- both nodes expose at least one direct peer

Observed:

- doctor reports real runtime blockers before startup
- process starts
- TUN comes up
- mesh starts listening
- status JSON is written
- status JSON now carries top-level `snapshot_version`, bounded `security`, and grouped `control_plane`
- diagnostics JSON includes reconnect counters and live `path_mode`
- health JSON summarizes whether the node currently has a usable path
- DHT JSON shows cached control-plane keys known to this node
- diagnostics JSON includes ICE counters and last selected endpoints
- cleanup removes pid file on exit

## What It Is Not Yet

- not a Windows service
- not a systemd unit
- not a hot-reload daemon
- `SIGHUP` only refreshes status output; it does not reload mesh, route, ICE, or tunnel config
- not a supervisor
- not a privilege manager

## Current ICE Boundary

`meshd` now exposes ICE configuration and diagnostics, and direct peers can already
switch their raw packet data plane over to the selected ICE pair.

Today the boundary is:

- direct-peer packet transport can use the selected ICE pair
- relay routing still stays on the existing P2P transport
- diagnostics tell you whether ICE is progressing and which endpoints won

That is intentional. It keeps the current working relay path intact while
end-to-end NAT-traversed direct upgrades across relay-learned peers are still
being expanded.

## Current Route Policy Boundary

Current route policy is intentionally narrow:

- config-driven only
- longest-prefix match
- `pin` only
- enforced in mesh forwarding instead of mutating the learned route table

That means:

- learned relay routes remain observed state
- `route_policy` is operator intent
- if a `pin` matches, the configured next hop wins even over a direct peer
- if that next hop is unavailable, the send fails instead of silently rerouting

## Current Admission Control Boundary

Current admission control is also intentionally narrow:

- direct-peer allowlist by virtual IP / CIDR
- secure-wire trust store by stable transport node ID
- enforced when `MESH_HELLO` identifies the peer
- direct-connect attempts and direct ICE upgrades honor the same allowlist

That means:

- an empty virtual-IP list does not restrict virtual IPs
- an empty node-ID trust store permits isolated startup only and rejects every remote Noise identity
- a configured list rejects non-matching direct neighbors
- routed traffic policy is limited to explicit route pins, router-side
  `local_egress_cidrs`, and source CIDR checks via
  `local_egress_allow_cidrs`
- `packet_policy` can filter data-plane packets statically, but richer
  user/tag/service ACLs are not implemented yet

## Current Packet Policy Boundary

Packet policy is static local configuration:

- directions are `in`, `out`, `forward`, `local-egress`, or `any`
- rules can match source CIDR, destination CIDR, IP protocol, source port, and destination port
- no rules for a direction means compatible allow
- once a direction has at least one rule, unmatched packets in that direction are dropped
- first matching rule decides

It does not yet understand users, tags, processes, named services, audit-only
rules, policy epochs, or controller-distributed policy.

## Current MagicDNS Boundary

Current MagicDNS support is local static configuration:

- `magic_dns_domain` sets the optional suffix for short records
- `magic_dns_names` maps configured names to mesh virtual IPs
- names are normalized to lowercase
- reverse lookup can return configured names with the suffix applied

It does not yet run a DNS server, install OS search domains, distribute names
through the control plane, or synthesize records from live peer state.

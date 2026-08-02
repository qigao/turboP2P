# `meshd`

`meshd` is the config-driven long-running `mesh + TUN` process.

It is not a full OS service manager yet. It is the first sane step away from ad-hoc example binaries.

## Commands

```text
meshd doctor -c mesh.yaml
meshd run -c mesh.yaml [--status-file status.json] [--pid-file meshd.pid] [--status-interval-ms 1000]
```

## Config

`meshd` uses the same basic mesh config keys as `meshctl`.

```yaml
node_name: eu-node
network_id: dev-mesh
virtual_ip: 10.42.0.1
virtual_prefix: 16
identity_secret_hex: 0101010101010101010101010101010101010101010101010101010101010101
listen_port: 9993
advertise_ip: 161.97.65.129
bootstrap_peers: []
status_file: /var/run/meshd/status.json
pid_file: /var/run/meshd/meshd.pid
status_interval_ms: 1000
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

Stable identity notes:

- `identity_secret_hex` is optional and must be a 64-character hex-encoded private key
- generate one with `meshctl genkey`, then copy the printed `identity_secret_hex` into YAML
- or use `meshctl init -o mesh.yaml ...` to write a starter config with a fresh identity in one step
- when configured, the node keeps the same mesh identity across restarts
- status output reports `identity_configured`, but does not expose the secret value

Shared management identity notes:

- all six `mgmt_*` settings are optional as a group; partial configuration is rejected
- management mode requires a stable `identity_secret_hex`
- key and issuer files contain exactly 32 bytes encoded as 64 hexadecimal characters
- `mgmt_execution_grant_issuer_key_file` is optional and must be distinct from the
  management certificate issuer; when present it enables targeted node execution
- node execution startup requires the local management certificate to include the
  Operator role and advertises `TARGETED_RPC` plus `NODE_EXECUTION`
- the certificate file contains exactly 354 bytes encoded as 708 hexadecimal characters
- whitespace is allowed in those files; other characters and incorrect lengths are rejected
- startup verifies certificate signature, mesh id, management key and the live P2P transport identity
- `mgmt_first_record_epoch` initializes `mgmt_record_epoch_file` only when the state file does not
  exist; once created, the state file is the sole source of the next signed record sequence
- each endpoint or RPC service sequence is atomically reserved and fsynced before signing; an
  invalid, exhausted or unwritable state file prevents management startup or publication
- `meshd` holds a non-blocking exclusive lock on `<mgmt_record_epoch_file>.lock` for the complete
  management runtime lifetime; a second process using the same state fails during startup
- management and mesh traffic share the mesh listener, P2P identity and `mesh_poll()` event loop
- when RPC is enabled, `meshd` republishes its signed virtual RPC service every 10 seconds

Node execution RPC:

- `POST /v1/executions` accepts one canonical binary `COMMAND_REQUEST` body
- `GET /v1/executions/{correlation_id}` accepts an exact 64-character hexadecimal id
- both endpoints require `X-Meshd-Token` and never expose a physical peer address
- duplicate immutable bindings are idempotent and are not sent twice
- definitive pre-send failures are removed; ambiguous sends remain pending until a
  verified response or deadline timeout
- nodes without a configured execution worker return an authenticated
  `COMMAND_STATUS` with `STATUS_DISABLED`; they never silently discard a request

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
- `peer_allow_node_ids`: optional direct-peer admission allowlist by stable node identity
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

1. Generate a stable identity for each node with `meshctl genkey`, or write a
   starter config with `meshctl init -o mesh.yaml ...`.
2. Run `meshd doctor` on the bootstrap node config, then start that node with
   `meshd run`.
3. Run `meshd doctor` on the joining node config only after the bootstrap node
   is already listening, because `meshd doctor` checks each configured
   bootstrap peer for TCP reachability.
4. Start the joining node with `meshd run`.
5. Confirm that the status JSON shows a connected direct peer.

## Status File

The status file is written atomically through a temp file replacement.

Current JSON sections:

- `snapshot_version`
- `node`
- `runtime`
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
  "snapshot_version": 1,
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
- both nodes report `snapshot_version=1`
- bootstrap sees connected peer `10.42.0.2`
- joiner sees connected peer `10.42.0.1`
- both nodes expose at least one direct peer

Observed:

- doctor reports real runtime blockers before startup
- process starts
- TUN comes up
- mesh starts listening
- status JSON is written
- status JSON now carries top-level `snapshot_version` plus grouped `control_plane`
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
- enforced when `MESH_HELLO` identifies the peer
- direct-connect attempts and direct ICE upgrades honor the same allowlist

That means:

- an empty list still allows all peers
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

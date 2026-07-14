# Meshctl MVP

`meshctl` is the week-1 CLI for validating a two-node developer mesh.

## Commands

```text
meshctl genkey
meshctl init -o mesh.yaml
meshctl doctor -c mesh.yaml
meshctl up -c mesh.yaml
```

While `up` is running, use these local commands:

```text
status
status json
health
health json
dht
dht json
peers
peers json
routes
routes json
policy
policy json
admission
admission json
dump
dump json
diag
diag json
ping [virtual-ip]
help
quit
```

`status json`, `health json`, `dht json`, `peers json`, `routes json`, `policy json`, `admission json`, and `dump json` are stable machine-friendly exports.

Current automation schema notes:

- top-level `snapshot_version` is now emitted by `status json` and `dump json`
- `control_plane` is a stable grouped view for automation consumers
- `control_plane` currently groups `summary`, `dht`, `health`, and `diagnostics`
- legacy top-level fields remain for compatibility

- `status` focuses on node counters, direct/relay totals, and live `path_mode`
- `health` emits a compact automation-friendly state with `healthy` / `degraded` / `unhealthy`
- `dht` shows cached mesh control-plane DHT entries known to this node
- `peers` shows direct neighbors with `real_endpoint`, `node_id`, state, and byte counters
- `routes` shows learned relay paths with `next_hop`, `next_hop_real_endpoint`, and `hop_count`
- `policy` shows configured route-policy rules, separate from learned relay routes
- `admission` shows the configured direct-peer admission allowlist
- `dump` combines node config, counters, diagnostics, direct peers, and relay routes in one payload
- `diag` is an alias for `dump`

Generate a stable identity keypair:

```text
meshctl genkey
identity_secret_hex: 6f...<64 hex chars>...
node_id: 1b...<64 hex chars>...
# keep identity_secret_hex private
```

Generate a starter config file:

```text
meshctl init -o mesh.local.yaml --node-name local-dev --virtual-ip 10.42.0.2 --listen-port 9994 --bootstrap 161.97.65.129:9993 --stun stun:161.97.65.129:3479
Wrote starter config: mesh.local.yaml
node_id: 1b...<64 hex chars>...
```

`meshctl init` writes a new YAML file, generates a fresh `identity_secret_hex`, and refuses to overwrite an existing path.

## Config

```yaml
node_name: local-dev
network_id: dev-mesh
virtual_ip: 10.42.0.2
virtual_prefix: 16
identity_secret_hex: 0202020202020202020202020202020202020202020202020202020202020202
listen_port: 9994
bootstrap_peers:
  - 161.97.65.129:9993
ice_enabled: true
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
  - local-dev=10.42.0.2
  - eu-node=10.42.0.1
packet_policy:
  - allow,out,src=10.42.0.2/32,dst=10.42.0.1/32,proto=tcp,dport=443
  - allow,in,src=10.42.0.1/32,dst=10.42.0.2/32,proto=tcp,sport=443
peer_allow_cidrs:
  - 10.42.0.1/32
peer_allow_node_ids:
  - 1b...<64 hex chars>...
```

Current example STUN endpoint:

- `stun:161.97.65.129:3479`

Stable identity notes:

- `identity_secret_hex` is optional and must be exactly 64 hex characters
- `meshctl genkey` prints a valid `identity_secret_hex` plus the derived `node_id`
- `meshctl init` writes a starter config file with a freshly generated `identity_secret_hex`
- if unset, the node uses an ephemeral identity and its mesh node id changes on restart
- `meshctl status` / `dump` report whether identity is configured, but do not print the secret

Current route-policy format:

- `DEST_CIDR=NEXT_HOP_VIRTUAL_IP,pin`
- example: `10.42.0.3/32=10.42.0.1,pin`

Current semantics:

- longest-prefix match wins
- `pin` is authoritative
- when a `pin` matches, mesh uses that configured next hop even if a direct peer exists
- when the configured next hop is not connected, send fails instead of falling back silently
- non-mesh destinations are sent only when a pinned rule matches

Current local-egress format:

- `local_egress_cidrs:` list of non-mesh CIDRs this node will deliver to its local TUN/egress callback
- `local_egress_allow_cidrs:` optional source virtual CIDRs allowed to use local egress
- example subnet router: `192.168.50.0/24`
- example exit node: `0.0.0.0/0`
- when `local_egress_allow_cidrs` is unset, any source inside the mesh virtual prefix may use a matching local egress
- absent or non-matching local egress drops received non-mesh packets fail-closed
- non-mesh packets with a source outside the mesh virtual prefix are not delivered to local egress
- OS forwarding, route installation, and NAT remain deployment/daemon responsibilities

Current MagicDNS format:

- `magic_dns_domain:` optional suffix for short mesh names
- `magic_dns_names:` static `name=virtual_ip` records
- example: `local-dev=10.42.0.2`
- names are normalized to lowercase
- records must point at IPv4 addresses inside the configured mesh virtual prefix
- short names and names under `magic_dns_domain` resolve through the mesh API
- reverse lookup returns the configured name, with `magic_dns_domain` appended for short records
- this is not a DNS server yet; OS search-domain setup and control-plane name distribution are still outside `meshctl`

Current packet-policy format:

- `packet_policy:` list of static packet rules
- rule form: `allow|deny,<direction>,src=<cidr>,dst=<cidr>,proto=<any|icmp|tcp|udp|number>,sport=<port|start-end|any>,dport=<port|start-end|any>`
- directions: `in`, `out`, `forward`, `local-egress`, or `any`; multiple directions may be joined with `|`
- absent `src` / `dst` means `0.0.0.0/0`
- absent `proto`, `sport`, or `dport` means any
- when no rules exist for a direction, behavior stays compatible and packets are allowed by packet policy
- once at least one rule exists for a direction, packets in that direction must match an allow rule or they are dropped
- first matching rule decides

Current admission-control format:

- `peer_allow_cidrs:` list of allowed direct-peer virtual IP or CIDR entries
- example: `10.42.0.1/32`
- `peer_allow_node_ids:` optional list of allowed stable peer node IDs
- example: `1b...<64 hex chars>...`
- `peer_protocol_major:` optional direct-peer admission policy by mesh protocol major
- example: `1`

Current admission-control semantics:

- empty list means allow all peers
- if configured, only matching peers are accepted as direct neighbors during `MESH_HELLO`
- `peer_allow_cidrs` filters by claimed virtual IP
- `peer_allow_node_ids` filters by stable node identity derived from the peer public key
- `peer_protocol_major` requires peers to advertise the configured HELLO protocol major
- direct connect / direct upgrade attempts to non-matching peers are suppressed
- this is admission control; use `packet_policy` for static packet filtering

## First Start

For a first two-node bring-up, treat `mesh.eu.yaml` as the bootstrap node and
`mesh.local.yaml` as the joining node.

1. Generate a local starter config:

```text
meshctl init -o mesh.local.yaml --node-name local-dev --virtual-ip 10.42.0.2 --listen-port 9994 --bootstrap 161.97.65.129:9993 --stun stun:161.97.65.129:3479
```

2. Start the bootstrap node first:

```text
meshctl up -c mesh.eu.yaml
```

3. Validate the local config:

```text
meshctl doctor -c mesh.local.yaml
```

`meshctl doctor` only checks parse and config validation. It does not prove that
the configured bootstrap node is reachable, so the bring-up order still needs
the bootstrap node to be running first.

4. Start the local node:

```text
meshctl up -c mesh.local.yaml
```

5. Watch the periodic status output until both nodes report a connected peer.
6. Use `peers` to confirm the virtual IP on both sides, then run `ping <virtual-ip>`.
7. A successful reply prints `rtt=<n>ms`.

For Linux/tmux regression bring-up outside the unit-test binaries, use:

```text
mesh/tests/run_public_stun_suite.sh --bin-dir build/linux-gcc-debug/bin --scenario three-node
bash run_public_stun_tmux.sh --scenario matrix
bash run_public_stun_tmux.sh --action status --scenario matrix
```

`run_public_stun_suite.sh` is the direct runner.
`run_public_stun_tmux.sh` wraps the same suite in `tmux`, which is the safer path for longer
`three-node` or `matrix` runs on remote Linux hosts.

That path exercises the operator flow end to end with `meshctl init`, `meshctl doctor`, and `meshctl up`.

## Diagnostics

Human-readable snapshot:

```text
dump
```

JSON snapshot:

```text
dump json
```

Single-section JSON exports:

```text
status json
health json
dht json
peers json
routes json
policy json
admission json
```

Current DHT fields exposed by `status json`, `dht json`, and `dump json`:

- `entry_count`
- `known_entries[].label`
- `known_entries[].key`
- `known_entries[].present`
- `known_entries[].value`

Current health fields exposed by `status json`, `health json`, and `dump json`:

- `state`
- `reason`
- `summary`
- `path_mode`
- `signals.bootstrap_configured`
- `signals.bootstrap_reconnect_pending`
- `signals.has_direct_peer`
- `signals.has_relay_path`
- `signals.has_any_path`
- `signals.ice_enabled`
- `signals.ice_progressing`
- `signals.ice_failed`

Current diagnostics fields exposed by `status json` and `dump json`:

- `path_mode`
- `bootstrap_connect_attempts`
- `bootstrap_retry_rounds`
- `bootstrap_reconnect_scheduled`
- `bootstrap_reconnect_pending`
- `reconnect_poll_count`
- `direct_connect_attempts`
- `direct_connect_started`
- `peer_connect_events`
- `peer_disconnect_events`
- `control_plane_refreshes`
- `last_reconnect_reason`
- `last_direct_attempt_endpoint`
- `last_active_relay_next_hop`

Current route-policy fields exposed by `policy json` and `dump json`:

- `dest_cidr`
- `next_hop_virtual_ip`
- `flags`

Current admission fields exposed by `admission json`, `status json`, and `dump json`:

- `peer_admission`
- `peer_admission.cidrs[]`
- `peer_admission.node_ids[]`
- `peer_admission.protocol_major`
- `peer_identity_admission`
- `peer_protocol_major_policy`
- `cidr`
- `node_id`

Current `control_plane.summary` fields exposed by `status json` and `dump json`:

- `direct_peers`
- `relay_routes`
- `route_policy`
- `peer_admission`
- `peer_identity_admission`
- `peer_protocol_major_policy`
- `peer_count`
- `tx_packets`
- `rx_packets`
- `tx_bytes`
- `rx_bytes`
- `dht_entries`

Current `direct_peers` fields exposed by `peers json` and `dump json`:

- `virtual_ip`
- `real_endpoint`
- `node_id`
- `protocol_major`
- `protocol_minor`

Current node identity/version fields exposed by `status json` and `dump json`:

- `node_id`
- `protocol_major`
- `protocol_minor`

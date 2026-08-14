# Mesh Status

Current status of the `mesh/` stack as of 2026-08-14.

This file is the operational truth. Older design docs in this folder still contain historical WebRTC/ICE wording and should not be treated as the current implementation.

## Summary

- Status: `beta`, not `GA`
- Runtime: `TurboNet::CoroNet` / `CoroNet` only
- Data plane: real system ICMP and TCP verified
- Control plane: DHT-backed peer discovery and route propagation working
- Direct-path control plane: ICE signaling and connectivity checks integrated
- Recovery: leader flap recovery verified
- Topology: direct peers and learned routes are now separated cleanly
- Operator policy: config-driven pinned route rules are working
- Admission control: config-driven peer allowlists by virtual IP and stable node identity are working
- Stream admission: default-off `STREAM_V1` capability requires the P2P
  secure-wire v2 Noise XX lifecycle, identity-bound HELLO, current protocol
  major, and bilateral negotiation; the cryptographic baseline is implemented,
  but vector/interoperability/fuzz and independent-review release gates remain
- Listener admission: a fixed-capacity source-bound HMAC cookie gate now runs
  before inbound peer/Noise allocation and full transport send-budget
  reservation; the verified cookie is bound into the Noise transcript
- Daemon identity: deployable `meshd` profiles load transport and management
  private keys only from regular non-link files with owner-only POSIX modes or
  a strict Windows service-account ACL; exact decoding is bounded, temporary
  transport bytes are wiped after `mesh_create()`, and failures do not fall
  back to ephemeral identity. Embedders can supply either the synchronous
  opaque `p2p_private_key_provider_v3_t` or bounded blocking
  `p2p_blocking_private_key_provider_v4_t` through `mesh_config_t`. V4 moves
  the whole outgoing Noise static-DH message to a bounded worker with deadline,
  cancellation, capacity rejection and shutdown drain. Concrete OS/TPM/HSM
  adapters and their hardware integration tests remain release gaps
- Packet policy: static CIDR/protocol/port rules can filter outbound, inbound, relay-forwarded, and local-egress packets
- MagicDNS: local static mesh-name records are configurable; full tailnet DNS is not product complete
- Multi-network: an experimental additive V2 API can attach multiple userspace
  IPv4 Networks to one authenticated P2P underlay. `TMN2` frames, Ed25519
  membership tickets, explicit peer membership, generation fencing,
  overlapping-address isolation, bounded deterministic route snapshots,
  role-gated one-hop terminal subnet/exit delivery, digest-bound canonical
  route documents, bounded reconciler state and independent detach are
  component-tested. The standalone control agent can execute canonical Network
  APPLY/DELETE against either an injected fabric or a transport-neutral async
  provider. The `mesh-agent` executable wires that provider to local `meshd`
  through bounded FlowMQ/mTLS, persists RESULT before observed state and exact
  ACK, and issues deterministic exact-digest restore mutations after WAL restart.
  Network-scoped DHT, generic secure multihop, DNS/policy, OS TUN/VRF and
  gateway transactions and IPv6 remain absent. The transport-neutral
  `MeshNodeIPC/1` codec, bounded copied
  frame channel, single-owner operation/result state machine, and Network
  executor are component-tested. The standalone `FlowMQ::FlowMQ`
  ROUTER/DEALER adapter, client/server runtimes and a reconciler-compatible
  prestaged builtin/Native provider have same-process real-mTLS tests. An
  internal meshd composition now owns the bounded Network reconciler, typed
  executor and server runtime around a borrowed fabric; its real-mTLS test
  covers two Network APPLY operations, independent DELETE, fabric attach/detach,
  RESULT/exact ACK and shutdown drain. `meshd` now has default-off validated
  FlowMQ/mTLS configuration and uses the fabric as its sole underlay owner when
  enabled. CoroNet verified-certificate fingerprint extraction, FlowMQ ROUTER
  v4/CONNECT v3 symmetric HELLO verification, a bounded immutable exact-map,
  and mandatory Mesh adapter enforcement now exist. Same-process real-mTLS
  tests cover successful bidirectional traffic with distinct server/client
  leaves, unmapped client/server certificate rejection before admission/READY,
  real current/next leaf overlap, old-pin removal for new sessions, bidirectional
  EKU role mismatch rejection and listener-restart reauthentication. A bounded
  parent/child process test also completes one typed mTLS round trip with
  separate server/client credentials. Explicit client TLS configuration disables
  the CoroNet session cache. The remote H2 agent composition now owns durable
  local state, current/next client-certificate reload and reconnect; Controller
  identity admission validates chain/EKU/key/serial/validity/revocation and
  fences online sessions by durable generation, TLS leaf digest and policy
  generation. FlowMQ Network provider injection is present in `mesh-agent`;
  automatic local-channel certificate reload, production issuance/private-key storage and
  audit metrics remain open; the completion contract is
  [`FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md`](FLOWMQ_TLS_IDENTITY_BINDING_DESIGN.md)
- Product-control substrate: internal H1/H2 WebSocket ingress, signed MMP
  control frames, bounded ownership-transfer, desired/observed state,
  generation-consistent status pages, cursor events, and an agent lifecycle
  core are component-tested. Authenticated H1/H2 status/event pull is present;
  a bounded prestaged builtin/Native provider registry and reconciler are also
  component-tested. A typed `meshctl` client and Iris northbound adapter now
  provide bounded `nodes list/get`, `operations get`, placement plan and
  Network list/get/plan/apply/drain-delete integration contracts over explicit
  H2+mTLS. Network mutation handlers remain injected callbacks. A durable
  Controller outbox/session, bounded identity registry, typed outbound H2 agent
  state machine and durable agent runtime composition are component-tested.
  A Controller application with authoritative inventory/database, active
  observation/audit aggregation and service-manager units remains absent.

## What Works

### Management control plane

Current management infrastructure includes canonical signed MMP envelopes,
direct-trust node certificates, authenticated HELLO/ACK sessions, bounded replay
state, a shared-node MMP router/runtime, signed endpoint and RPC virtual-service
records, verified virtual-address resolution, and persistent monotonic record
epochs with a process-lifetime lock.

The internal product-control slice additionally defines transport-neutral
node/network/function/service/route/release resources and message primitives.
The operator slice adds a recursive TurboParser command tree, owned
bounded command values, one monotonic request budget, an explicit H2-only mTLS
client, read routes and bounded Network plan/apply/delete routes under
`/v1/meshes/:mesh`. Redirects,
automatic retries and H1 fallback are disabled; credential paths, identifiers,
the Controller origin and returned JSON are validated, with 32 KiB headers and
1 MiB bodies as hard client limits. The Iris adapter requires a verified
`sha256:<64-lower-hex>` CoroNet peer identity, delegates authorization before
query execution, and caps page size and output bytes. Focused Release tests
cover parsing, deadline arithmetic, route mapping, authorization, invalid
identity/source rejection, response ownership and post-close behavior.

Iris exposes one mTLS-only `/v1/control` WebSocket route over HTTP/1.1 RFC 6455
or HTTP/2 RFC 8441, verifies a signed MMP `CONTROL_FRAME`, and transfers an
owned payload through a bounded SPSC channel to one domain owner. That owner
commits replay state only after an idempotent desired-state operation succeeds;
deletion is an `ABSENT` tombstone, and a bounded event cursor provides the
local basis for reconnect resume. The mTLS-only `/v1/control/status` and
`/v1/control/events` H1/H2 routes require bilateral `OBSERVE` permission. Status
uses generation-consistent bounded pages; events use a strictly increasing
cursor. Both responses are capped at 256 KiB. Release loopback tests perform a
real TLS request, decode the binary response, verify 403 denial, and drain
accepted connection tasks during shutdown. The agent core owns the TLS
listener, CoroNet poll and configurable-timeout shutdown/drain ordering. A
fixed canonical function document binds function/provider/artifact/config/
network-policy digests and limits. The state owns a bounded reconciliation
copy, and DELETE retains the prior APPLY document so removal can be routed to
the same prestaged provider. The agent admits a function only when signed
grant, local permission, runtime availability, and exact provider registration
all agree. The bounded reconciler serializes each function, propagates provider
backpressure, applies completion to observed state, and interrupts unfinished
work only after provider shutdown drain.

On the current Windows dependency installation, the Release CoroNet DLL exports
the `coro_websocket_*` ABI required by Iris and the Release control tests
pass. The separately installed `turbonet-debug` CoroNet DLL does not export
those symbols, so the two Debug Iris-linked tests fail at process load with
`0xc0000139`; the ten transport-neutral Debug/ASan control tests pass. The
Debug package must be rebuilt from the matching CoroNet revision. Substituting
the Release DLL into the Debug/ASan process is not a valid workaround.

This is management transport and identity infrastructure, not a complete product
control plane. The new Product Controller adapter has injected callbacks but no
deployable authoritative state source. The CLI now has a bounded re2c/Lemon
Selector V1 compiler and a typed `placements plan` H2+mTLS POST path. The Iris
adapter authorizes and authoritatively recompiles the selector, then exposes an
immutable program to an injected read-only inventory planner. No deployable
inventory source is wired, so this is an integration surface rather than a
functioning global planner. The CLI still has no mutation/apply, request-ID
recovery, SSE watch, Ctrl-C cancellation, context key store or transfer
implementation. The diagnostic WebSocket path is currently inbound-only and
does not actively push snapshot/observation/operation/event/receipt state.
Direct mTLS H1/H2 polling is an operational view, not a signed audit artifact.
The production direction now uses a typed H2 POST sync loop: Controller commands
live in an authenticated bounded durable outbox; the agent persists accepted
commands in its WAL before sending a durable receipt; reconnect and certificate/
policy rotation fence old sessions. The repository now builds standalone
`mesh-agent` and delivery-focused `mesh-controller` binaries. The former can
bridge signed Network intents into the default-off `meshd` FlowMQ/mTLS owner
and run explicitly prestaged Native/TurboWASM providers. The latter owns
the authenticated durable outbox and accepts only pinned-mTLS, cryptographically
valid signed-MMP commands for configured mesh/controller/target/lifetime
bindings, returning 202 only after persistence. There is still no product
Controller database, user/approval application or service-manager unit. The local boundary now includes the
standalone `FlowMQ::FlowMQ` ROUTER/DEALER mTLS adapter, bounded client/server
runtimes, and a prestaged builtin/Native provider adapter exercised through the
real reconciler. The Network path additionally has an internal `meshd`
composition against a borrowed userspace fabric and default-off validated
configuration. Seam tests cover agent WAL-before-ACK/restart restore and the
real FlowMQ provider-to-meshd APPLY/DELETE/idempotent-restore path. The execution plane now has
digest-pinned Native and authenticated TurboWASM child processes with bounded
I/O, timeout and process-tree cleanup. Function providers persist a bounded
claim before process start, retain signed terminal results across lost ACKs,
and fence recovered RUNNING claims as indeterminate instead of rerunning them.
Raw WASM accepts only the exact `core|utils|app` profile. Production requires a digest-pinned
sandbox launcher with bounded shell-free argv; service accounts, Windows/Linux sandbox profiles, audit and
cross-platform fault validation remain incomplete. Neither the reconciler nor
the remote contract permits paths, argv, executable bytes or dynamic loading.
Membership gossip/anti-entropy, policy compiler/
signed rollout, revocation, Controller and audit closure remain incomplete.
Older incremental notes later in this document describe the state when
individual MMP layers were introduced and must not be read as the current
aggregate status.

### Core mesh

- Virtual IP based overlay networking works
- Direct peers and relay routes are tracked separately
- `mesh_send_packet()` prefers direct peers and falls back to learned routes when no policy matches
- `route_rules` can pin a destination CIDR to a specific next-hop virtual IP
- A pinned rule is authoritative: if its next hop is down, mesh send fails instead of silently falling back
- Subnet-router / exit-node local-egress groundwork is implemented: pinned CIDR
  route policy can steer non-mesh traffic toward a router, and the router
  delivers only configured `local_egress_cidrs` to TUN/OS fail-closed
- `local_egress_allow_cidrs` can restrict which source mesh virtual CIDRs may
  use the router-side local egress role
- `peer_allow_cidrs` can restrict which virtual IPs are allowed to become direct peers
- `peer_allow_node_ids` is the secure-wire trust store; a multi-node Mesh must list each allowed stable transport identity
- `peer_protocol_major` can restrict which mesh protocol generation is allowed to become a direct peer
- `packet_policy_rules` can match source CIDR, destination CIDR, IP protocol,
  source port, destination port, and direction; configured directions fail
  closed when no rule matches
- static `magic_dns_domain` / `magic_dns_names` config can resolve mesh names to
  virtual IPs and reverse-map configured virtual IPs
- Direct endpoint information can be learned from control-plane announcements
- ICE credentials and trickle candidates can be exchanged over existing mesh signaling

### Routing

- `1-hop relay` is verified
- 4-node route learning is verified
- Direct neighbors are no longer allowed to pollute the route table
- Route lookup and next-hop selection are stable under current test coverage
- Longest-prefix route policy lookup is active for operator-pinned rules
- Learned relay routes and operator route policy are exposed separately
- Direct peer admission can now be limited by CIDR allowlist
- Direct peer admission can also be limited by stable node identity allowlist
- Direct peer admission can also be limited by mesh protocol major policy
- Direct-connect and direct-upgrade attempts are suppressed for peers outside that allowlist
- Learned relay routes and routed control signaling are now suppressed for peers outside the CIDR allowlist

### Self-heal

- Bootstrap retry works
- Explicit reconnect is no longer blocked by stale cooldown state
- Leader restart recovery is verified
- Reconnect storms were reduced by single-flight / suppression fixes in `p2p`

### Data plane

- `meshctl` synthetic packet path works
- `mesh_vpn` system-level ICMP works
- `mesh_vpn` system-level TCP works
- Direct path is preferred over relay when both exist
- Direct path fallback back to relay is verified
- Pinned route policy can override an available direct path
- Pinned route policy no-fallback behavior is verified
- Disallowed peers are rejected during `MESH_HELLO`
- Unannounced peers cannot inject raw mesh payloads
- Inbound relay forwarding fails closed when the destination is outside `peer_allow_cidrs`

### ICE / direct-path groundwork

- `mesh` can be configured with:
  - `ice_enabled`
  - `ice_allow_loopback`
  - `stun_servers`
- ICE agents are initialized after `MESH_HELLO`, not before peer identity is known
- Controlling role is derived deterministically from virtual IP ordering
- CMake requires and links the installed `TurboNet::Ice` target; ICE and the
  `ice_agent_close()` shutdown path are compiled into Mesh
- ICE teardown in mesh now queries `ice_agent_get_state()` directly during shutdown instead of trusting callback-driven mirrored strings
- Mesh calls `ice_agent_close()` before clearing callbacks so shutdown stops creating new ICE work
- For already-direct peers, a selected ICE pair can carry raw mesh IP packets
  only when both peers negotiate `MESH_CAP_SELECTED_PAIR_IP`;
  `mesh_send_packet()` then prefers that direct ICE path before falling back to
  the existing P2P stream transport.
- `mesh_poll()` now services selected-pair IO and feeds received ICE payloads through the same IP packet handler used by the P2P path
- `meshctl` and `meshd` diagnostics export:
  - ICE enable state
  - ICE peer counts
  - ICE auth/candidate message counters
  - ICE end-of-candidates tx/rx counters
  - ICE checks-started counter
  - local/remote candidate counts captured at the moment checks started
  - last ICE state
  - last selected local/remote endpoint
- In the current trickle flow, checks may start before the final remote candidate total arrives; later candidates are still accepted and folded in while CONNECTING
- Current implementation now covers signaling, connectivity checks, and direct-peer IP packet transport over the selected ICE pair
- Relay routing uses the existing P2P transport. Routed ICE signaling is now
  fail-closed because hop-by-hop P2P authentication does not authenticate the
  origin named inside `MESH_CTRL`; direct neighbors can still negotiate and use
  selected ICE pairs.
- Public STUN on EU is now verified against both:
  - `stun.cloudflare.com:3478`
  - self-hosted `stun:161.97.65.129:3479`

### DHT / P2P

- `p2p_dht_get()` is now a real synchronous network lookup
- `p2p_dht_put()` now replicates across connected / discovered peers
- Lookup state is request-id based instead of one global fake active lookup
- 4-node DHT lookup deadlock in multi-hop setup was fixed

## Verified Results

EU verification currently passes:

```text
ctest --test-dir build/linux-gcc-release-nosan \
  -R 'test_mesh|test_mesh_faults|test_mesh_multihop' \
  --output-on-failure --parallel 1

100% tests passed, 0 tests failed out of 3
```

Covered by that run:

- `test_mesh`
- `test_mesh_faults`
- `test_mesh_multihop`

Focused route-policy verification on EU also passes:

```text
./bin/test_mesh --filter 'prefers direct path over relay'
./bin/test_mesh --filter 'pinned route'
./bin/test_mesh --filter 'admission allowlist'
```

Covered by those runs:

- baseline direct-over-relay preference
- pinned route overrides direct path
- pinned route fails closed when the configured next hop disappears
- peer admission allowlist rejects disallowed mesh members
- peer admission allowlist rejects disallowed learned routes and relay forwarding
- identity admission allowlist rejects disallowed mesh members

Additional real-world validation already performed during development:

- Windows <-> EU leader connectivity
- Windows -> EU worker via leader relay
- system `ping 10.42.x.x`
- TCP request/response over the mesh
- leader restart recovery

Additional ICE-focused verification on EU:

```text
ctest --test-dir build/linux-gcc-release-nosan -R '^test_mesh$' --output-on-failure --parallel 1
ctest --test-dir build/linux-gcc-release-nosan -R '^(test_mesh_faults|test_mesh_multihop)$' --output-on-failure --parallel 1
```

Covered by those runs:

- two-node ICE signaling regression inside `test_mesh`
- fault recovery regression
- isolated multi-hop regression

Additional live srflx validation on EU already passed:

- 2-node public-STUN run with `stun:161.97.65.129:3479`
  - both peers selected public `161.97.65.129:*` endpoints
  - `path_mode=direct-only`
  - mesh ping succeeded after ICE selection
- Historical 3-node relay-bootstrap run with the same STUN service, before
  routed ICE was disabled pending end-to-end origin authentication:
  - `node2 -> leader -> node3` relay traffic triggered routed ICE signaling
  - both non-leader nodes converged to `path_mode=direct-only`
  - the relay route for `node2 <-> node3` was removed after direct promotion
  - mesh ping succeeded across the upgraded direct path

Sibling `turbo-webrtc` verification on EU also passes:

```text
cd /root/code/turbo-webrtc/build/linux-gcc-debug-manual
LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 ./bin/test_e2e_connection

1 passed, 0 failed
```

That run is important because it exercises the lower ICE/DTLS/SCTP stack directly and confirms
the earlier forced-teardown warning is gone there as well.

## Important Fixes Already Landed

### Mesh

- unified next-hop lookup for direct-first, route-second forwarding
- IPv4 header checksum recalculation on forwarded packets
- non-mesh and multicast traffic filtered out of mesh routing
- duplicate mesh peer wrappers removed
- route table no longer stores direct-neighbor routes

### P2P

- explicit `p2p_connect()` bypasses stale reconnect cooldown
- repeated bootstrap and repeated candidate connect amplification reduced
- peer table no longer keeps fake connected entries
- disconnect / teardown path cleaned up enough for current mesh regressions
- request-id based DHT lookup state introduced

### Tunnel

- `mesh_vpn` runs in packet mode
- packet mode no longer creates proxy TCP/UDP sessions
- `libuv` dependency was removed from `tunnel`
- runtime is now `CoroNet` only

## What Is Not Product Ready Yet

### 1. NAT traversal

Direct path groundwork exists, but full NAT traversal / hole punching is not complete.

Right now, the most stable path is still:

- direct when endpoint information is known
- relay when direct is unavailable

That is useful, but still below product-grade peer-to-peer networking.

Current gap:

- direct-peer mesh traffic can switch over to ICE-selected sockets
- live public srflx validation now covers both 2-node direct and 3-node relay-to-direct promotion on EU
- broader NAT coverage is still missing: different NAT types, distinct public hosts, and repeatability beyond the current single-host EU setup
- there are now repeatable EU integration harnesses for the current single-host public-srflx cases:
  - `mesh/tests/public_stun_harness.sh`
  - `mesh/tests/run_eu_public_stun_2node.sh`
  - `mesh/tests/run_eu_public_stun_regression.sh`
  - `mesh/tests/run_eu_public_stun_matrix.sh`
  - they are environment-driven integration checks, not in-process unit tests
  - the matrix currently covers:
    - self-hosted EU STUN: `stun:161.97.65.129:3479`
    - Cloudflare public STUN: `stun:stun.cloudflare.com:3478`
    - Google public STUN: `stun:stun.l.google.com:19302`

### 2. Daemonization

There is now a config-driven `meshd` binary for long-running `mesh + TUN` operation,
with periodic JSON status output, pid-file support, and a real `doctor` command.

That is progress, but it is still not full production daemonization.

Missing pieces:

- service-manager integration (`systemd`, Windows service, launchd)
- auto-start / restart policy
- config reload story
- privilege and deployment packaging

### 3. Observability

Current diagnostics are better than before, but still not enough for production operations.

What exists now:

- `meshd` status JSON includes reconnect counters and live `path_mode`
- `meshctl status/diag/dump json` exports the same diagnostics
- `meshctl health [json]` now exposes a compact automation-friendly health summary
- `meshctl dht [json]` now exposes cached mesh control-plane DHT entries
- `meshctl status json`, `meshctl dump json`, and `meshd` status snapshots now emit
  top-level `snapshot_version` and a grouped `control_plane` object for automation
- `meshd` status-file schema v2 and `/v1/status` expose one bounded atomic P2P
  `security` snapshot: capacity, typed rejection counters, optional blocking-key
  executor status, and fixed role/stage handshake-latency histograms; no secret,
  credential, peer identity, address, channel binding, or per-handshake sample is emitted
- `meshd` status JSON now includes the same `health` section
- `meshd` status JSON now includes the same cached `dht` view
- `meshd doctor` checks config, bindability, TUN prerequisites, writable paths, and bootstrap TCP reachability
- ICE diagnostics are exported in both `meshctl` and `meshd`
- `meshd` handles shutdown by deferring mesh/tunnel teardown to the main loop
- on POSIX, `SIGHUP` requests an immediate status snapshot refresh

Still needed:

- stronger route / peer / DHT dump surfaces
- richer health heuristics once larger-topology and churn data exists
- the internal `mesh_mgmt_codec` now bounds and canonicalizes the structural
  MMP/1 envelope before authentication or signature verification, but it is not installed,
  network-connected, schema-complete, authenticated, or an implementation of
  `mesh-agent`
- the internal `mesh_mgmt_crypto` adapter now verifies RFC 8032 Ed25519 vectors
  through OpenSSL EVP and BLAKE2b-256 through Monocypher; key generation,
  persistence and secure storage remain outside this adapter
- the internal `mesh_mgmt_envelope` now freezes all 14 MMP/1.1 common-header
  field IDs, canonicalizes their fixed-width values, verifies payload hashes,
  and signs/verifies the domain-separated frame before returning any borrowed
  payload view; certificate/clock/sequence/ACL and message-specific schemas
  remain outside this layer, and it is not connected to a network handler
- the internal direct-trust certificate validator now freezes a 14-field
  canonical certificate, verifies its domain-separated issuer signature,
  mesh/time validity, and mandatory node transport/data identity bindings
- the internal HELLO state machine now freezes HELLO/HELLO_ACK payload fields,
  intersects versions/features/resource limits, detects signed downgrade or
  identity mismatch, binds ACK/post-handshake frames to the HELLO origin
  session/incarnation and the current Noise handshake hash, and gates every
  post-handshake kind until mutual ACK. Pre-binding MMP/1.0 HELLO is rejected
- the internal replay gate now provides an allocation-bounded message-ID cache,
  RFC 1982 sequence ordering, live-entry-preserving capacity failure, and
  non-mutating prepare followed by generation-checked commit
- the internal raw-frame dispatcher now owns structural decode, envelope
  verification, session/feature binding, replay commit, and typed observer
  event ordering; it has no callback or network side effect and explicitly
  rejects FORWARD/COMMAND kinds without consuming replay state
- the internal `mesh_mgmt_transport` now preserves fragmented and coalesced
  MMP frames with one fixed 16 KiB buffer plus one retained chunk capped at 16 KiB,
  returns generation-bound borrowed receipts, releases each recv chunk exactly
  once, and becomes terminal on malformed length/canonical frame or I/O
  ambiguity; its CoroNet adapter accepts only an already-open TLS 1.3 socket,
  never owns the socket, rejects raw TCP before transport state, and passes a
  real TLS 1.3 loopback frame exchange
- the internal `mesh_mgmt_connection` now owns one adjacent transport plus
  dispatcher, binds every receive to the authenticated transport peer ID,
  keeps borrowed typed-event views alive through a synchronous consumer, and
  commits the exact receipt only after delivery; dispatch rejection and
  consumer rejection consume the frame then make the connection terminal,
  while HELLO/HELLO_ACK use send-before-state-commit and close on ambiguity.
  It exposes stable transport/dispatch-stage/consumer diagnostics, emits no
  duplicate hot-path logs, rejects outgoing FORWARD/COMMAND traffic before IO,
  and never owns the caller's CoroNet socket
- the internal `mesh_mgmt_peer` now drives HELLO/HELLO_ACK without retaining a
  private key: synchronous builders lend signed frames, while the driver
  independently verifies the local HELLO certificate/config/transport binding
  and requires the ACK to exactly match the accepted negotiation and original
  local session binding. It commits the received HELLO before building ACK and
  becomes terminal without retry on builder, signature, binding, or send failure
- the internal `mesh_mgmt_peer_signer` now supplies the production-shaped
  HELLO/HELLO_ACK builder contract: it verifies the caller-loaded Ed25519 seed
  against the direct-trust certificate and mesh/node/transport identity, uses
  TurboUtils system CSPRNG for every message ID, advances sequence only after a
  complete signed frame exists, caps handshake frame TTL at 60 seconds, and
  securely wipes its copied seed and frame buffer on destroy. Clock and entropy
  remain injectable for deterministic failure tests; key generation,
  persistence, OS-backed loading, and post-handshake message builders remain at
  the future agent boundary
- the internal `mesh_mgmt_p2p_adapter` now accepts only peers whose encrypted
  P2P handshake exposes an authenticated static public key and nonzero channel
  binding, copies both from one security snapshot, uses that exact 32-byte key
  as the remote transport identity, borrows one complete `P2P_MSG_CUSTOM` MMP frame
  only for the synchronous callback, and keeps legacy custom payloads outside
  MMP by magic classification. The per-peer `mesh_mgmt_p2p_peer` composition
  root additionally verifies the local P2P public key against the certificate
  transport binding, injects the Noise binding into both signer and session,
  and combines adapter, signer and handshake driver; a real two-node encrypted
  P2P regression completes bilateral signed HELLO/ACK and proves both sides use
  their current Noise binding
- the internal `mesh_mgmt_agent_router` now owns the exclusive peer/message
  callback boundary for one P2P node and a bounded `turbo_vec_t` table of up to
  64 per-peer MMP runtimes. It validates the local transport identity and
  signer/dispatch templates before installation, creates connection IDs from a
  CSPRNG-backed 128-bit process namespace plus a checked monotonic sequence,
  routes legacy custom payloads without changing MMP state, fails closed on an
  unknown MMP peer or protocol failure, and wipes each short-lived signer on
  disconnect. The real two-node regression also covers callback ownership,
  cleanup, legacy muxing, and a reconnect with a fresh connection ID
- the internal `mesh_mgmt_endpoint_pool` now keeps a bounded identity-keyed
  endpoint fact source: local static records outrank explicitly verified
  discovery records; stale, expired, conflicting, and capacity-exhausting
  updates fail closed. Owner-loop ticks provide single-flight dial state,
  bounded connect timeout, capped exponential backoff with CSPRNG jitter, and
  protocol-failure quarantine requiring explicit reset. Expired discovery
  records are not redialed after their active connection closes. A real P2P
  regression composes this pool with router established/closed callbacks and
  automatically reconnects with a fresh MMP connection ID
- the internal `mesh_mgmt_endpoint_record` now freezes exact 8-field canonical
  IPv4/IPv6 payloads and verifies the MMP envelope, direct-trust certificate,
  mesh/node/principal/transport bindings, expiry and bounded TTL before creating
  the only record type accepted by `apply_verified`. Hostnames, multicast,
  IPv4-mapped IPv6, wrong DHT-owner binding, tamper and stale records fail
  closed. Its DHT key builder/parser additionally freezes the exact 139-byte
  lowercase `mgmt:<mesh>:node:<node>` owner key and rejects aliases or zero IDs.
  Iterative DHT lookup/refresh and anti-entropy integration, daemon timers/config,
  and bootstrap/relay selection remain absent
- the internal `mesh_mgmt_endpoint_publisher` validates the local transport,
  management-key and certificate binding once, builds the exact signed endpoint
  frame with a CSPRNG message ID and caller-owned monotonic record epoch, then
  stores it locally and pushes it only to currently connected peers. Encode,
  entropy, certificate-lifetime and signing failures do not advance the epoch;
  successful publication and remote cached consumption are covered by a real
  two-node test. Iterative lookup, periodic refresh, anti-entropy and epoch
  persistence remain daemon-owner work
- the internal `mesh_mgmt_agent_runtime` now composes a dedicated P2P node and
  listener, the callback router, and the endpoint pool on one caller-driven
  event loop. It requires an explicit nonzero listen port and every retry/
  timeout limit, copies the caller-provided transport key into the P2P node,
  validates all static bootstraps before binding, defaults unknown signed
  inbound identities to rejection, and permits them only through an explicit
  admission callback. Stop disables redial, disconnects peers, unregisters
  callbacks, and destroys the owned node; the stopped instance is terminal.
  Its endpoint-frame entry verifies raw signed input before mutating dial state.
  A second entry consumes an exact frame already present in the local P2P DHT
  cache under the canonical owner key, but deliberately never starts the
  synchronous network lookup from inside the owner API; cache miss fails closed
  and certificate/trust material remains caller-owned. A third entry publishes
  the local signed endpoint frame using an explicit first record epoch.
  Real two-node regressions cover connected-peer push, remote cached consumption,
  tamper without endpoint-state mutation, signed establishment, explicit
  admission, shutdown, backoff, and reconstruction on the same identity/port
- management-listener port exclusivity is still blocked in CoroNet on Windows:
  the IOCP TCP listener enables `SO_REUSEADDR` and exposes no exclusive-listen
  option, and a regression probe demonstrated that two listeners can bind the
  same host/port. The runtime propagates ordinary bind failures but cannot yet
  guarantee occupied-port fail-fast. This needs an upstream cross-platform
  exclusive listener option and a cross-process regression before deployment
- the internal `mesh_stream_mgmt_ticket` now freezes exact canonical MMP
  request/issued schemas, gates both kinds on negotiated capability, derives
  initiator identity from the authenticated node session, requires the
  fail-closed `OPERATOR` role baseline, and is the only MMP delivery-side
  issuance path into the responder ticket store; response correlation, both endpoint identities,
  stream claims, expiry and the 60-second hard TTL are verified before use
- the internal `mesh_stream_codec` now provides allocation-free length-first
  framing for future reliable streams, with a 256 KiB hard ceiling, canonical
  bounded metadata, raw borrowed payload views, exact partial-input
  requirements, and one-frame-at-a-time consumption; it remains uninstalled
  and is not connected to P2P, CoroNet, TurboMedia, or the mesh data path
- the internal receiver-side `mesh_stream_session` now binds OPEN to a
  pre-authorized stream ID/epoch/class/size policy, enforces exact sequence and
  offset progression, uses bounded absolute flow-control credit, and separates
  receive/control prepare from generation-checked commit; it remains
  transport-agnostic and has no application or media callback
- the internal `mesh_stream_transport` now owns a one-frame bounded receive
  window, releases each CoroNet recv chunk exactly once, drives synchronous
  application acceptance before session commit, sends ACCEPT/WINDOW_UPDATE
  before control commit, configures a send HWM, and fails terminally on
  protocol/application/I/O ambiguity; its CoroNet entry now rejects raw TCP
  and incomplete/non-TLS-1.3 sockets before allocating transport state
- the internal `mesh_stream_channel` now requires an immutable admission
  snapshot containing remote identity, authenticated generation, stream ID,
  and stream epoch; when supplied by the authenticated peer owner, stale
  disconnect work cannot revoke a newer channel, while close, revoke, and
  terminal failures preserve diagnostics and release transport-owned memory
  without taking ownership of the CoroNet socket
- the internal `mesh_stream_registry` now enforces fixed total/per-peer channel
  quotas, rejects duplicate admitted stream tuples, retains terminal diagnostics
  until explicit release, and uses registry-plus-slot generations to reject
  stale handles across both slot reuse and registry reinitialization; peer
  revoke is restricted to an exact remote identity and admission generation
- the internal `mesh_stream_bind` now implements an exact-length, three-message
  Ed25519 transcript bind over a one-time, responder-owned ticket; mesh/node
  identities, initiator/responder roles, stream/epoch, admission generation,
  expiry, and the RFC 9266 `tls-exporter` value are signed, while a bounded
  `ISSUED -> CHALLENGE -> CONSUMED` table retains replay tombstones until
  expiry; tamper, replay, wrong-channel, expiry, role-reflection, truncation,
  capacity, and invalidation tests pass
- CoroNet now exports the fixed 32-byte RFC 9266 binding only for fully-open
  TLS 1.3 sockets. The mesh adapter derives it directly, sends all three bind
  messages in order, invalidates on send ambiguity, and creates a short-lived
  authorization bound to role, remote node, admission generation, stream,
  expiry, and that exact connection; channel/registry admission rejects raw
  TCP, missing authorization, expired claims, or cross-connection reuse; a
  real TLS 1.3 loopback regression completes mutual bind before registry
  OPEN/DATA/CLOSE and verifies both endpoints receive the same authorization
  binding
- `meshd` and `meshctl` now accept default-off `stream_enabled`; enabling it
  advertises `MESH_CAP_STREAM_V1` only after the P2P handshake lifecycle and
  `mesh_peer_stream_ready()` additionally requires identity-bound HELLO,
  bilateral capability negotiation, a current protocol major, and a live
  direct peer; disconnect revokes admission before callbacks, while actual
  DHT endpoint lookup/refresh orchestration, stream listener ownership,
  ticket-event orchestration, runtime TLS bind/transfer
  orchestration, multi-node transfer, and TurboMedia wiring remain absent
- multi-level certificate chains, rotation/revocation, a persistent command
  journal, product-level ACL/role authorization, replay persistence, the
  deployable management-agent service, secure persistent key loading,
  exclusive listener binding and external configuration remain unimplemented;
  the internal typed control payload/state/agent core described above does not
  close those product gaps

### 4. Policy / identity

Missing product-level controls:

- richer controller-owned ACL / network policy beyond admission allowlist,
  static packet policy, and static pinned routes
- product-level subnet-router / exit-node authorization, including who is
  allowed to use configured local-egress routes

Compatible next cut:

- keep `peer_allow_cidrs`, `peer_allow_node_ids`, and `peer_protocol_major` as
  the direct-peer admission inputs for now.
- compile those fields into one internal policy snapshot owned by
  `mesh_network_t`.
- evaluate each security decision by action: peer admission, route learning,
  routed control signaling, direct upgrade, and relay forwarding.
- use `packet_policy_rules` for data-plane packet filtering by direction,
  CIDR, protocol, and port.
- preserve current compatibility: no configured policy remains permissive;
  configured allowlists fail closed for unmatched peers or destinations.
- introduce richer ACL/controller fields only after the public config and
  protocol impact is approved.

Control-plane versioning plan:

- current `MESH_HELLO` already advertises `proto=<major>.<minor>` and stores the
  peer version in `mesh_peer_info_t`.
- `peer_protocol_major` is the current compatibility gate.
- capability negotiation is additive and key-based using a trailing
  `caps=<hex-bitmap>` token after `proto=`.
- peer diagnostics expose advertised capabilities and the local/remote
  intersection.
- `MESH_CAP_ROUTED_CONTROL` is defined but not advertised by default. Routed
  `MESH_CTRL` remains disabled until forwarded payloads authenticate their
  origin end to end and include replay protection; direct control messages
  remain compatible.
- `MESH_CAP_SELECTED_PAIR_IP` gates both send and receive use of the ICE
  selected pair for raw mesh IP packets.
- `MESH_ICE_AUTH` may repeat a capability bitmap for parsing compatibility, but
  that self-asserted field is not accepted as an identity proof for routed ICE.
- capability bits are also defined for signed route announcements and policy
  epoch awareness; those later behaviors are not required by current forwarding
  paths yet.

### 5. Subnet router / exit node

Current mesh route policy supports CIDR matches and can pin a client destination
CIDR to a next-hop virtual IP without changing the existing route-rule contract.
The compatible local-egress cut is now present:

- existing `route_rules` remain client-side pinned intent.
- router-side `local_egress_cidrs` declares which non-mesh CIDRs this node may
  egress to the OS/TUN side.
- optional `local_egress_allow_cidrs` declares which directly authenticated
  source mesh virtual CIDRs may use that local egress.
- `packet_policy_rules` can further restrict local-egress packets with
  direction `local-egress`.
- non-mesh destinations pass `mesh_send_packet()` only when an explicit pinned
  policy rule matches.
- `mesh_handle_ip_packet()` delivers packets to `on_packet_received` only when
  the destination matches a local-egress CIDR owned by this node, the packet
  arrives from a direct peer with a completed identity-bound `MESH_HELLO`, and
  the packet source equals that peer's virtual IP and passes local-egress source
  policy. Relayed local egress remains closed.
- unmatched non-mesh traffic fails closed.
- exit-node is the same mechanism with `0.0.0.0/0`, but daemon/deployment-owned
  OS routing and NAT still have to be configured outside the mesh core.

Still missing:

- controller/user policy deciding who may use a subnet or exit route.
- route advertisement UX and trust model for local-egress routes.
- authenticated origin metadata for relayed local-egress traffic.
- platform-specific OS route, firewall, and NAT management.
- keep the virtual-prefix gate fail-closed for invalid prefixes so malformed
  local config cannot widen mesh routing by accident.

### 6. MagicDNS

The current MagicDNS slice is local and static:

- `mesh_config_t.magic_dns_domain` declares an optional DNS suffix.
- `mesh_config_t.magic_dns_records` maps configured names to mesh virtual IPs.
- `meshctl` and `meshd` YAML accept `magic_dns_domain` and `magic_dns_names`.
- `mesh_resolve_magic_dns()` accepts short names and names under the configured
  suffix.
- `mesh_reverse_magic_dns()` returns configured names, using the suffix for
  short records.
- record names are normalized to lowercase and virtual IPs must stay inside the
  node's configured virtual prefix.

Still missing:

- DNS server / DNS hijack integration for these names.
- control-plane distribution of node names.
- automatic node-name records.
- search-domain injection.
- reverse-DNS protocol integration.
- conflict resolution and product UX for duplicate names.

### 7. Scale validation

Current coverage is meaningful, but still small.

Verified well:

- 2 nodes
- 3 nodes
- 4 nodes

Not yet verified at product scale:

- 10+ nodes
- 20+ nodes
- churn under load
- route convergence under larger topologies

### 8. Node function provider and isolated execution boundary

The control schema now distinguishes built-in, Native and WASM runtimes, with
independent `RUN_BUILTIN`, `RUN_NATIVE` and `RUN_WASM` permissions. It also
separates permission from local runtime availability. The safe default enables
only built-ins; Native and WASM both require an explicit local availability
profile, an exact prestaged deployment and a runtime-matching signed Grant.

The internal V1 provider boundary is now implemented: providers are exact-ID
registrations with copied descriptors and borrowed, caller-owned contexts;
requests and completions are typed and bounded; temporary saturation preserves
the queued operation; and shutdown drains provider ownership before marking
unfinished operations interrupted. The execution plane additionally implements
digest-bound Native and TurboWASM child processes; it provides no general plugin
loader and does not make third-party workloads production-enabled by itself.

Production activation scope:

- only explicitly enrolled compute nodes advertise `compute.wasm.v1`; relay,
  exit, DNS, and ordinary edge nodes do not acquire a TurboWASM dependency
- MMP keeps its typed management operations and never exposes shell, argv,
  arbitrary export names, or arbitrary host functions
- the node accepts only a signed manifest and content-addressed module digest;
  effective capabilities are the intersection of the request and immutable
  local policy
- execution runs in a separate low-privilege executor process with bounded
  memory, deadline, control-flow, host-call, input, output, and audit quotas
- cancellation, replay-safe job identity, crash recovery, result persistence,
  and process-tree cleanup have end-to-end tests before the capability can be
  enabled

Replay-safe identity, crash recovery, result persistence and process-tree
cleanup now have component tests. Cooperative cancellation and production OS
sandbox/profile tests remain activation blockers.

Activation requires the additive compute protocol rollout plus product Grant
authority, low-privilege sandbox profiles and audit closure. Until then, the
child worker is an internal explicitly configured component: it is not advertised
as a generally available third-party runtime and remains disabled by default.

### 9. M3 distributed object storage

[`M3_DISTRIBUTED_STORAGE_DESIGN.md`](M3_DISTRIBUTED_STORAGE_DESIGN.md) now defines a proposed
M3 service above Mesh: Raft-consistent metadata over CoroNet, immutable chunk replicas over Mesh
bulk streams, and an Iris HTTP/S3-shaped gateway. It is deliberately not part of Mesh core.

No M3 runtime, Raft state machine, durable chunk store, replication, repair, GC, server-side
SigV4 verifier, or production-safe streaming gateway exists in this repository. The current
`p2p_minio_s3` example and `p2p_put_file()` / `p2p_get_file()` path remain incomplete integration
prototypes and must not be described as distributed storage.

## Current Product Readiness

Use this wording, not marketing nonsense:

- `p2p`: beta
- `mesh relay`: beta
- `direct path`: beta-minus
- `overall mesh product readiness`: not GA

Practical interpretation:

- good enough for continued internal testing
- good enough to keep adding hosts
- not ready to call a finished public product

## Best Next Steps

Order of value:

1. Build a real `mesh daemon`
2. Strengthen diagnostics / observability
3. Implement real NAT traversal / hole punching
4. Add ACL / identity policy
5. Add product policy and platform integration for subnet-router / exit-node use
6. Expand MagicDNS from local static records to control-plane node naming and DNS serving
7. Run scale and churn tests on more hosts

## Recommended Commands

Build:

```bash
cmake --build build/linux-gcc-release-nosan --target test_mesh test_mesh_faults test_mesh_multihop
```

Run mesh regressions:

```bash
ctest --test-dir build/linux-gcc-release-nosan \
  -R 'test_mesh|test_mesh_faults|test_mesh_multihop' \
  --output-on-failure --parallel 1
```

## Notes

- If a mesh test fails immediately with `Failed to listen on 0.0.0.0:<port>`, check for stale test processes first.
- Fixed test ports plus leftover processes will produce fake failures.
- The earlier `coro_context_destroy: forced teardown with pending loop work` warning in the two-node ICE regression and sibling `test_e2e_connection` was eliminated on 2026-04-23.
- The final blocker was in sibling `turbo-webrtc/ice`: after a STUN request/response moved the agent out of `CONNECTING`, the candidate-socket receive loop could still yield back into another `recvfrom`, leaving the connectivity-check coroutine alive during teardown.
- Mesh-side shutdown hardening is still relevant: it now checks `ice_agent_get_state()` directly instead of trusting stale mirrored state, and calls `ice_agent_close()` before clearing callbacks.
- As of 2026-04-23, the two-node mesh ICE regression also verifies raw IPv4 packet delivery over the selected pair; the remaining cleanup gap is a small LeakSanitizer report in that standalone `LD_PRELOAD` run when duplicate DHT-driven peer connects are triggered during the same process lifetime.
- As of 2026-04-23, EU builds also prefer sibling `turbo-webrtc/ice` sources over `/opt/turbonet/lib/libturbo_ice.a`, so local ICE fixes and trace hooks are no longer hidden behind an older installed archive.
- The old docs in `MESH_README.md` and `MESH_DESIGN.md` describe earlier aspirations, not the exact current runtime.

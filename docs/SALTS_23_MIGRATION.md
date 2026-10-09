# Salts 2.3 / SaltsUtils 4.3 migration contract

Tracking: [TurboP2P #33](https://github.com/qigao/turboP2P/issues/33).
This branch extends draft [PR #32](https://github.com/qigao/turboP2P/pull/32)
and **does not** mean the complete root build has been migrated.
The SDK baseline is the **2.3.0/4.3.0 release family**, with currently
published `v2.3.0-rc.1` and `v4.3.0-rc.1` release candidates.
NuGet uses floating `2.3.0-*` / `4.3.0-*` rather than an exact RC build.
The CI validates the actual resolved package identity before compiling.

## Responsibility and admission

| Concern | Source of truth | Admission boundary |
| --- | --- | --- |
| Server connection and callback Owner | Salts CNet + fixed NativeIO SG Owner | Select once with `cnet_owner_placement_choose` on accept; commit local CNet or explicit credited handoff |
| Client remote peer | Verified signed P2P/MMP peer identity and CNet endpoint snapshot | `cnet_destination_choose` once before dial; a pinned peer cannot silently reroute |
| Transport lifetime | CNet terminal and optional `cnet_manager` | Manager reservation and CNet connect/adopt have distinct bounded credits |
| Protocol session reuse | P2P Noise/MMP authentication + `cnet_client_pool` | Only bind READY after verified protocol identity and handshake |
| Reconnect and application retry | Host policy + CNet recovery/retry gate | Transient transport restore is not file/DHT/command DATA replay |
| Configuration and service descriptors | Host ACE Configurator, CMeta, SaltsUtils DataBind | Versioned immutable typed config and compiled plans at startup/admission |
| Domain lifecycle | CFlow, if it simplifies an owner-level state machine | Cannot override CNet physical connection truth |
| Optional modules | Salts Plugin with retained descriptor/callable leases | Module unload after complete quiescence, never inside borrowed callbacks |

**Do not** add a second network backend, Manager DSO, Actor/mailbox
combination, per-packet strategy evaluation, hot-path reflection, implicit
binary admission, or fallback to retired CoroNet/TurboNet/TurboHttp.

Existing management endpoint-pool backoff, cookie admission, Noise framing
and MMP signed-record lifecycle are production protocol logic; they are **not**
silently replaced by a new generic CNet retry/pool helper. Reconcile
authentication state, deadlines and cancellation behavior before such a
production change. Protocol wire and disk formats are unchanged in this slice.

## Verification

The installed-SDK tests compile and execute C11/C++17 calls against canonical
`Salts::CNet` and `Salts::DataBind`, validating explicit Server placement,
strict-key Client destination, no-fallback/invalid-version behavior,
protocol-authorized retry decisions and DataBind/CMeta public C ABI.
They do not claim real SG/Manager/Pool production composition or an installed
TurboP2P consumer. The established foundation suite and P2P sanitizer tests
must still pass against the selected 2.3/4.3 SDKs.

The root `CMakeLists.txt`, `p2p/CMakeLists.txt` and `mesh/CMakeLists.txt`
still reference retired targets. Subsequent work follows #5–#12, with
Windows/installed-consumer CI and representative data-plane benchmarking
required before full migration is accepted.


## Phase C1 — production Client Destination admission (#33)

`mesh_mgmt_agent_runtime_set_client_policy_v2()` now installs one **immutable**
CNet 2.3 Client destination plan on a dedicated management runtime **after
init and before start**. This is a production entry point, not a standalone
SDK smoke. Only `EXPLICIT`, `ROUND_ROBIN`, and `STRICT_KEY` are accepted;
future advisory weight/pressure modes require validated provider inputs first.

1. Static bootstraps or cryptographically **verified** MMP endpoint records
   create bounded identity-keyed entries. The pool derives a stable
   BLAKE2b-256-to-u64 selection ID from the complete 32-byte transport peer
   key; nonzero identity and collisions are fail-closed. Stable IDs do not
   represent socket handles or authenticate an endpoint by themselves.
2. Every Owner poll progresses expiry and pending dial timeouts in the
   existing **sole** pool state, then builds one sorted immutable Client
   selection snapshot. A pinned ID stays in the set with
   `eligible=false` during backoff, quarantine, DIALING, ACTIVE or expiry.
   CNet's `cnet_destination_choose()` runs **once** on this admission, never
   in receive/send callbacks. Missing/blocked pinned IDs are reported as
   `NO_SOURCE` with **zero dial attempts**, not redirected.
3. At most one real `p2p_connect()` request is made per selected Owner
   progress turn. Its connection still belongs to CNet's configured Owner;
   P2P enforces live transport capacity and Noise, while the management
   router owns signed MMP protocol READY. TCP connected/queue admission
   cannot mark a management service authenticated.
4. The runtime treats `NO_SOURCE` as a normal no-dial turn and continues
   `p2p_poll()`. Incorrect versions, invalid snapshots, resource exhaustion
   and callback lifecycle violations still fail fast. No automatic DATA
   retries, new thread/Actor, or second CNet Manager is introduced.
5. Existing `tick_v1` fan-out remains only for existing unconfigured
   consumers. Once the new policy is installed, entering that path is an
   explicit INVALID_STATE; there is no hidden mode fallback or hot reload.

**Verification:** the new management Client policy CTest drives the real
production pool with bounded dial callbacks; the dedicated runtime test
constructs two real CNet listeners and confirms that an EXPLICIT signed
transport identity alone completes Noise+MMP while the other stays untouched.
These are part of the Linux Release and focused ASan/UBSan gates in draft
PR #35. Retained next steps: SG Server Owner placement/credited handoff,
owner-local CNet Manager/ClientPool/ManagedDial with complete protocol READY
and terminal lease accounting, and DataBind 4.3-compiled ACE configuration.


## Phase C2 — DataBind 4.3 host ACE Configurator (#36)

`mesh_mgmt_client_policy_from_json_v1()` is a synchronous **host-side
startup-only** adapter to the canonical `Salts::DataBind` runtime. A trusted
`MeshClientPolicy` IDL schema is parsed into one codec, and a
`DataBindValidationPlan` is compiled during configuration admission before
the runtime's CNet policy is published. Strict JSON binding rejects unknown
keys and scalar token coercion. Version, kind, identity encoding and
key/identity exclusivity fail closed, leaving the output zeroed on failure.

The host copies the DataBind record into an owned
`mesh_mgmt_client_destination_policy_v2_t`. The codec, immutable plan and
record are freed **before returning**. No borrowed reflection, parser, schema
executor, application data, or secret is kept by a CNet Owner or a P2P
receive/send callback. The full transport public key, not its 64-bit strategy
projection, remains the Noise/MMP authentication authority.

**Current SaltsUtils 4.3 admission detail:** `data_bind_create_from_text()`
validates the schema's positional Binary field ordering even when the only
requested format is JSON. Thus the trusted `MeshClientPolicy` declaration
places fixed `schema_version`/`key_hash` before the two variable strings,
while JSON object key order remains unrestricted. We do not request or infer
Binary runtime layouts, and this loader restriction must not be hidden by a
second schema parser or format fallback. Track true text-only schema admission
upstream rather than allowing invalid ordering in this consumer.

An EXPLICIT identity from configuration can only select a matching trusted
static bootstrap or independently **verified** signed endpoint record.
Configuration text does not by itself grant remote trust. The adapter accepts
bounded strict JSON for Client EXPLICIT, ROUND_ROBIN and STRICT_KEY only.
It does not implement a generic runtime Service Configurator, hot reload,
data-plane Binary layout admission, SG topology, or Server placement.
Those and generated CMeta service descriptors follow #36/#37/#38 separately.

Tests reject malformed/unknown fields/versions/coercion/identity input,
project the typed policy into the **real** endpoint pool, and exercise a real
two-listener CNet+Noise+MMP end-to-end session driven by DataBind-parsed
EXPLICIT configuration. Linux Release and ASan/UBSan are required in draft
PR #39.

## Phase C3 — Typed RPC service configuration and canonical admission (#36)

`mesh_mgmt_service_config_from_json_v1()` consumes a strict DataBind 4.3
schema with fixed scalars before the variable `dns_name`. It supports the
published RPC/IPv4 service contract, schema version 1, four 0..255 octets,
port 1..65535 and optional canonical lowercase DNS. Unknown fields, type
coercion, malformed or unsupported IPv6/service-family settings fail fast.
No textual address parser, host DNS resolver or alternate network engine is
introduced; IPv6 needs a separate explicitly versioned contract.

The CNet Owner receives **no DataBind objects**. After codec, immutable plan
and record have been released, a caller holds an independent
`mesh_mgmt_service_config_v1_t` containing the canonical address, port and
owned DNS. Its `mesh_mgmt_service_config_publish_view_v1` borrows the DNS
from this address-stable config only for the synchronous
`mesh_mgmt_agent_runtime_publish_cached_service_v1` call. Never persist,
move or copy that borrowed view. Canonical validation reuses
`mesh_mgmt_service_record_encode_v1` with a dummy nonzero local identity,
epoch and expiry — it never signs, publishes or touches the DHT while parsing.

The existing live Noise/MMP service discovery test now drives this Configurator
before publishing the **real signed RPC service** and re-verifies cached
service resolution and tampering refusal. The typed adapter also has direct
tests for malformed JSON/version, unknown fields, exact scalar tokens,
invalid addresses, DNS and embedded NUL, plus view lifetime.

This completes a **Client+RPC-service Configurator slice** only: additional
ACE Server SG topology, Manager/Pool/ManagedDial, generated IDL/CMeta service
descriptors, cross-platform installed consumer and complete root migration
remain the distinct #36/#37/#38 acceptance gates.


## Phase S1 — credited P2P cross-Owner Server handoff (#37)

`p2p_cnet_sg_create_v1` binds one live CNet acceptor to up to four
**distinct final CNet Owners**, each with its own real P2P listener, cookie
gate, Noise handshake, identity callbacks, peer tables and backend. The
acceptor's existing `p2p_cnet_owner_poll` performs the **only** TCP accept.
For each detached stream it gathers a coherent final-Owner
`cnet_handoff_get_snapshot` credit/queue view and calls the real Salts 2.3
`cnet_owner_placement_choose` exactly once. Cross-Owner selection moves the
socket through `reserve → publish` into an owner-local inbox.
The final Owner's existing poll exclusively executes
`take → cnet_client_adopt_accepted → cookie → Noise → P2P protocol`.
No producer thread invokes final Owner application callbacks, and an
admitted socket is **never migrated again**.

Supported preauthentication placement: EXPLICIT, ROUND_ROBIN and
LOWEST_PRESSURE (using admission credit pressure, not synthetic CPU metrics).
STRICT_KEY is rejected: TCP source address is **not** authenticated peer
identity and cannot be used as a trusted strict key. Capacity/queue shortage
or a sealed inbox closes only the current detached socket and counts a denied
admission; no alternate Owner is implicitly selected. Error conditions such
as malformed topology and stale admission fail fast. A same-Owner choice may
adopt directly while preserving the current CNet path.

One `cnet_handoff_ticket` follows each accepted socket across Owners.
TAKEN credits are held through CNet terminal **and** application callback
retirement; completed CNet stop also qualifies for retirement only after
callback quiescence. No callback, queue, CNet record or detached TCP descriptor
is freed speculatively after a timeout. The safe shutdown ordering is:
seal SG → stop/join acceptor producers → stop final Owner P2P nodes and drain
queued/taken tickets → SG destroy → node/transport destroy. Out-of-order
destroy is refused while owners or credits are still live.

**Production evidence required**: installed Salts 2.3 foundation regression
drives real TCP accepted sockets into two final P2P Owner contexts, performs
each server's own cookie/Noise identity check, then sends authenticated
application messages. Separate tests verify forged/unavailable preauth strict
key is refused, malformed topology, hard connection-credit full, sealed
inbox and cancellation/drain semantics. Existing ordinary one-Owner P2P
polling remains unchanged when SG is not configured.

**Not yet SG-native host**: This phase is the production cross-Owner
handoff, but the acceptor/final Owners are still advanced by their own
explicit polling loops; it does not install
`native_io_sharded_host_lease`, route one already-observed batch through
`cnet_sg_host_route_batch`, or benchmark 1/2/4 SG host worker threads.
That work remains open under #37. No claim of full CPU-scaled multicore
P2P or complete root TurboP2P release is made from this phase alone.

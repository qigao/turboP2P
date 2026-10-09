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

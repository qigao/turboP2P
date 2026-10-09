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

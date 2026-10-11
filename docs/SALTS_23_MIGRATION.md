# Salts 2.3 / SaltsUtils 4.3 migration contract

Tracking: [TurboP2P #33](https://github.com/qigao/turboP2P/issues/33).
This branch extends draft [PR #32](https://github.com/qigao/turboP2P/pull/32)
and **does not** mean the complete root build has been migrated.
The SDK baseline is the **2.3.0/4.3.0 release family**, with currently
published `v2.3.0-rc.10` and `v4.3.0-rc.8` release candidates
(installed Windows x64 SDK identities verified on 2026-10-11).
NuGet uses floating `2.3.0-*` / `4.3.0-*` rather than an exact RC build.
The CI validates the actual resolved package identity before compiling.

Version audit on 2026-10-11 compared installed producer manifests with GitHub
release publication times and default-branch ancestry. The installed Salts
`2.3.0-rc.10`, SaltsUtils `4.3.0-rc.8` and CHttp `2.1.0-rc.3` match the newest
published releases including prereleases. CHttp's copied Salts and SaltsUtils
dependency manifests match both installed producer commits exactly. This is
dependency identity evidence, not full-root qualification.

The release commits are not the current default-branch heads: comparing each
installed producer to `master` yields Salts diverged (9 master-only and 8
release-only commits), SaltsUtils master 33 commits behind its release, and
CHttp master 2 commits behind its release. Salts rc.10 does not merge the
long-lived ACE branch as a whole. This is a history statement, not evidence
that its current Component/Plugin or reflected pattern APIs are absent.
Comparing rc.10 (`6ba9868a`) with the remotely verified ACE head
`bc8c13603b46c3e2171d4b812ae00b91229fc3b3` found identical Component,
ComponentPlugin and Plugin public headers/runtime sources, and identical
Interceptor, synchronization and NativeIO ACT headers. Leader/Followers
conformance was synchronized independently by `42141432`; the release also
contains the exported Concurrency LF backend. Existing Reflection/ObjectRef
headers have no differences in this comparison.

The branch retains the older `Salts::CFlowCNet` receive-credit adapter and
`cflow/io_cnet_adapter.h`. The release removed that legacy adapter during the
CNet integration (`06475bca`, following `a22b6a61`) and retained real
TCP-to-Channel-to-Actor conformance without it in `c6b42d02`. This is not a
missing new Component/Plugin feature to copy into consumers. The release also
has CNet strategy and CMeta portability/import improvements absent on the old
branch. Source presence remains distinct from complete 17-pattern downstream
and device qualification; the consumer evidence below proves only its stated
installed contracts.
Sources: [Salts rc.10](https://github.com/qigao/salts/releases/tag/v2.3.0-rc.10),
[SaltsUtils releases](https://github.com/qigao/salts-utils/releases),
[CHttp releases](https://github.com/qigao/chttp/releases),
[Salts comparison](https://github.com/qigao/salts/compare/6ba9868a965f3273cf87ab243dab1884072eb7a3...615b1e77f20652e3ce8c33c6f28728415cb71b23).

The legacy SaltsNet installation remains `1.0.6` at
`97fcef684e95ddd05b649977ecef9d00197ecec4`, with manifest dependency `salts=2.1.0`.
Its newest published prerelease is
[1.1.0-rc.2](https://github.com/qigao/salts-net/releases/tag/v1.1.0-rc.2).
That old installation is not admitted to the migrated foundation graph and
does not establish compatibility with Salts 2.3. Root presets also reference
an absent local `turboparser` installation; legacy root dependencies are still
outside the validated closure. No shared SDK installation was changed by this
audit.

## Mesh control Component provider slice

Tracking: [typed contracts #10](https://github.com/qigao/turboP2P/issues/10)
and [Plugin extensions #11](https://github.com/qigao/turboP2P/issues/11).
This slice uses the qualified draft #84 checkout as its baseline. It adds an
explicit admission path for the existing `mesh_control_provider_v1_t`; the
agent's `function_reconciler.providers` configuration accepts the resulting
borrowed descriptor without a wire, WAL, provider callback or return-code change.
It does not enable loading arbitrary modules from remote command data.

The source owner initializes its Native/WASM/builtin provider first. A static
publisher declares `cmeta_component(Name,
cmeta_provides(mesh_control_component_provider_v1))` and an immutable
`salts_component_provider_binding` using
`MESH_CONTROL_COMPONENT_BINDING_V1(Name, &native_descriptor)`. The adapter's
ObjectRef borrows that descriptor and context; the original owner destroys
them only after generation drain. Its Component declares no config or
dependencies: provider construction and startup parsing remain with the owner.
A dynamic publisher can instead return an owned ObjectRef with its explicit
native destructor, and publishes a canonical `salts_component_provider` export
through `CMETA_PLUGIN_DECLARE` / `Salts::PluginABI`.

| Responsibility | Owner and lifetime |
| --- | --- |
| Type/protocol metadata | CMeta Interface plus a read-only native DataDesc projection of `runtime` and `reserved`; callback/context fields remain opaque |
| Explicit provider selection and create rollback | Component; static component ID selects one provider, without ranking or fallback |
| Published generation and admission pin | ComponentPlugin; caller supplies bounded generation storage and initializes runtime/generation with SDK initializers |
| DSO loading, stop/quiescence and unload | Plugin registry; the generation owns its module leases |
| Request copy, backpressure, completion retention and exact ACK | Existing single-owner provider and reconciler |
| Agent shutdown and durable-result gate | Existing agent owner; it must finish reconciler shutdown before releasing the borrowed provider lease |

Host sequence:

1. For a DSO, load/start through Plugin, then build a ComponentPlugin generation
   from an explicit `salts_component_plugin_source`; for a static provider use
   an explicit deployment. Complete admission before publication.
2. Publish the generation and acquire an address-stable, zero-initialized
   `mesh_control_component_lease_v1_t` by component ID. The adapter binds the
   exact typed Interface once and returns the original provider identity/runtime
   with reconciler-compatible callback trampolines.
3. Pass `mesh_control_component_lease_provider_v1(&lease)` to the agent or
   reconciler. Its copied callback context still borrows the lease. Every
   provider callback runs on the existing owner thread. Scopes pin code; they
   do not provide exclusive native I/O authority. The host must select a native
   provider in only one live lease/generation and must not reuse its context
   across overlapping generations.
4. Close the reconciler/provider. New starts return `MESH_CONTROL_CLOSED`.
   Continue progress and the existing durable-result/ACK protocol: close never
   consumes an unacknowledged completion. Destroy the drained reconciler/agent
   before releasing the lease. `BUSY` preserves the scope and its module pin.
5. Withdraw generation admission with runtime close (its `out_previous` is
   required), drain the generation, then request Plugin stop, poll quiescence
   and unload. ComponentPlugin releases ObjectRefs before module leases. A
   copied/moved lease cannot release the original scope count.

Reflection grants read access only, not assignment or native value lifecycle.
Descriptor equality is semantic across C11/C++17/TUs/DSOs, never an address
comparison. Plugin ABI epoch, Reflection epoch, Component declaration format
and SDK package version retain their separate meanings. No metadata traversal
is added to the packet path and no implicit hot reload/replay is introduced.

The alternative of replacing the reconciler with a second registry/execution
runtime was rejected: it would duplicate identity, bounded work and durable ACK
state. The bridge reuses those existing owners. Migration is opt-in through
provider selection; rollback selects the original static descriptor after
normal close/drain and lease release. There is no automatic fallback after
failed dynamic admission.

Formal verification lives in `mesh/tests/component_provider/` and the existing
`test_mesh_control_reconciler.c`: real Plugin DSO load/start/stop/unload, C/C++
descriptor equality, read-only assignment rejection, wrong Interface rejection,
candidate rollback, partial owned create failure, copied scope rejection,
retained completion/exact ACK, active-scope drain rejection, and Native
APPLY/DELETE through the real reconciler. The DSO fixture requires Component
object destruction before Plugin quiescence. This is provider boundary
qualification, not a complete mesh-node DSO deployment or hot-reload feature.

The existing formal installed-SDK project now has a versioned Windows Release
user preset and vcpkg manifest. From `tests/salts_foundation`, inside a
`VsDevCmd.bat -arch=x64 -host_arch=x64` environment:

```powershell
# GITHUB_TOKEN (read:packages) comes from the parent environment, never a file.
# Bind vcpkg to this VsDevCmd session; its path must have no trailing separator.
$env:VCPKG_VISUAL_STUDIO_PATH = $env:VSINSTALLDIR.TrimEnd([char]92, [char]47)
cmake --preset win-foundation-release
cmake --build --preset win-foundation-release --target test_mesh_control_component_provider test_mesh_control_reconciler
ctest --preset win-foundation-release -R '^test_mesh_control_(component_provider|reconciler)$'
```

The preset selects the matching installed SDKs and preserves the shared read-only
NuGet feed plus writable local binary cache. It does not pin an RC. Existing
root legacy profiles/CI and full-root migration are outside this slice; Linux,
sanitizers and device results must be qualified separately.
The preset requires the normalized parent `VCPKG_VISUAL_STUDIO_PATH`, preventing
an unselected VS installation from silently becoming vcpkg's compiler. See
[vcpkg's VS selection contract](https://learn.microsoft.com/en-us/vcpkg/users/triplets#vcpkg_visual_studio_path).

Local Windows x64 Release evidence (2026-10-11): all six selected CTest targets
passed: the two provider/reconciler suites, `test_salts_23_contracts` and its C++
peer, and `test_mesh_mgmt_execution_rpc_registry` / `_control`. The DSO suite
passed eight cases and 168 assertions. Installed producer revisions were Salts
`6ba9868a965f3273cf87ab243dab1884072eb7a3` and SaltsUtils
`3d39b8c23403bad5fc3e04241bb74a7889bd8a03`; Noise-C resolved to
`cfe25410979a87391bb9ac8d4d4bef64e9f268c6`. These are observed validation
identities, not dependency pins.

## Management RPC service Component slice

The next opt-in consumer is `mesh_mgmt_agent_runtime`, the migrated CNet/MMP
composition. The older `mesh_control_agent` still depends on retired
CoroNet/Iris APIs and is not qualified by the current SDK graph. This slice
does not migrate that older agent or change its startup behavior.

`mesh_mgmt_service_component.h` declares `MeshMgmtRpcServiceV1`, configured
by the existing `mesh_mgmt_service_config_v1_t`, and the canonical typed
`mesh_mgmt_service_provider_v1` Interface. Its read-only DataDesc describes
all existing fields, including the fixed address and DNS array extents.
Descriptor equality is semantic across C11, C++17 and the real Plugin DSO.
Reflection grants no field-write or automatic value-lifecycle permission.

The existing DataBind startup schema and canonical MMP validator remain the
config authority. Component create validates and copies one fixed-size native
config per selected deployment into an owned ObjectRef. Source config storage
may then change or expire. Snapshot calls borrow DNS from that immutable owner
and copy scalar/address values; they do not parse JSON or traverse reflection.
Failed admission releases candidate objects and module pins through Component
and ComponentPlugin, including a later selected provider's create failure.

Host sequence (one management Owner thread):

1. Parse service JSON with `mesh_mgmt_service_config_from_json_v1`. Select the
   explicit static binding `mesh_mgmt_rpc_service_component_binding_v1`, or a
   canonical Plugin `salts_component_provider` export. The host supplies bounded
   generation storage; one selected service consumes one snapshot. No implicit
   plugin search, dependency loader or remote module selection is introduced.
2. Build/publish the generation, acquire an address-stable scope, and call
   `mesh_mgmt_service_component_bind_v1` once with `MeshMgmtRpcServiceV1`.
   The returned view borrows that scope; copying it acquires no pin. Clear every
   copy before scope storage reuse. Scope release expires its service views.
3. Call `mesh_mgmt_agent_runtime_publish_component_service_v1` while the agent
   is RUNNING, outside another API call. Keep scope/provider storage live until
   return. The bridge delegates to the existing signer, epoch allocator and
   signed DHT publication. CMeta visibility is not authorization; signing and
   peer/issuer trust remain with the existing management owners. Invalid views
   return INVALID_ARG with epoch zero before signing or epoch allocation.
4. Finish synchronous provider use, clear views and release scope. Close/drain
   the generation before Plugin quiescence/unload. The encoded cached frame and
   transport payload have their own ownership; no provider/config pointer is
   retained by publication after it returns. A scope pins the DSO, but grants
   no independent network progress or transport ownership.

The bridge is a separate internal library linking Component and agent runtime;
the service Component itself has no dependency on the agent runtime in the
product graph. Existing public mesh configuration, signed wire format and
authentication policy are unchanged. Adoption is explicit; rollback uses the
existing direct service publication call and withdraws/drains this generation.

Formal coverage adds `test_mesh_mgmt_service_component` (8 cases, 174
assertions): immutable config ownership, read-only arrays, semantic descriptors,
invalid/missing admission, rollback, copied/released scope rejection, BUSY
drain/unload and unload/reload stale-capability rejection. Concurrent call
retirement is covered by the additional suite below.

The existing `test_mesh_mgmt_cnet_runtime` now publishes the service through a
real DSO, releases/drains/unloads it **before remote reception**, then resolves
the signed remote DNS/IP record. It still rejects signature tampering and
verifies reconnect. Reentry and expired-view publication are rejected before
epoch allocation. Its formal static P2P graph explicitly supplies `CXX_C_API=`
to avoid Windows dllimport definitions; the product DLL contract is unchanged.
The foundation graph follows the root PIC policy for static dependencies linked
into the DSO fixture.

Windows x64 Release evidence (2026-10-11): **11/11 selected CTest targets
passed**, including the prior six targets, service Component, C/C++ service
config, real CNet/MMP runtime and service concurrency. Reproduce inside VsDevCmd from
`tests/salts_foundation`:

```powershell
cmake --build --preset win-foundation-release --target test_mesh_mgmt_service_component test_mesh_mgmt_service_component_concurrency test_mesh_mgmt_cnet_runtime test_mesh_mgmt_service_config test_mesh_mgmt_service_config_cpp
ctest --preset win-foundation-release -R '^(test_mesh_mgmt_service_(component(_concurrency)?|config|config_cpp)|test_mesh_mgmt_cnet_runtime)$'
```

### Concurrent borrowed calls and generation retirement

`test_mesh_mgmt_service_component_concurrency` adds two formal scenarios
(627 assertions). Its test-only DSO wrapper owns the production service
ObjectRef and borrows an address-stable host gate. The wrapper delegates the
typed snapshot to the production service, then pauses inside the DSO call.
No synchronization hook, callback field or blocking behavior enters the
production service config, Interface or packet path.

The runner owns Plugin lifecycle, publication and drain. A separate worker
alone acquires, binds, invokes and releases its scope. Gate fields are protected
by Salts mutex/condition primitives; worker results are read only after join.
Fatal runner assertions wake/join the worker before any gate, generation or DSO
storage is destroyed. Cleanup rejection fails the test.

- Sixteen actual load/start/call/stop/drain/unload rounds overlap stop/unload
  with a paused DSO snapshot. Runtime close rejects new scopes and Plugin stop
  rejects new module leases. Drain/unload remain BUSY while that call is live.
  A second phase pauses after the call returns: its DNS borrow and DSO-owned
  field metadata still require the scope, and drain/unload still reject.
  The worker consumes both borrows before release; expired service views then
  reject without DSO dispatch. Draining destroys the ObjectRefs before module
  release, permitting quiescent unload and rejecting old registry refs on reload.
- Explicit publication of generation 2 while generation 1's call is paused
  admits the new DNS/port configuration to a new scope. The old call retains
  its original config through return and release. Draining generation 1 does
  not invalidate generation 2's service. The second generation continues to pin
  the module until its own scope and objects retire.

These are controlled cross-thread DSO-call/lifecycle overlaps and explicit
generation publication, not an implicit hot-reload/migration API, a race
detector result, or concurrent network-owner transfer. Each reload round
destroys the retired runtime before starting a new one; the publication
scenario separately exercises two attached generations of one live runtime.

### Concrete daemon startup, refresh and shutdown

`mesh/examples/meshd_rpc_service_component.{h,c}` now owns the built-in service
for meshd. It uses one static deployment, one generation and one scope, with no
DSO registry or loader. Component owns the immutable config allocation;
ComponentPlugin owns admission and scope counts. The concrete Owner reuses
Salts Platform's address-stable thread-affinity state and busy guard rather
than adding a second lock, state machine or lease counter.

`meshd.c` builds the existing IPv4/DNS/port config at RPC startup, admits it once,
then publishes through that Owner. Its existing 10-second refresh uses the same
snapshot, signer and durable epoch allocator. No CLI, config schema, wire format,
trust policy or physical endpoint behavior changes. Config reload is not part of
this slice. A failed admission returns through the existing startup cleanup.

Foreign-thread and copied Owner calls are refused. Synchronous publication marks
the Owner busy until the existing publisher returns, including its external
epoch and signing callbacks. Callback destruction returns BUSY and recursive
publication returns INVALID_STATE with epoch zero, preserving the borrowed DNS.
Checked shutdown withdraws admission, releases the Owner scope/view, drains the
objects and destroys the runtime before management contexts are reset. Additional
live scopes leave storage intact on BUSY for explicit release and retry.

The root/example graph and formal SDK graph link the same production helper.
`test_meshd_rpc_service_component` passes six cases and 86 assertions covering
config ownership, invalid-init rollback, copied/foreign Owner rejection, withdrawn
BUSY storage, checked retry, reinit and invalid publication. The real CNet/MMP
suite invokes the public epoch callback during two refreshes: destroy/reentry are
rejected, epochs advance to 2 and 3, and the service Owner is destroyed before
remote polling verifies the signed epoch-3 DNS/IP. Its new static Owner is held in
fixture storage so fatal assertions cannot strand its Component scope/config.

Windows x64 Release evidence (2026-10-11): **12/12 selected CTest targets passed**,
including all eleven preceding targets and the concrete Owner suite. Salts
`2.3.0-rc.10`, SaltsUtils `4.3.0-rc.8` and the producer identities above were used;
CMake and vcpkg both selected the VS2022 Professional compiler in this session.
From `tests/salts_foundation`, inside VsDevCmd with the token and normalized
VS path supplied as above:

```powershell
cmake --build --preset win-foundation-release --target test_meshd_rpc_service_component test_mesh_mgmt_service_component test_mesh_mgmt_service_component_concurrency test_mesh_mgmt_service_config test_mesh_mgmt_service_config_cpp test_mesh_mgmt_cnet_runtime test_mesh_control_component_provider test_mesh_control_reconciler test_salts_23_contracts test_salts_23_contracts_cpp test_mesh_mgmt_execution_rpc_registry test_mesh_mgmt_execution_rpc_control --parallel 4
ctest --preset win-foundation-release -R '^(test_meshd_rpc_service_component|test_mesh_mgmt_service_(component(_concurrency)?|config|config_cpp)|test_mesh_mgmt_cnet_runtime|test_mesh_control_(component_provider|reconciler)|test_salts_23_contracts(_cpp)?|test_mesh_mgmt_execution_rpc_(registry|control))$'
```

The full meshd/tunnel/HTTP root executable and its automatic timer/startup paths
have not been built or run against this SDK: retired APIs in the legacy graph
remain a separate migration gate. The focused graph compiles and tests the exact
shared Owner source and real transport publication, not the full daemon. Rollback
restores direct service publication at the daemon call sites after normal checked
Owner destruction; no runtime fallback or implicit reload path is installed.

### Durable daemon epoch storage

`mesh/examples/meshd_management_epoch.{h,c}` isolates the existing daemon epoch
Owner and removes its dependency on `turbo_fs.h`. It links installed
`Salts::Core`/`Salts::Platform`, uses owned `tstr` paths and typed `fmt` formatting,
and parses a bounded `vstr` over at most 63 persisted bytes. No second registry,
storage engine, schema runtime or network observer is introduced. The shared
production source is linked by both the root daemon and formal SDK graph.

The prior inline writer flushed a staging file, then used ordinary rename;
`fsync(file) != 0 || close(file) != 0` also skipped close when flushing failed.
The replacement closes its writer on every write outcome, then delegates staging
flush and namespace durability to `cmeta_fs_replace_durable`. Its SDK publication
state distinguishes NOT_PUBLISHED, PUBLISHED_DURABLE and DURABILITY_UNKNOWN.
Only confirmed durable publication of `next + 1` permits returning `next` to
the signer. Unknown durability returns epoch zero and fences this Owner's
allocations until checked close/reopen reconciles the persisted file. A failure
before publication permits explicit retry of the unissued value.

Compatibility: the file still stores decimal next-epoch followed by newline;
existing `.lock`/`.tmp` paths, 0600 creation modes and the <260-byte configured
path limit are retained. Valid whitespace, optional leading `+`, and leading
zeros remain accepted. Existing persisted values override the initialization
seed. Negative values, embedded NUL suffixes, overflow and exhausted UINT64_MAX
are rejected without replacing the file. Only ENOENT permits initialization;
permission/stat/read errors never trigger a reset to the seed. There is no data
format migration or automatic fallback to the old writer.

The daemon opens one address-stable Owner per path on its management thread.
SDK affinity rejects live reinit, copied storage and foreign-thread mutation.
The OS lock lasts until checked close; POSIX fcntl locks exclude other processes,
so the host must not duplicate the Owner for the same path within one process.
Close errors retain storage for diagnosis, and daemon startup refuses to proceed
when reset left a live epoch or service Owner. Ambiguous native close errors
must not be blindly retried. Signing, endpoint/service ordering and authentication
remain with the existing publishers; storage commits precede signing as before.

An isolated private module was chosen over keeping this logic in the legacy
mesh/ICE daemon compilation unit: it gives the real storage protocol its own
formal failure/restart tests while preserving the daemon's callback and format.
It remains synchronous control-plane disk I/O and makes no throughput claim.
The same format permits source-level rollback without rewriting user data;
retain checked durable publication when changing the surrounding wiring.

Windows x64 Release evidence (2026-10-11): **13/13 selected CTest targets passed**,
including all twelve preceding targets plus `test_meshd_management_epoch`
(9 cases, 216 assertions). The new suite covers durable reserve/reopen, source
path independence, legacy syntax, corrupted bytes, bounded reads, copy/thread
rejection, real staging-open failure/retry, exhaustion and Windows lock exclusion.
The real CNet suite now uses the exact daemon disk allocator: publish epoch 2,
close/reopen with seed 1, publish epoch 3, destroy the service Owner, then verify
the signed DNS/IP remotely. Existing tamper rejection and reconnect remain green.

Linux registers a real fork-based process-lock case and an explicit linker-wrapped
post-publication durability fault case; neither was executed here. That fault case
calls the real replace primitive before injecting UNKNOWN, proving consumer
fencing rather than actual disk-fault or power-loss durability. Linux, sanitizers,
full daemon startup/timer execution and crash/power-loss behavior remain unqualified.
Run the preceding build command with `test_meshd_management_epoch` added, then:

```powershell
ctest --preset win-foundation-release -R '^(test_meshd_(management_epoch|rpc_service_component)|test_mesh_mgmt_service_(component(_concurrency)?|config|config_cpp)|test_mesh_mgmt_cnet_runtime|test_mesh_control_(component_provider|reconciler)|test_salts_23_contracts(_cpp)?|test_mesh_mgmt_execution_rpc_(registry|control))$'
```

Issues #10/#11 remain open: selected DataBind-generated wire contracts,
representative reflection/packet benchmarks, broader extension/race matrices
and production deployment are not completed by these slices. The full root,
Linux, sanitizer and ThreadSanitizer graphs have not been executed here. No
performance, data-race absence or cross-platform qualification is inferred
from these results.

### Daemon loop refresh cadence

`meshd_rpc_service_component_refresh` now owns the publication cadence alongside
the existing immutable service/generation. Both the daemon's startup call and
each turn of its existing loop use this production helper; the separate daemon
last-publication timestamp has been removed. There is no timer runtime, worker,
queue or retained agent/clock callback. The helper samples the caller's monotonic
clock synchronously and keeps the Owner busy through both clock samples and the
existing signer/epoch callbacks.

The first call attempts publication immediately, including at clock zero. After
either success or failure, the next attempt waits 10 seconds from completion,
preserving the daemon's prior policy when storage or signing takes time. Calls
before the interval return OK with epoch zero and do not touch the epoch allocator,
signer or transport. Late polling emits one record, never a catch-up burst.
Subtraction after an explicit backward-clock rejection avoids added-deadline
overflow; a backward sample leaves the previous deadline intact. Copied,
foreign-thread, withdrawn and reentrant Owners are rejected before the clock is
called. Fully retired/reinitialized storage starts a new cadence.

Windows x64 Release evidence (2026-10-11): **13/13 selected CTest targets passed**
using the preceding filter. `test_meshd_rpc_service_component` now has 6 cases and
101 assertions; `test_mesh_mgmt_cnet_runtime` has 16 cases and 2849 assertions.
The real CNet discovery case supplies a deterministic clock to this same helper
while retaining the real Component, signer, DHT and daemon disk allocator. It
covers failed first publication, interval suppression without epoch/callback
effects, exact-boundary retry, failed refresh with close/reopen, a 250ms logical
advance inside the real epoch callback, backward time, late polling near
UINT64_MAX, and fresh startup after complete retirement. Epochs 2 through 6 are
issued without reuse; after final Owner destruction the remote peer verifies
the signed epoch-6 DNS/IP. The injected clock advance proves cadence handling,
not measured disk latency or throughput.

Build the two modified formal targets with the documented user preset, then run
the preceding 13-target CTest filter. The shared loop step is now qualified;
native startup config assembly, OS loop/tunnel scheduling, full daemon execution,
Linux and sanitizer results remain unverified. Root dependency inspection also
found installed SaltsNet 1.0.6 and Chttp 2.1.0-rc.3, but their exported targets do
not replace the root's CoroNet/Iris lifecycle by a target rename. No unsupported
alias or disabled ICE/HTTP feature is added to bypass that migration.

Rollback restores the prior timestamp and loop call sites after normal checked
Owner destruction; config and wire formats need no conversion. Keep the durable
epoch writer and admitted Component lifecycle when altering cadence wiring.

### Bounded native daemon startup admission

The prior daemon startup adapter compared virtual-host and IPv4 fields with
`strcmp` before checking the DNS terminator. With an unterminated native field,
that comparison could read beyond the supplied storage before validation. The
daemon now passes explicit `vstr` storage views to the private production helper
`meshd_rpc_service_component_init_native`; terminator searches are bounded by
both supplied capacity and the IPv4/DNS protocol maxima before any comparison or
native parsing.

The adapter keeps the existing `inet_pton` IPv4 boundary, exact textual IP-host
comparison, and canonical Component service validation. A host equal to the
configured virtual IP produces empty DNS; a distinct canonical host is retained.
Bytes after the native NUL terminator remain irrelevant. No separate DNS/address
validator, configuration schema, loader, network progress Owner or reflection
registry is introduced. Core supplies `vstr`; the Windows native adapter links
Winsock explicitly. The Component copies and owns the final immutable config,
so native source fields may expire after admission.

Missing terminators, invalid storage/IP and port zero are rejected before Owner
initialization. Canonical-policy failure uses the existing Component rollback.
Live, copied or foreign-thread Owners cannot be reinitialized or overwritten;
checked cleanup retains storage on failure under the original lifecycle contract.
No admission path reserves an epoch or signs/sends a record.

Windows x64 Release focused evidence (2026-10-11): **13/13 selected CTest targets
passed**. The concrete Owner suite now passes 10 cases and 186 assertions,
including maximum canonical DNS/port/address, source mutation, IP-only discovery,
exact host comparison, stale bytes after NUL, malformed/unterminated storage,
canonical-policy rollback, and corrected admission. The real CNet suite passes
16 cases and 2872 assertions: it now uses this exact native adapter, mutates its
input buffers, and verifies signed DNS epoch 6 and IP-only epoch 7 remotely after
each corresponding service Owner has been destroyed. Persisted next-epoch is 8.
The preceding focused filter remains reproducible.

The complete foundation build additionally exposed a Windows TUN header-order
failure: `Windows.h` introduced Winsock1 before the Salts headers introduced
Winsock2. `tunnel_tun_windows.c` now includes Winsock2 first. This local include
ordering fix restores compilation without global compiler flags or changes to
driver/transport behavior. Building Wintun code does not qualify driver loading,
privileged adapter configuration or real device traffic.

The broader CTest run then found `test_proxy_cnet` depending on Wintun during
fixture construction: Windows `tunnel_create` loads that library eagerly, before
the supposedly device-free transport case can run. Its fixture now follows the
existing packet/session fixture pattern, explicitly allocating the test Owner
and creating real mutex/NAT/proxy state with no TUN device. It uses the unchanged
production CNet, `tunnel_poll`, callback destruction, stop/drain and final teardown
paths. All existing assertions remain; the focused proxy suite passes 22 cases
(753 assertions in the recorded run), including verified TLS/SNI, identity
rejection, HTTP/SOCKS fragmentation, coalesced payload, callback retirement,
command pressure and NAT send admission. It does not qualify `tunnel_create`,
TUN device I/O or Wintun loading. Production creation/error timing and TLS trust
policy are preserved; no driver is installed and no feature/test is disabled.

After these corrections the **entire installed-SDK foundation graph built and
63/63 CTest targets passed** on Windows x64 Release (82.70 seconds for the final
run). This expands evidence beyond the preceding selected 13 targets to the
registered P2P transport/admission/lifecycle, key worker, Noise security,
file-transfer/DHT, one/multiple SG Owner and handoff, stream/media, management,
and tunnel suites. Salts `2.3.0-rc.10` and SaltsUtils `4.3.0-rc.8` identities above
remain the installed package baseline. From the documented VsDevCmd environment
and `tests/salts_foundation`:

```powershell
cmake --build --preset win-foundation-release --parallel 4
ctest --preset win-foundation-release
```

This is local uncommitted-worktree evidence on draft #84 base
`359027351be8145b12964ee55a632bcd0d3270e1`, not exact-head remote CI or the full
legacy root build. Read-only GitHub refresh on 2026-10-11 confirmed #10, #11 and
#33 remain OPEN. Generated stable DataBind wire contracts/benchmarks, broader
production Plugin deployment, root CHttp/SaltsNet migration and Linux/sanitizer
qualification are still required by their acceptance gates.

The shared native conversion is now tested; the full daemon's upstream config
parser, MagicDNS selection and OS startup/loop remain separate qualification
gates. Linux and sanitizer execution remain outstanding. Rollback restores the
native call-site wiring after checked retirement, preserving bounded validation
and config/wire formats.

### Generated RPC startup contract (#10/#33)

`mesh/contracts/rpc_service_config.schema` now owns the strict JSON startup
field names, scalar widths and constraints. The matching installed SaltsUtils
`salts_idl_target(ARTIFACTS TYPES)` generates a private C11 NativeSourceIR header
with canonical CMeta VALUE bindings. CMake embeds that same schema for runtime
admission and tracks it as a configure dependency; no compiler or schema file
is deployed. Binary generation/transport selection is absent.

Previously the adapter maintained schema text and eight string-key getters.
The alternative of binding the existing host config directly would conflate
its address array/size/version with JSON octets/schema_version. Instead one
generated staging record feeds the unchanged fixed-storage config. At each
startup admission the codec and MessagePlan compile before input decoding;
exact JSON CSerde tokens then enter the generated native value. Required,
unknown, duplicate and scalar-type checks precede compiled validation and the
existing canonical MMP address/DNS validator. Success closes the reader before
copying fields to the host snapshot. Every exit destroys generated owned text,
then the plan and codec; the address-stable descriptor binder outlives the plan.
The scratch budget is 4096 bytes, depth 4, 32 items; owned payload remains bounded
by the existing 4096-byte JSON limit. No DataBind value/metadata reaches a
Component snapshot, refresh, P2P callback or signed service record.

This removes duplicate startup definitions without adding a registry, loader
or serializer in the packet path. The generated text carrier is compiler-owned
private staging, not a new application string API. The installed TYPES output
is C11: C++17 keeps consuming the existing public C config ABI and a retained
producer descriptor through C ABI. Direct C++ inclusion of this generated
header is outside this slice. Public config layout, error codes, empty-DNS
semantics and signed MMP TLV bytes stay unchanged. Rollback restores the prior
startup-only record adapter and removes its private generation target; persisted
state and network peers need no migration.

Formal configuration tests pass eight cases/4101 assertions, including generated
VALUE descriptor equivalence across C translation units, exact uint32 storage,
independent owned copies and refusal to admit VIEW as lifecycle authority.
Behavior cases cover reordered/boundary fields, source mutation, duplicate and
unknown fields, required/null/numeric-string/floating/overflow rejection, a late
failure after DNS ownership, and exact 127/128-byte DNS result semantics. The
C++17 public caller/producer-descriptor test also passes. These are installed
Salts `2.3.0-rc.10` + SaltsUtils `4.3.0-rc.8` Windows x64 Release results; generated
cross-node service/wire contracts, packet-path benchmarks, direct generated C++
types, root execution and Linux/sanitizer gates remain open.

After the final source change, the complete foundation graph builds and the
unfiltered `ctest --preset win-foundation-release` passes **63/63** (125.69
seconds). This includes real CNet signed-service propagation and the existing
real-DSO Component/Plugin lifetime, concurrency and unload tests. Run from
`tests/salts_foundation` in the documented VS2022 environment:

```powershell
cmake --build --preset win-foundation-release --parallel 4
ctest --preset win-foundation-release
```

Evidence remains local and uncommitted on draft #84 base
`359027351be8145b12964ee55a632bcd0d3270e1`. Root test registration is updated but
the legacy root build/device paths were not executed. The original checkout's
HEAD and 101 dirty entries are preserved; issues #10/#11/#33 remain open.

### CLI RPC HTTP boundary (#7/#33)

`meshctl rpc` and `meshctl cluster status` now share the private
`meshctl_rpc_http` target, linked to installed `CHttp::Client`. The endpoint,
token and canonical node-resolution path helpers and CLI response rendering
live with that transport boundary, so the formal foundation tests compile the
actual production implementation without importing the legacy mesh daemon.
`CHttp::Server` is linked independently by its real loopback fixture.

The choice is a blocking CHttp facade for this sequential CLI: it is the sole
CNet progress owner during each request. Reusing CoroNet, injecting a global
client, or adding an external poll/Actor adapter would retain the retired
runtime or introduce an unnecessary lifetime owner. Each call admits one
bodyless HTTP/1.1 GET/POST, with no redirect or application retry. The existing
5000 ms result timeout, 1 MiB response body bound, 32 KiB response header bound,
512-byte complete URL limit and token length/line-break checks are retained.
CHttp additionally requires finite start-line, header-count and informational
response bounds. Connection/command/request/event capacities are explicit.

An HTTP 3xx/4xx/5xx response still counts as a completed transport call, matching
the existing CLI exit/cluster aggregation behavior; changing that product
policy is a separate decision. Raw output preserves body bytes and length.
Task-summary inspection first copies the bounded byte span into an owned
terminated `tstr`; bodyless responses print the parsed status and headers.
Request errors are consumed once at the CLI boundary through `tlog`, without
logging the token. No generated schema or reflection is evaluated during an
HTTP exchange, and controller signing/TLS/session policy is not involved in
this existing plaintext local RPC path.

The response and client remain distinct owners. The blocking result timeout
does not promise a 5000 ms total wall time: terminal cancellation and transport
drain may extend it. The caller retains initialized clients on request failure,
destroys the response and checks client shutdown before releasing owner
storage. CLI shutdown uses positive 5000 ms drain attempts: CHttp's zero timeout
does not mean unlimited session drain. A timeout retains the same client and
retries only destruction until terminal, so cleanup has no overall deadline.
Any other non-success is fatal rather than silently losing a live owner.
No shutdown retry resubmits a possibly processed POST.

The installed CHttp profile is selected only by `HTTP_SERVICES_ROOT` at the
user-preset owner. The Windows foundation profile uses CHttp `2.1.0-rc.3` with
the existing installed Salts/SaltsUtils pair and runtime PATH. Root native
profiles select matching debug/release roots; the root still has other retired
SDK dependencies. No target alias, compatibility API, runtime DLL copy rule or
new external library is introduced. Rollback consists of reverting this CLI
source/target/preset slice; it needs no persisted-data or wire migration.

Formal tests cover real authenticated GET, bodyless POST and no duplicate
request, preserved HTTP-error policy, unfollowed redirects, option rejection,
exact body-bound acceptance/overflow, oversized headers, deferred POST timeout,
response ownership after client teardown, stopped-endpoint failure and a fresh
owner. The original CLI/cluster test keeps its endpoint, parser and aggregation
assertions and now shares the CHttp fixture configuration, uses atomic counters,
and stops/destroys both servers explicitly rather than leaking a raw listener.
That root test still requires the broader legacy CLI closure. The shared vcpkg
lock has cleared and the production adapter and formal test compile/link.
The first test run exposed the zero-timeout destruction assumption. After the
correction, focused `test_meshctl_rpc_http` passed (11 cases, CTest 7.31 seconds);
the zero-budget case preserves the same owner on timeout and a positive-budget
retry releases it without another HTTP request. The complete Windows x64 Release
foundation graph then built and passed **64/64 CTests in 93.18 seconds**, including
this adapter and the adjacent CNet, Component/Plugin and tunnel suites. Reproduce
from `tests/salts_foundation` in the documented VS environment with
`cmake --build --preset win-foundation-release --parallel 4` followed by
`ctest --preset win-foundation-release`. The preceding 63/63 evidence predates
this slice. That run did not yet cover the Controller H2/mTLS leaf added
below. Full-root CLI, Linux and sanitizer qualification remain outstanding;
[issue #7](https://github.com/qigao/turboP2P/issues/7) remains OPEN.

## Controller CLI H2/mTLS transport slice (2026-10-11)

The production `meshctl_controller_request_http2` / `query_http2` implementation
now lives in `mesh/src/meshctl_controller_http.c`, consumed by the existing
`meshctl_product_run` caller. Its common options, request, result, response and
client declarations are moved without changing layout, numeric constants or
signatures into `meshctl_controller_http.h`; the existing product header includes
it. Endpoint and credential admission are shared with the product parser, not
implemented as a second set of rules. The v1 media type has one declaration.
The Controller adapter no longer includes or links TurboHttp. It links installed
`CHttp::Client`, `Salts::UriParser` and `Salts::JsonParser`.

This slice was chosen because the old adapter already used the synchronous
`turbo_http_create_sync` / `request_sync` facade. Moving this sequential CLI
boundary to CHttp therefore retains the progress topology. The daemon's agent
HTTP client and ICE path still suspend on CoroNet; calling blocking CHttp or ICE
inside those owners would change scheduling and shutdown behavior. They require
separate owner integration. Replacing every retired identifier with an alias
would hide that incompatibility and was not selected. The old product command
tree remains on TurboParser: its recursive `turbo_cmd_*` API has no same-name
entry point in the installed SDK. Full-root qualification remains open.

The validated HTTPS origin is mapped to one `tls://` connection URI while
retaining its authority, bracketed IPv6 syntax, explicit port and optional root
slash. Endpoint validation rejects non-HTTPS origins, non-root paths, nonempty
userinfo/query/fragment, overflowing parser components and invalid ports.
Credential-file ownership/permissions and Windows reparse-point checks remain
as before. CNet always verifies peer trust and hostname/IP; the immutable TLS
profile offers only `h2` and includes the required operator certificate/key.
The request explicitly selects `CHTTP_HTTP_2`. No TLS bypass, redirect, retry,
H1 fallback or plaintext downgrade is introduced.

| Data/lifetime | Protocol |
| --- | --- |
| Options, route and request body | Borrowed for one synchronous call; CHttp copies them before progress |
| Progress | One local blocking client, one physical connection, one request/stream |
| Capacity | Request 64 KiB, decoded response headers 32 KiB, body 1 MiB; bounded CNet queues and TLS buffers |
| Response | Existing `malloc`-owned, terminated JSON copy; independently released by `meshctl_controller_response_destroy` |
| HTTP error | Non-2xx status remains a completed transport response; the existing product executor maps exit codes |
| Failure | Invalid admission leaves output unchanged; admitted failures leave it empty; no business replay |
| Close | Destroy response, drain the same client to real terminal, then release TLS profile and formatted URI storage |

The HTTP-result wait uses the caller's remaining budget; setup and terminal
drain are not a strict total wall-time bound. Destruction uses positive drain
budgets and repeats only on `SALTS_ETIMEDOUT`, retaining the same owner. An
unexpected non-timeout destruction failure is fatal, as in the local RPC
adapter. A timed-out or partially processed POST is never resubmitted.

Formal `mesh/tests/test_meshctl_controller_http.c` uses the installed Client
and independent Server over real loopback TLS/H2. Locally generated P-256
fixtures have separate server/operator roots, serverAuth/clientAuth EKUs,
wrong-host and unrelated-operator identities. These are test keys only; root
signing keys were not retained. Tests use private temporary credential files
and assert H2 version plus the verified peer-certificate identity at dispatch.
Coverage includes GET with a trailing origin slash/query route, exactly one
POST on HTTP 503, an unfollowed redirect, wrong trust, wrong server identity,
untrusted operator, an H1-only authenticated listener, malformed/empty JSON,
exactly 1 MiB valid JSON acceptance, one-byte body overflow, decoded header
overflow with an otherwise valid JSON response, timeout/drain/no replay,
invalid request/origin admission, and a valid call after missing credentials.

Evidence: the complete Windows x64 Release foundation graph built and passed
**65/65 CTests in 93.53 seconds**. Two additional shared-admission cases and the
single media-type declaration were subsequently rebuilt; focused Controller
CTest passed **16 cases / 952 assertions in 1.95 seconds**. The earlier full
run included its first 14 cases. No Linux or sanitizer run was performed for
this local slice; WSL is unavailable on this host. The root executable/legacy
command-tree closure, daemon Controller client, ICE, RESULT recovery/ACK/WAL,
and macOS/Android exact-SDK gates are not qualified by this leaf.

Reproduce from `tests/salts_foundation` in the documented VS environment:

```powershell
cmake --build --preset win-foundation-release --target test_meshctl_controller_http --parallel 4
ctest --preset win-foundation-release -R '^test_meshctl_controller_http$' -V
cmake --build --preset win-foundation-release --parallel 4
ctest --preset win-foundation-release
```

No shared SDK installation, signed wire format, persisted data or daemon
scheduling is changed. Rollback reverts this source/header/target split and
restores the previous product adapter; it requires no data conversion. The
remote draft CI result applies to its committed baseline, not these uncommitted
local changes. Neither #7 nor the full-root migration issue is closed by this
step.

## Execution Store durable publication and recovery slice (2026-10-11)

**HIGH / source facts:** the prior
[`mesh_mgmt_execution_store.c`](../mesh/src/mesh_mgmt_execution_store.c)
used staging-file `fsync` plus `rename` and returned success without the
SDK's destination-directory durability step. It also restored in-memory
state after every publication failure. A post-rename durability failure can
leave a published disk record, so unconditional rollback can make memory and
disk disagree. Journal submit/transition/recovery and terminal compaction
also incremented an imported `uint64_t` generation without exhaustion checks.

The bounded Store remains the single, serialized, synchronous owner. Its
existing snapshot encoder, integrity digest, signed rich-result validation,
and v1/v2 loader remain in the Store. The new private
[`mesh_mgmt_execution_snapshot_io.c`](../mesh/src/mesh_mgmt_execution_snapshot_io.c)
owns staging write/close and delegates publication to installed Salts Core
`cmeta_fs_replace_durable`. The checked SDK header specifies staging flush,
rename and parent-directory `fsync` on POSIX, and staging flush followed by
`MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH)` on Windows. Only an explicit
`PUBLISHED_DURABLE` success satisfies Store success.

| Publication outcome | Owning Store behavior |
| --- | --- |
| Not published | Return existing `STORE_IO`, restore the previous journal/result/generation, allow an explicit retry |
| Published durable | Commit the new in-memory state and return success |
| Durability unknown or contradictory | Return `STORE_IO`, retain the writer lock and mutation state, reject all subsequent reads and writes until close |
| Reopen | Validate disk integrity and signed results, preflight complete recovery, then durably publish before admitting access |

An unchanged snapshot is republished using its exact original bytes, including
legacy v1 encoding. Integrity alone cannot discharge a previous owner's unknown
durability. If RUNNING records exist, recovery marks them indeterminate and
publishes that recovered state before returning success. Failed initialization
or reopen releases all allocations and the writer lock; `out_recovered` is
assigned only on success. A live or fenced owner must be closed before reuse.
The orchestrator now requires the existing owner byte to be exactly usable
(`open == 1`), and its existing execution path suppresses signed output when
Store commit fails. That orchestrator composition remains outside the current
non-TurboWasm SDK foundation graph.

Fresh submissions, transitions and terminal compaction reject generation
exhaustion with the existing `RESOURCE_EXHAUSTED` result. Exact dedupe and
signed-result idempotence remain available at the last generation. Recovery
counts all RUNNING entries and checks remaining generations before modifying
any entry; an exhausted reopen leaves the disk bytes untouched. Empty imports
also avoid a zero-length `memcpy` with a null source.

The selected private I/O boundary keeps filesystem policy out of journal and
signature logic. A new runtime callback table or public fault hook was rejected
because the synchronous production boundary already provides a narrow link
seam. Formal fault tests compile the real private writer under a renamed
private symbol; their wrapper delegates to actual durable filesystem
publication before returning an injected UNKNOWN/error. This proves owner
fencing and checked reopen, not real power-loss behavior or an actual failed
POSIX directory `fsync` on this Windows host. Normal tests exercise actual
staging rejection, corruption, writer-lock exclusion, signed-result retention,
restart, v1 byte compatibility and generation exhaustion. Fixtures release
owners and files even after fatal checks.

Focused Windows x64 Release evidence: **3/3 CTests in 0.26 seconds**;
journal **8 cases / 78 assertions**, Store **12 cases / 250 assertions**, and
publication-fault **6 cases / 122 assertions**: **26 cases / 450 assertions**
in total. The final complete foundation graph built and passed **68/68 CTests
in 95.83 seconds**, including all 16 Controller H2/mTLS cases and the final
Store reopen behavior. `git diff --check` passed and CodeGraph was synced.
This slice uses the installed Salts `2.3.0-rc.10` and matching Utils
`4.3.0-rc.8` profile; it does not update a shared SDK installation.

Reproduce from `tests/salts_foundation` using the existing VS environment and
user preset:

```powershell
cmake --preset win-foundation-release
cmake --build --preset win-foundation-release --target test_mesh_mgmt_execution test_mesh_mgmt_execution_store test_mesh_mgmt_execution_store_fault --parallel 4
ctest --preset win-foundation-release -R '^test_mesh_mgmt_execution(_store(_fault)?)?$' -V
cmake --build --preset win-foundation-release --parallel 4
ctest --preset win-foundation-release
```

The struct layout, public signatures/error values, existing v1/v2 disk formats
and canonical signed wire bytes are retained. The existing owner byte now
expresses a fenced state; callers must honor API errors. Reopen adds one
synchronous durable publication even without recovery changes. This is startup
I/O on the execution owner, not Mesh/MMP event-loop work. Reverting this
source/target split requires no disk conversion, but restores the old weaker
failure behavior and must not be treated as a durability-preserving rollback.

The authenticated remote `COMMAND_RESULT` ACK -> owning requester WAL ->
execution Store terminal compaction pipeline remains outstanding. This refers
to the MMP command-execution plane, not the existing desired-state control
agent provider ACK protocol. Native send completion still does not establish
remote durable acknowledgement; no implicit command RESULT replay was added. Full-root/legacy command-tree and ICE progress-owner migration,
TurboWasm production composition, Linux/sanitizer execution, and macOS/Android
release gates remain unqualified. Local changes are uncommitted, so remote
draft CI still applies only to its committed baseline.

## Authenticated control WAL durable publication slice (2026-10-11)

The two RESULT paths must remain distinct:

| Plane | Existing source facts | Current boundary |
| --- | --- | --- |
| Desired-state control/provider | `mesh_control_agent.c` persists `OPERATION_RESULT`, applies the prepared completion/advances the committed index, then performs provider exact ACK | Existing WAL/ACK composition; checkpoint and worker now have installed-SDK tests below, while complete agent composition remains pending |
| MMP command execution | `mesh_mgmt_execution_sender.c` consumes Egress only after the native write terminal; `mesh_mgmt_codec.h` declares COMMAND_REQUEST/RESULT/STATUS, without a command-result ACK kind | Remote durable ACK, requester result retention and execution Store compaction require their own authenticated protocol design |

**HIGH / source facts:**
[`mesh_control_wal.c`](../mesh/src/mesh_control_wal.c) previously created the
WAL in place and compacted with file `fsync` plus `rename`, without the SDK's
full durable namespace publication. An existing WAL was scanned and admitted
without resolving a prior owner's unknown append/publication durability.
Every failed `lstat` on the WAL path was treated as a missing file. This could
acknowledge persistence too early or attempt initialization after a lookup
error. The control agent already rejects failed WAL-worker completions before
applying observed state or sending a provider ACK; this change strengthens the
WAL's success boundary instead of duplicating that orchestration.

The public filesystem dependency is migrated from `turbo_fs.h`/`turbo_fs_*`
to `cmeta_fs.h`/`cmeta_fs_*` and `Salts::Core`. Historical Salts source before
rename (`193733d0^:utils/include/turbo_fs.h`) and the installed rc10 header
both define the file handle as `int` and the path capacity as 260, preserving
WAL layout. Public function signatures, result codes, authenticated header,
record encoding, HMAC chain and bounded record/byte capacities are retained.

The WAL owns authentication, replay validation, tail/base indexes and fault
state. The private
[`mesh_control_wal_snapshot_io.c`](../mesh/src/mesh_control_wal_snapshot_io.c)
owns synchronous staging writes and exact-file republication, with 8 KiB
scratch storage and `cmeta_fs_replace_durable`. It always closes acquired file
handles and cleans staging only when no namespace publication occurred.
Creation and compaction publish the encoded header; a checked reopen scans
and validates the complete original log, then republishes its exact bytes
before exposing replay or idempotent append success.

| Outcome | WAL owner behavior |
| --- | --- |
| Published durable | Return OK and commit new base/anchor/count after compaction |
| Not published | Return IO, retain the previous compact state and permit an explicit retry |
| Unknown or contradictory publication | Return existing COMMIT_UNKNOWN, set `faulted`, retain the writer lock, reject append/replay/compact until close |
| Failed initialization/reopen | Wipe local owner including the key and release the lock; a later checked open must establish durability |

Only `ENOENT` initializes a missing log or permits creating its lock file.
Other lookup errors fail with IO. The existing rejection of non-file WALs,
symlinks, corrupt/partial tails, wrong identity/key and HMAC tampering stays
intact. Diagnostics can still read stats on a faulted handle; those indexes
are not permission to replay or advance domain state. Append still fsyncs the
record and faults on ambiguous writes, without application replay.

A runtime injection table or public test hook was rejected: the private
production filesystem implementation is a sufficient test link boundary.
The formal fault target renames only its private symbols, delegates to the
real successful filesystem writer, then injects UNKNOWN. Normal tests exercise
real staging-directory rejection and exact authenticated bytes. Fixture
teardown closes all owners and removes files even after fatal checks; POSIX
writer exclusion uses a real child because advisory locks are process-scoped.
No new wire kind or WAL format is introduced.

Focused Windows x64 Release evidence: **2/2 CTests in 0.23 seconds**, normal
WAL **8 cases / 387 assertions** and fault publication **3 cases / 76
assertions**. The tests cover intent/result replay, exact tail dedupe, wrong
key/binding/tampering, partial-tail rejection, checkpoint-only compaction,
unpublished retry, unknown publication fencing/lock retention, reopened HMAC
anchors and logs spanning multiple copy chunks. The selected SDK remains
Salts `2.3.0-rc.10` with matching SaltsUtils `4.3.0-rc.8`. The final
complete Windows foundation build and CTest run passed **70/70 tests in
101.88 seconds**, including the prior Store/Controller/Component slices.
`git diff --check` passed and CodeGraph was synced; its local index is not a
versioned deliverable.

Reproduce from `tests/salts_foundation` in the existing VS environment:

```powershell
cmake --preset win-foundation-release
cmake --build --preset win-foundation-release --target test_mesh_control_wal test_mesh_control_wal_fault --parallel 4
ctest --preset win-foundation-release -R '^test_mesh_control_wal(_fault)?$' -V
cmake --build --preset win-foundation-release --parallel 4
ctest --preset win-foundation-release
```

Reopen adds a complete bounded log copy/publication on the persistence owner;
it needs temporary disk space up to the configured log byte bound, while
scratch RAM remains 8 KiB. This extra startup I/O is the durability tradeoff;
no performance benefit is claimed. Rollback needs no disk conversion but
restores the earlier weaker durability behavior.

This WAL slice qualifies its real tests, not a migrated full control agent.
The subsequent checkpoint/worker slice below covers their Core dependencies;
the daemon Controller HTTP path and full-root graph still need current-SDK
composition and tests.
No actual power-cut, failing POSIX directory fsync, Linux/sanitizer or mobile
run is represented by the injected publication result. The command-execution
remote ACK design and root/ICE/platform release gates remain open. Shared SDKs
and the original dirty checkout remain untouched; changes are uncommitted.

## Checkpoint and WAL worker durability slice (2026-10-11)

`mesh_control_checkpoint_store` now uses the installed Salts Core filesystem;
`mesh_control_wal_worker` uses its current mutex and bounded thread-pool APIs.
Their product targets link `Salts::Core`, and the existing codec/store/worker
mesh tests link the matching `Salts::TinyTest` in both graphs. The foundation
closure includes the real checkpoint, owner, channel and worker implementations.
No shared SDK or original checkout was changed.

Two HIGH correctness findings were fixed:

- File fsync plus rename did not establish namespace durability before checkpoint
  success authorized WAL compaction. Saves now require both a successful
  `cmeta_fs_replace_durable` result and `PUBLISHED_DURABLE` state. Unknown or
  contradictory publication returns the existing Store `IO` error, leaving
  the worker's WAL uncompactable for that completion.
- Worker initialization/destruction could send a zero-initialized WAL handle
  to filesystem close, including repeated destruction after wiping the worker.
  Windows formal teardown exposed a CRT abort. Cleanup now closes only an
  acquired/open WAL and initializes/restores invalid handle sentinels.

Loading only treats `lstat == -ENOENT` as first start. Other lookup failures
return `IO`; nonfiles and symlinks fail validation. The exact-read path closes
its handle even on a non-EOF trailing read. Existing files must pass HMAC,
format/digest, identity/session binding, capacity and state-import checks.
A private codec transaction boundary then republishes the **original bytes**,
including the original HMAC tag, before transferring prepared state/replay
storage into the owner. Failure frees prepared storage and leaves owner/index
unchanged with `out_found=0`. Legacy V1 stays V1; V2 stays V2. Expired replay
entries may be omitted from the restored owner by existing policy, without
rewriting the file from that derived state.

The Store's const signatures, layout and error enumeration remain intact.
Adding mutable Store fault state or casting away const was avoided: snapshot
replacement has no append/dedupe acknowledgement state. A single writer may
explicitly retry the same immutable snapshot, but must obtain `OK` before any
compaction. The worker owns admission and closes it on **any** failed persistence
completion. It retains exactly one completion under its mutex for owner-thread
consumption; recovery requires destroy/init. Initialization durably restores
checkpoint bytes before opening/replaying the WAL and accepting more work.
A failed checkpoint restore releases the writer lock and never starts the pool.

The data-path bounds remain one admitted job, one owned signed-frame/result
slot or one transferred checkpoint allocation, and one persistence thread with
a queue capacity of one. Checkpoint allocation and staging disk use the existing
`MESH_CONTROL_CHECKPOINT_MAX_SIZE_V1` bound (69,107,968 bytes plus a 32-byte
HMAC for authenticated files); restore allocations remain bounded by owner
configuration. Startup adds one exact snapshot write/publication, using the
already loaded buffer. This is a durability cost; no speedup is claimed.
Shutdown explicitly drains accepted work and checks the pool's wait status.
Caller teardown must be exclusive; no owner callback runs on the worker.

Formal regressions cover byte-exact authenticated V1/V2 recovery, unchanged
owner/file on staging failure, explicit Store retry, binding-before-publication,
nonfile rejection, authentication/tamper, retained single-slot completion,
copied operation-result ownership, failed-append admission closure, repeated
and zero-worker destruction, checkpoint-before-compaction, and startup lock
release. Separate test targets wrap only the private checkpoint publication
boundary: the real filesystem writer runs before a synthetic UNKNOWN or
contradictory result is returned. There are no production fault hooks or
filesystem mocks. Worker tests verify that UNKNOWN retains WAL records,
closes admission, preserves a consumable failure, and requires successful
checkpoint republication during reinitialization.

Validation: the five codec/store/worker CTests passed **35 cases / 798
assertions** (codec 2/44, Store 8/177, worker 7/159, Store fault 11/258, worker
fault 7/160). The final complete Windows Release foundation build and CTest
run passed **75/75 tests in 98.45 seconds**; `git diff --check` passed.

Reproduce from `tests/salts_foundation`, with the preset credential environment
and Windows `VsDevCmd.bat` active:

```powershell
cmake --preset win-foundation-release
cmake --build --preset win-foundation-release --parallel 4
ctest --preset win-foundation-release -R 'test_mesh_control_(checkpoint|wal_worker|wal)' -V
ctest --preset win-foundation-release
```

Full control-agent/daemon HTTP composition and root package/installation gates
remain open, as does the separate MMP `COMMAND_RESULT` remote durable ACK
protocol. Linux, sanitizer, Android/device and actual power-cut/directory-fsync
failure were not tested here. Rollback needs no disk conversion; it restores
weaker durability and worker failure-admission behavior. Changes remain
uncommitted.

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
published RPC/IPv4 service contract, schema version 1, first octet 1..223,
remaining octets 0..255, port 1..65535 and required canonical lowercase DNS
storage (empty is permitted). Unknown fields, type
coercion, malformed or unsupported IPv6/service-family settings fail fast.
No textual address parser, host DNS resolver or alternate network engine is
introduced; IPv6 needs a separate explicitly versioned contract.

The CNet Owner receives **no DataBind objects**. After codec, immutable plan
and generated staging have been released, a caller holds an independent
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

The follow-up [generated startup contract](#generated-rpc-startup-contract-1033)
replaces the handwritten schema/getters with the shared IDL source and private
C11 CMeta/MessagePlan binding while preserving this admission behavior.

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


## Phase S2 — NativeIO SG Host with real P2P protocol Owner (#37)

The explicitly configured `p2p_cnet_owner_create_external` now borrows the
single NativeIO backend associated with one `native_io_sharded_host_lease`.
It does not create another NativeIO backend. The immutable SG runtime/shard
identity and lease generation are checked before progress; wrong-shard or
foreign tickets fail before any CNet command or completion is consumed.

One SG Owner task calls `p2p_cnet_owner_poll_sg_host`, advancing CNet external
requests then calling `native_io_sharded_context_observe_host` **exactly once**.
It routes the **whole** batch through `cnet_sg_host_route_batch`, processes
accepted child descriptors, and re-arms one external accept. SG-owned terminal
completions were settled by SG and are never resubmitted to CNet.
Each task terminates promptly; there is no Actor, hidden task loop or separate
observer. A shard supports ONE standalone P2P hosted transport through this
helper; mixed cohosting needs a **combined** host routes[] and is not admitted
by making multiple independent observe calls.

The final P2P Owner may use `p2p_node_cnet_bind_handoff_accept` without an
unneeded local listener, while the acceptor on another SG shard owns the
sole listener. The acceptor uses real Salts Server placement and bounded
`cnet_handoff`; only the final Owner makes the actual
`cnet_client_adopt_accepted` and runs P2P cookie/Noise/identity callbacks.
Credit remains TAKEN through final CNet terminal plus borrowed application
callback retirement. Stop/destroy must release all credited sockets, clients,
P2P contexts, then SG host leases **before** NativeIO SG shutdown.

The installed-SDK acceptance uses real SG worker shards, real TCP handoff and
P2P application traffic with a standalone source client outside SG. This is
a stricter gate than merely checking strategy IDs or a mocked completion
batch, but it is **not** mixed-protocol cohosting nor a 1/2/4-core performance
qualification. Complete #37 only after SG-host multi-consumer, 4-shard
workloads, real multicore benchmark and cross-platform installed SDK gates.


### Phase S3 — four SG-native P2P shards (#37)

The `test_p2p_cnet_sg_host_four` installed-SDK gate runs **four** real
`native_io_sharded` workers: one acceptor with a listener and three
separate final P2P/Noise Owners, each borrowing its own SG Host lease and
backend. The acceptor applies one CNet `ROUND_ROBIN` placement per accepted
socket, transfers it through a distinct bounded `cnet_handoff` inbox, and
the selected Owner alone performs cookie/Noise/credential admission and
application callbacks.

The three real standalone P2P clients connect in deterministic order; all
three authenticated sessions then carry distinct concurrent bidirectional
P2P messages. Each SG callback asserts its actual Owner thread identity,
and the test refuses a modified host lease generation before observing.
After terminal events, every taken handoff credit reaches zero. No SG backend
is freed before the final client, borrowed callback and Host lease drain;
an asynchronously canceled accept is observed on the **same** SG Owner
before retrying stop.

This qualifies P2P protocol *placement and correctness*, not scalability
metrics by itself. The CNet cohosting contract for two+ external clients
on one shard and repeatable 1/2/4-core latency/throughput/CPU measurements
remain independently open. Release and focused ASan/UBSan are mandatory,
and prebuilt SDK binaries remain outside instrumentation.


### Phase S4 — multiple CNet consumers on ONE SG Owner (#37)

A host can explicitly bind a P2P CNet Owner **plus up to four independent
`cnet_client_init_external` consumers** to the same shard/backend using
`p2p_cnet_owner_poll_sg_host_cohosted` (or the corresponding Node-level
domain-maintenance entry point). This is an application-composed CNet Host,
not a parser, strategy registry or second CNet polling runtime.

All clients belong to the one native SG Owner worker and borrow the **same**
registered host lease/backend. One bounded task advances every external
client, performs **exactly one**
`native_io_sharded_context_observe_host`, sends the *whole* completion batch
through **one** `cnet_sg_host_route_batch` with all clients, and advances
all consumer command/callback state once more. The host routes its optional
single listener before client completions. There is no attempt to observe or
route already-SG-owned terminals again. Duplicate/NULL client references,
excess consumers, wrong shard or stale lease reject without fallback.

Each extra CNet consumer still owns its own connection callbacks and
protocol logic; P2P cookie/Noise and signed MMP session READY cannot be
inferred from an unrelated CNet client's CONNECTED callback. All extra
consumers must reach real terminal and be stopped/destroyed on their Owner
**before** `native_io_sharded_context_release_host` succeeds. The standalone
one-consumer SG API delegates to the same shared implementation.

An installed SDK regression runs a two-shard NativeIO SG topology with a real
P2P cross-Owner handoff + Noise-authenticated bidirectional data **while**
a second, independent external CNet client on the P2P Owner's same backend
connects to a separate remote listener and exchanges real TCP request/reply
bytes. The two CNet observer lifecycles are verified on the same SG worker,
including duplicate-client refusal and terminal/resource quiescence.

This proves cohosting correctness, **not** transparent multiplexing of two
listeners on one routes[] or comparable throughput/latency measurements.
A general multi-listener group would need its own explicit admission topology.

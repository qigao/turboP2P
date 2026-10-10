# TurboP2P / SG Cohost: CNet Manager physical attachment

Parent: TurboP2P #38. Prototype integration acceptance is stacked on
the SG/native admission tests in #37. It does **not** yet replace the
production Mesh MMP endpoint pool or the signed P2P connection transport.

## Canonical source/owner split

The installed Salts 2.3 CNet already provides the authoritative:
- `cnet_client` and listener: TCP/NativeIO commands and callbacks
- `cnet_manager`: generation-safe physical connection attachment, state
  observer forwarding, and post-terminal `on_recycle`
- `cnet_client_pool`: a separate physical/stream admission budget and
  lease reuse **only after protocol authentication READY**
- `cnet_managed_dial`: optional Owner-driven reconnect episodes and
  backoff ticket semantics, never a hidden retry loop
- `native_io_sharded` SG Host: one borrowed backend, one completion observer
  per shard; P2P+independent CNet events are jointly routed in one batch

This slice qualifies a real 2-shard NativeIO SG Host containing a P2P Noise
final Owner and an independent, **plaintext TCP echo test-only Client**.
That extra client now attaches an upstream `cnet_manager` on its exact
existing SG shard. Before physical `cnet_manager_reserve/connect`, the
same Host reserves one canonical CNet Handoff credit already shared with
SG-accepted P2P. The manager observes actual socket CONNECTING/CONNECTED/
CLOSED, wraps existing CNet send/receive callbacks, and is advanced **after**
the SG Host's single combined CNet completion routing. It does no NativeIO
observe or event loop of its own.

The Host holds the credit and its observer context until the real CNet
terminal callback unwinds, then `cnet_manager_advance` invokes exactly one
`on_recycle`. Only then can the SG Owner release the original Handoff ticket.
`manager_destroy` needs a fully drained snapshot and occurs before
`cnet_client_destroy`, before P2P final-owner destroy and SG Host lease
release. Foreign-thread Manager snapshots/lookups fail owner-affinity checks;
stale managed handles no longer name a recycled record.

## Protocol security and recovery boundaries

**The extra echo connection is plaintext and is NOT MMP protocol READY.**
Neither `cnet_pool_bind_ready` nor
`cnet_managed_dial_protocol_ready` is called in this fixture. TCP CONNECTED
is only a transport event, never an authenticated P2P Noise peer or a
signed MMP service session. It does not authorize pooled reuse, protocol
command replay, or a reconnect/backoff reset.

The production `mesh_mgmt_endpoint_pool` continues to own its existing
per-peer quarantine/backoff/expiry state. Full migration of authenticated
MMP protocol READY with stable identity/authority, real Pool leases,
ManagedDial generation-safe ticket and single retry timeline remains #38.
This qualification is a **physical Manager first slice**, not that migration.

No extra sockets, NativeIO backend, Owner worker, Actor, compatibility
fallback, provider-private scheduler or new CMeta interface runtime are
introduced. Existing CMeta ACE policy remains borrowed and invoked only at
connection admission. The code must build/test against floating latest
Salts.Native 2.3.0-* and SaltsUtils.Native 4.3.0-* without exact RC pins.


## Next acceptance: ClientPool CONNECTING on the true SG Owner

The same real 2-shard SG Host fixture now creates **CNet ClientPool**
alongside its already qualified CNet Manager and extra external CNet client,
all on the **same Owner shard**. This adds only the SDK's bounded physical
CONNECTING budget, not a new socket runtime or a second recovery timeline.

Physical admission on the SG final Owner is ordered:

    CNet Handoff shared credit reserve
       -> cnet_pool_reserve_connecting(key)
       -> cnet_manager_reserve(attachment)
       -> cnet_manager_connect(real tcp://127.0.0.1:port)
       -> one NativeIO SG Host observe/routes batch
       -> cnet_manager_advance (post-transport terminal recycle)
       -> cnet_pool_terminal (CONNECTING, never READY)
       -> CNet Handoff credit release
       -> cnet_pool_destroy -> cnet_manager_destroy -> cnet_client_destroy
       -> SG Host lease release

The copied **test-only pool key** contains nonzero, stable runtime, Owner,
endpoint, placeholder authority, transport and echo-protocol identifiers.
Its provisional authority ID is NOT a signed enrollment fact and it can
**never authorize reuse**. A copied key is merely CNet's physical CONNECTING
partition; cross-Owner reserve rejects and capacity cannot be overbooked.
No MMP protocol callback is fabricated.

A real CNet TCP CONNECTED event, plus fully exchanged echo bytes, must still
leave the upstream pool snapshot at `connecting=1, ready=0,
active_leases=0`, and `cnet_pool_try_acquire` must refuse with ENOBUFS.
`cnet_pool_bind_ready` is **not** called at all. The first real Manager
`on_recycle` unlocks terminal release, and the now-retired generation
cannot be released or looked up again. Destroy is blocked until both Pool and
Manager have genuinely drained and shared SG Handoff credits are returned.
The main thread has no authority to inspect or mutate the Owner-local Pool.

Production integration of **authenticated** CNet ClientPool leases requires
binding the **same Manager-owned physical connection** that actually carries
P2P Noise + signed MMP identity. The unrelated plaintext echo connection
cannot inherit the already-authenticated P2P neighbor's READY capability.
No hidden reconnect, MMP command replay or CNet ManagedDial state is added.
That signed protocol boundary and a single authoritative retry timeline
remain the subsequent phase of issue #38.


## Signed MMP Router READY proof (not a generic CONNECTED callback)

The dedicated production Mesh CNet/MMP Router now offers
`mesh_mgmt_agent_router_ready_session_v1()` to copy a **bounded,
generation-bound, verified** MMP readiness snapshot from its *actual live*
signed session, using the existing certificate and Router session state.
The caller must present the expected 32-byte P2P transport identity and
expected signed 32-byte managed-node identity. The Router verifies:
- its own active P2P peer slot is still READY, not disconnecting, failed
  or pending close;
- signed MMP session state is ESTABLISHED and remote HELLO verified;
- the signed remote certificate's transport/managed-node IDs match the
  locally verified P2P slot and the requested identity;
- there is no second simultaneously qualified signed session for that
  managed node;
- if supplied, the previous/current exact 16-byte Router
  `connection_id` equals the still-live generation (preventing the
  previous session from being silently reused after reconnect).

On success the result copies the signed identity, current connection ID,
remote session ID and signed remote incarnation; **on every failure it
zeros the output**. There is no packet-path reflection walk, Manager
reservation, new network worker, DHT access or automatic retry. The real
dedicated CNet management runtime test covers two signed P2P+MMP peers,
wrong transport identity, wrong managed-node identity, foreign peer and
the stale old `connection_id` after an actual reconnect. The fresh
generation can be attested again.

**This proof is not itself a CNet Manager binding or a Pool lease.**
A future production adapter must additionally prove that the *same*
physical Manager connection carries this authenticated P2P/MMP session,
recheck the token against the Router immediately before a
`cnet_pool_bind_ready` operation, and use a correctly projected complete
Pool security key. An unrelated plaintext SG Cohost Manager cannot borrow
this READY proof by having the same Owner or Host. There is no
`cnet_pool_bind_ready` call in the plaintext echo fixture.


## Exact managed physical P2P stream and signed Router READY

This phase changes **actual incoming P2P CNet Adopt**, not the independent
plaintext Cohost, to use upstream `cnet_manager_reserve/adopt` on its
original final Owner. The Manager borrows the *existing P2P CNet client*:
it creates neither NativeIO backend, observer, thread, reconnect timer nor
a second physical socket.

- Each final P2P Owner initializes one bounded Manager attachment table
  alongside its own `cnet_client`. The real cross-Owner or same-Owner TCP
  accepted descriptor is consumed by `cnet_manager_adopt`, forwarding the
  existing P2P cookie/Noise callbacks through the Manager's single observer.
  Outbound P2P remains unmanaged until a later explicit migration; it does
  not inherit an inbound READY capability.
- The P2P CNet connection retains its original
  `cnet_managed_connection` generation. `on_recycle` only marks that
  the native CNet terminal observer finished and Manager callback storage
  can be retired; it never releases peer callbacks inside a terminal event.
  Poll or SG Host progression explicitly calls `cnet_manager_advance`.
  P2P connection sweep must not release a taken/reserved Handoff credit
  or free the observer's context before `on_recycle`. On stop/drain,
  Manager must drain/destroy **before** the borrowed CNet client and
  final SG Host lease are released; timeout retains context for retry.
- An exact P2P `p2p_connection_t` exposes its Manager-bound physical
  identity only via `p2p_cnet_connection_managed_binding_v1`: CNet
  Manager BOUND record, same native physical `cnet_connection`
  slot+generation and identical P2P callback context are all verified
  on the original Owner. `p2p_peer_cnet_managed_binding_v1` obtains
  only the current live `peer->conn`. Foreign Owner, terminated,
  detached, recycled, stale or outbound/unmanaged connections cannot
  return a physical binding.
- `mesh_mgmt_agent_router_physical_ready_v1` first requires the
  original signed MMP Router READY attestation (live P2P peer,
  certificate-verified transport and managed-node IDs, and optional
  current Router `connection_id` generation). It then requires that
  exact peer's P2P CNet connection is **Manager BOUND** on the caller's
  expected Manager, including matching CNet physical slot/generation
  and attached observer. Only then does it copy the two proofs.
  A separate plain SG Cohost Manager cannot satisfy this check even
  when sharing the identical Host backend and Owner shard.

The real dedicated MMP CNet runtime test now verifies positive signing +
same physical inbound Manager, refusal of an unrelated Manager and
unmanaged outbound Client, then performs a **real signed reconnect**:
the prior Router connection_id is stale, the old CNet Manager record
generation has been recycled, and the fresh Manager-bound physical
generation can be attested again. A separate real SG cross-Owner
Noise test validates the same final-Owner Manager binding.

### Still not Pool READY

This binds real signed Router identity to the *same* Manager-owned
physical P2P connection and is the required prerequisite for
`cnet_pool_bind_ready`, but it is **not** a Pool lease and does not
modify the unrelated plaintext SG Cohost Pool into READY. A future
production Pool integration must reserve CONNECTING **on this exact
Manager before connecting/Adopting**, build an exact signed-authority
and connection-generation-bound CNet `cnet_pool_key`, revalidate
the live Router proof at bind, and settle actual protocol-slot leases
once. No ManagedDial READY is signaled and no duplicate
quarantine/reconnect timeline is installed. The existing Mesh
endpoint pool still owns its retry policy. Windows/macOS/Android
installed consumers and performance benchmarks are separate gates.

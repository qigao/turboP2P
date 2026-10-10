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

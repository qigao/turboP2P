# RPC virtual service record

## Background

The mesh has two distinct address domains:

- Physical transport endpoints are used by the P2P runtime to establish links.
- Virtual RPC endpoints are used by authenticated users and control-plane clients.

Publishing a virtual address as a transport endpoint would allow discovery data to
enter dial state and would also expose physical topology through the RPC contract.

## Decision

RPC discovery uses an independent signed service record and DHT namespace:

```text
mgmt:<mesh-id-hash>:node:<node-id>:service:rpc
```

The canonical payload contains only:

- owner node ID
- service type (`rpc`)
- virtual IPv4 or IPv6 address
- optional lowercase canonical MagicDNS name
- RPC port
- monotonically increasing record epoch
- expiration time

The existing management envelope and enrollment certificate establish provenance.
Verification binds the mesh, enrolled node, signing key, certificate serial,
principal epoch, record epoch, and expiration before producing a query record.

The verified service record is not compatible with
`mesh_mgmt_endpoint_record_v1_t` and must never be applied to the physical
endpoint pool.

## Alternatives

Reusing the physical endpoint record was rejected because its output is designed
to enter transport dial state and includes a transport peer ID.

Returning bind or advertised addresses from `/status` was rejected because status
is local diagnostic output rather than authenticated mesh discovery.

Maintaining an RPC-only central registry remains possible later, but would add a
new availability and state-consistency dependency.

## Tradeoffs

The separate record adds one codec, verifier, and DHT key per node. In return, the
transport and control-plane security boundaries remain explicit, physical
addresses are not part of the user-facing contract, and service records can
evolve without changing transport discovery.

## Migration

1. Nodes continue serving RPC on their configured bind address.
2. The service publisher signs the configured virtual DNS/IP and writes the RPC service key.
3. Consumers read the local DHT cache, verify the record, and connect through
   `virtual_host:port`; cache reads never modify transport endpoint state.
   When resolving by node ID, the certificate must come from an established
   authenticated management session, not from RPC input.
4. The RPC adapter may expose a verified snapshot through
   `GET /v1/node/resolve/<node-id>`. It must return unavailable when no verified
   resolver is connected and must never fall back to physical addresses.
5. Explicit `meshctl --addr` remains a compatibility path until verified service
   lookup is available everywhere.

No existing endpoint key, wire payload, or RPC response is changed by this step.

The `meshd` startup path now admits the configured RPC IPv4/DNS/port as the
static `MeshMgmtRpcServiceV1` Component. Its concrete
`meshd_rpc_service_component` Owner stores one immutable native config
snapshot, one bounded generation and one address-stable scope. Startup uses
the existing daemon config; it introduces no new CLI option or config format.
The existing 10-second refresh interval reuses that snapshot and the agent's
signer/durable epoch allocator. No schema or reflection graph is traversed on
each refresh, and the Component supplies service data without changing trust
or physical endpoint policy.

Startup and the existing daemon loop call the same Owner refresh step. Its first
call attempts publication immediately; later attempts wait 10 seconds after the
previous attempt completes, including failures. Interval suppression returns
epoch zero without signer, allocator or transport work. A late loop iteration
emits at most one record, and a backward monotonic sample is rejected without
changing the deadline. The clock callback is borrowed synchronously and creates
no timer or additional progress Owner.

Native startup passes explicit storage views for the fixed IPv4/virtual-host
fields. The private adapter checks bounded NUL termination before comparison and
IPv4 parsing, preserves exact IP-host equality as empty DNS, and delegates service
policy and immutable config ownership to Component. Source fields may expire
after admission; malformed storage or policy errors never publish partial state.

Publication and lifecycle remain on the daemon Owner thread. Salts' existing
thread-affinity state rejects foreign-thread calls and marks synchronous
publication busy, so epoch/signing callbacks cannot destroy its borrowed DNS or
reenter publication. Checked shutdown closes scope admission, releases the
Owner's view/scope, drains Component objects and destroys generation runtime
before management contexts are reset. If an additional scope makes drain
BUSY, its generation storage stays alive for explicit release and retry.
Successful signed publication leaves encoded frames owned by the existing
cache/transport, so those frames do not require the service Owner after return.

The daemon's `meshd_management_epoch` storage uses Salts' durable replacement
primitive to persist the next unused epoch before signing. Existing decimal
files and lock paths remain compatible. A missing file may initialize from the
configured seed; corrupt or inaccessible state is refused. Unconfirmed durability
withholds the epoch and fences further allocation until checked close/reopen.
Exhaustion never wraps. The existing daemon opens one storage Owner per path;
POSIX process locks do not authorize duplicate same-process Owners.

## Rollback

Disable service-record publication and lookup. Existing physical endpoint
discovery and explicit RPC addresses remain unchanged because the namespaces and
types are independent.

## Verification scope

The optional strict JSON RPC startup adapter uses
`mesh/contracts/rpc_service_config.schema` as its single field/constraint source.
The installed SaltsUtils `salts_idl_target(ARTIFACTS TYPES)` generates private C11
native records and CMeta VALUE bindings; the same schema is embedded in the
build for startup MessagePlan admission. There is no generated Binary codec or
change to the signed TLV service payload. Exact JSON tokens, required fields,
version/range constraints and canonical address/DNS admission remain enforced.
The generated text carrier is confined to owned staging and destroyed before
return. Only the existing fixed-storage config reaches Component/CNet. The
private generated header is C11; C++ consumes the existing config C ABI and
retained producer descriptors, not that generated header.

Tests cover canonical key separation, payload round trips, DNS rejection, signed
identity binding, tamper rejection, explicit runtime publication, propagation to
a connected peer's DHT cache, and fail-closed cached reads. Iterative DHT lookup,
expiry replacement, and `meshctl` integration require focused tests when those
layers are connected.

The installed-SDK foundation suite additionally exercises the exact daemon
service Owner: config snapshot ownership, invalid-init rollback, copied/foreign
Owner rejection, BUSY destroy/retry, real signed refresh epochs and callback
reentry rejection. Complete `meshd`/tunnel/HTTP root execution still requires
qualification of the legacy root graph; these focused tests do not imply it.
The real CNet suite additionally closes/reopens the exact daemon epoch storage
between signed refreshes and verifies continued epochs at the remote peer.
The same production refresh step is tested with a deterministic monotonic clock:
first-attempt failure, suppressed calls without epoch/callback effects, exact
retry boundaries, completion-based cadence, backward time, near-UINT64_MAX
arithmetic, and fresh startup after retirement. The remote peer verifies signed
epoch 6 after final service Owner destruction. Actual OS loop/tunnel timing and
upstream config parsing/MagicDNS selection remain unqualified by this focused
suite. Native startup conversion itself is now covered, including unterminated
fields, maximum canonical DNS/port, source mutation and failed-admission rollback.
The real CNet case also signs the IP-only native form at epoch 7, destroys its
service Owner, then verifies empty DNS and the virtual IP at the remote peer.
Focused storage tests cover malformed files, retry before publication, exhaustion
and OS locks. Linux fault injection and crash/power-loss qualification remain open.

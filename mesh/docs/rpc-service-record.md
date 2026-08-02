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

## Rollback

Disable service-record publication and lookup. Existing physical endpoint
discovery and explicit RPC addresses remain unchanged because the namespaces and
types are independent.

## Verification scope

Tests cover canonical key separation, payload round trips, DNS rejection, signed
identity binding, tamper rejection, explicit runtime publication, propagation to
a connected peer's DHT cache, and fail-closed cached reads. Automatic refresh,
iterative DHT lookup, expiry replacement, and `meshctl` integration require
focused tests when those layers are connected.

# Management control plane on the shared mesh node

## Decision

The mesh data plane remains the sole owner of the P2P node callbacks. The MMP
management router runs in embedded mode and receives peer and custom-message
events from `mesh_network_t`. No second listener, P2P identity, or event loop is
created.

## Background

The standalone management runtime owns a private listener and installs the MMP
router as the exclusive P2P callback owner. `mesh_network_t` already owns those
callbacks for mesh HELLO, route control, ICE signaling, and packet transport.
Installing the router directly would replace the mesh callbacks and break the
data plane.

## Alternatives

- A second management listener preserves callback isolation but creates two
  transport identities, two endpoint records, and two lifecycle owners.
- Moving the complete mesh data plane into the management runtime would require
  a broad migration of routing, ICE, and packet behavior.
- Shared callback dispatch keeps one transport identity and one listener while
  retaining separate protocol state machines.

## Ownership and dispatch

- `mesh_network_t` owns the P2P node and all registered P2P callbacks.
- The caller owns `mesh_mgmt_agent_router_v1_t`; mesh borrows it while attached.
- Peer connect and disconnect events are forwarded to the router.
- MMP custom messages are consumed by the router before legacy mesh parsing.
- `MESH_MGMT_AGENT_ROUTER_NOT_MMP` returns ownership to the existing mesh
  protocol path.
- Malformed, unauthorized, or otherwise rejected MMP input is consumed and
  never falls through to mesh HELLO, route, ICE, or packet parsing.

## Lifecycle

The router is initialized against
`mesh_mgmt_mesh_borrow_p2p_node_v1(mesh)` and attached before `mesh_start()`.
Detaching retires MMP sessions but does not disconnect shared P2P peers.
`mesh_destroy()` attempts to detach before destroying the P2P node. The caller
must keep the router alive until detach or mesh destruction completes.

## Compatibility

The public `turbo_mesh.h`, `mesh_config_t`, mesh wire messages, and listener
configuration are unchanged. The bridge remains internal until management
identity, trust, and enrollment configuration have a stable deployment
contract.

## Migration

1. Initialize the mesh and obtain its borrowed P2P node.
2. Build the existing signer and dispatch templates for that node identity.
3. Initialize the MMP router with the borrowed node.
4. Alternatively configure `mesh_mgmt_agent_runtime_v1_t` with `shared_mesh`;
   listener, private-key, and management bootstrap fields must remain empty.
5. Start the router or runtime before `mesh_start()`.
6. Start the mesh; both data-plane and management traffic use the same peers.
7. Poll only the mesh event loop in shared mode.
8. Stop the runtime to detach MMP, then stop and destroy the mesh.

The current standalone management runtime remains available during migration.

## Rollback

Remove the bridge attachment and continue using the standalone management
runtime. No mesh configuration, persistent data, or wire-format migration is
required.

## Validation scope

Focused validation must cover:

- exclusive router callback mode remains unchanged;
- embedded mode completes an authenticated bilateral MMP handshake;
- non-MMP messages still reach mesh HELLO/control/data dispatch;
- rejected MMP messages cannot fall through to the mesh parser;
- detaching management leaves shared data-plane peers connected;
- mesh stop and destroy retire every MMP peer exactly once.

#ifndef P2P_PEER_CNET_H
#define P2P_PEER_CNET_H
#include "peer.h"
#include "cnet_transport.h"
#include "../security/p2p_cookie.h"

/* Internal owner-thread binding; public node constructors still own CoroNet.
 * The caller enforces node admission policy and retains the node until peers
 * and private-key work are drained. The peer owns its connection. */
int p2p_peer_connect_cnet(p2p_peer_t *peer, p2p_cnet_owner_t *owner);
/* Called by the node's verified-cookie promotion hook. Copies borrowed proof
 * into peer storage. On success pass output to admission unchanged; connected
 * attaches the actual connection and starts the existing inbound handshake.
 * A failed handoff calls closed, releasing the prepared peer reservation. */
int p2p_peer_prepare_cnet_inbound(p2p_peer_t *peer,
    const uint8_t preface[P2P_SECURE_PREFACE_SIZE],
    const uint8_t binding[P2P_COOKIE_BINDING_SIZE], p2p_cnet_callbacks_t *output);
/* Borrowed, Owner-local CNet Manager physical binding for exact peer->conn.
 * Must be combined with the live Router's signed MMP proof before any
 * ClientPool READY, never with an unrelated Cohost CNet client. */
int p2p_peer_cnet_managed_binding_v1(
    const p2p_peer_t *peer, p2p_cnet_managed_binding_v1_t *out);

#endif

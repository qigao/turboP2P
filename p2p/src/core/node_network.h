#ifndef P2P_NODE_NETWORK_H
#define P2P_NODE_NETWORK_H

#include "../internal.h"

/* Explicit owner binding; no runtime detection or implicit backend fallback.
 * Queries run under node->mutex on the owner thread and must not mutate state. */
struct p2p_node_network_ops_s {
    int (*connect)(p2p_peer_t *peer, void *context);
    int (*pending_gates)(p2p_node_t *node, const char *source_ip,
        size_t *total, size_t *source, void *context);
};

int p2p_node_source_prefix_matches(const char *left, const char *right);
p2p_security_rejection_reason_v2_t p2p_node_pending_peer_rejection_locked(
    p2p_node_t *node, const char *source_ip);
void p2p_node_record_handshake_latency_locked(p2p_node_t *node,
    p2p_security_role_t role, p2p_security_latency_stage_t stage,
    uint64_t started_ms, uint64_t completed_ms);
/* Owner-thread expiry/probing; callbacks and I/O occur outside node->mutex. */
void p2p_node_expire_pending_peers(p2p_node_t *node, uint64_t now_ms);
void p2p_node_maintain_peers(p2p_node_t *node, uint64_t now_ms);

#endif

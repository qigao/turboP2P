#include "p2p.h"
#include "../core/node_network.h"

int p2p_poll(p2p_node_t *node) {
    const p2p_node_network_ops_t *ops;
    if (!node) return P2P_ERR_INVALID_ARG;
    ops = node->network_ops;
    if (!ops || !ops->poll) return P2P_ERR_INVALID_STATE;
    return ops->poll(node, node->network_context);
}

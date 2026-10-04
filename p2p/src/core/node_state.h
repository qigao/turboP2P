#ifndef P2P_NODE_STATE_H
#define P2P_NODE_STATE_H
#include "../internal.h"

/* Private shared constructor; owns mutex, DHT, identity and transfer manager.
 * An explicit network owner must be attached before starting network work. */
p2p_node_t *p2p_node_state_create(const char *ip, int port);
/* Network owner must be destroyed first. Retains node and manager on live
 * transfer leases; release them and retry on the same owner thread. */
int p2p_node_state_destroy(p2p_node_t *node);
int p2p_node_cleanup_transfers(p2p_node_t *node);
/* Legacy counters or a final quiescent CNet snapshot, under node->mutex. */
void p2p_node_saved_cookie_status_locked(const p2p_node_t *node,
    p2p_node_cookie_status_t *status);
#endif

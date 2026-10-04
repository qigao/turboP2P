#ifndef P2P_NODE_CNET_H
#define P2P_NODE_CNET_H

#include "node_network.h"
#include "cnet_transport.h"
#include "../security/p2p_cnet_admission.h"

typedef struct p2p_node_cnet_s p2p_node_cnet_t;

/* @internal @incomplete Public constructors/get_loop and file-transfer owner
 * migration remain separate work. This explicit network owner runs the real
 * node policy, peer protocol, PING/PONG and DHT. A file_message_handler must be
 * attached before file traffic is accepted; absence closes that connection.
 *
 * The caller provides an initialized, security-configured node with mutex/DHT,
 * no legacy context/listener/timer, peers or lookups. The node, credentials,
 * callbacks and optional polling key executor remain borrowed through destroy.
 * All operations/callbacks run on one owner thread. No public backend selection.
 * Tracked peers, including retained failed endpoints, are capped by the CNet
 * connection capacity; cookie gates additionally have their configured cap.
 */
int p2p_node_cnet_create(p2p_node_t *node, const p2p_cnet_config_t *config,
    p2p_node_cnet_t **output);
int p2p_node_cnet_listen(p2p_node_cnet_t *owner);
/* Bounded nonblocking turn: expire, pump worker, progress CNet, maintain peers
 * and DHT. The caller supplies scheduling; no background native timer. */
int p2p_node_cnet_poll(p2p_node_cnet_t *owner);
/* Callback stop is deferred until poll returns. Stop is terminal, joins the
 * key worker, detaches/destroys peers and cancels lookups before CNet drain.
 * On drain timeout retain owner AND node; retry stop/destroy. Destroy inside a
 * callback is rejected. Stop does not destroy the borrowed executor or node. */
int p2p_node_cnet_stop(p2p_node_cnet_t *owner);
int p2p_node_cnet_destroy(p2p_node_cnet_t *owner);
int p2p_node_cnet_admission_stats(const p2p_node_cnet_t *owner,
    p2p_cnet_admission_stats_t *output);

#endif

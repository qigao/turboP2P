/**
 * connection.h - typed CNet connection ownership for one P2P peer.
 */
#ifndef P2P_CONNECTION_H
#define P2P_CONNECTION_H

#include <cnet/cnet.h>
#include <stddef.h>

typedef struct p2p_connection_s p2p_connection_t;

typedef enum {
    P2P_CONN_OUTBOUND,
    P2P_CONN_INBOUND
} p2p_conn_type_t;

struct p2p_connection_s {
    p2p_conn_type_t type;
    cnet_client *owner;
    cnet_connection handle;
    int is_connected;
    int close_requested;
};

p2p_connection_t *p2p_connection_create(p2p_conn_type_t type,
                                         cnet_client *owner,
                                         cnet_connection handle);
void p2p_connection_destroy(p2p_connection_t *conn);
int p2p_connection_send(p2p_connection_t *conn, const void *data, size_t len);
int p2p_connection_close(p2p_connection_t *conn);

#endif /* P2P_CONNECTION_H */

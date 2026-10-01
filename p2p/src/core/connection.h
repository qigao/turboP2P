/**
 * connection.h - P2P ownership wrapper for one CNet connection.
 *
 * CNet remains the sole transport runtime. This structure carries only
 * P2P metadata plus a generation-checked CNet handle.
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
    cnet_client *client;
    cnet_connection handle;
    int close_requested;
};

p2p_connection_t *p2p_connection_create(cnet_client *client,
                                        cnet_connection handle,
                                        p2p_conn_type_t type);
void p2p_connection_destroy(p2p_connection_t *conn);
int p2p_connection_send(p2p_connection_t *conn, const void *data, size_t len);
int p2p_connection_close(p2p_connection_t *conn);

#endif /* P2P_CONNECTION_H */

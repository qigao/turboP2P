/**
 * connection.h - Unified connection abstraction
 * Eliminates dual client/conn state
 */

#ifndef P2P_CONNECTION_H
#define P2P_CONNECTION_H

#include <stddef.h>

/* Forward declarations */
typedef struct p2p_connection_s p2p_connection_t;

/* Connection types */
typedef enum {
    P2P_CONN_OUTBOUND,  /* Client-initiated */
    P2P_CONN_INBOUND    /* Server-accepted */
} p2p_conn_type_t;

/* Connection operations (virtual function table) */
typedef struct {
    int (*send)(void *handle, const void *data, size_t len);
    void (*close)(void *handle);
    void *handle;
} p2p_conn_ops_t;

/* Unified connection structure */
struct p2p_connection_s {
    p2p_conn_type_t type;
    p2p_conn_ops_t ops;
    int is_connected;
};

/* Connection lifecycle */
p2p_connection_t *p2p_connection_create_outbound(void *client_handle);
p2p_connection_t *p2p_connection_create_inbound(void *server_handle, void *conn_handle);
void p2p_connection_destroy(p2p_connection_t *conn);

/* Connection operations */
int p2p_connection_send(p2p_connection_t *conn, const void *data, size_t len);
void p2p_connection_close(p2p_connection_t *conn);

#endif /* P2P_CONNECTION_H */

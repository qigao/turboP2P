/**
 * connection.h - Unified connection abstraction
 * Eliminates dual client/conn state
 */

#ifndef P2P_CONNECTION_H
#define P2P_CONNECTION_H

#include <stddef.h>

/* Forward declarations */
typedef struct p2p_connection_s p2p_connection_t;
typedef void (*p2p_send_complete_fn)(void *context, int status);

/* Connection types */
typedef enum {
    P2P_CONN_OUTBOUND,  /* Client-initiated */
    P2P_CONN_INBOUND    /* Server-accepted */
} p2p_conn_type_t;

/* Connection operations (virtual function table) */
typedef struct {
    /* Returns P2P_OK for admission, otherwise a P2P error. */
    int (*send)(void *handle, const void *data, size_t len);
    void (*close)(void *handle);
    void *handle;
    /* Optional asynchronous owner: detach callbacks and reclaim after quiescence. */
    void (*destroy)(void *handle);
    int (*pause)(void *handle, int paused);
    int (*send_completed)(void *handle, const void *data, size_t len,
                          p2p_send_complete_fn complete, void *context);
    /* CNet-only durable app send completion. Unlike security's borrowed
     * callback, the application context stays live after logical detach
     * until CNet reports full wire-write or physical terminal. */
    int (*send_terminal)(void *handle, const void *data, size_t len,
                         p2p_send_complete_fn complete, void *context);
} p2p_conn_ops_t;

/* Unified connection structure */
struct p2p_connection_s {
    p2p_conn_type_t type;
    p2p_conn_ops_t ops;
    int is_connected;
};

/* Connection lifecycle */
p2p_connection_t *p2p_connection_create_outbound(void *client_handle);
p2p_connection_t *p2p_connection_create_inbound(void *conn_handle);
void p2p_connection_destroy(p2p_connection_t *conn);

/* Connection operations */
int p2p_connection_send(p2p_connection_t *conn, const void *data, size_t len);
void p2p_connection_close(p2p_connection_t *conn);
int p2p_connection_pause(p2p_connection_t *conn, int paused);
/* Copies bytes before return. Rejection produces no completion; admission
 * produces one continuation: CNet waits for the full-write terminal; the
 * explicit CoroNet adapter preserves its inline admission-based continuation.
 * Destroy detaches pending completions together with other protocol callbacks.
 * Context is borrowed until completion or destroy. All calls are owner-thread. */
int p2p_connection_send_completed(p2p_connection_t *conn, const void *data,
    size_t len, p2p_send_complete_fn complete, void *context);
/* CNet full logical wire-write or final failure, including after P2P logical
 * detach. Exactly one callback after accepted admission; none on rejection.
 * Only the live CNet Owner may drive progress. Legacy CoroNet fails closed. */
int p2p_connection_send_terminal(p2p_connection_t *conn, const void *data,
    size_t len, p2p_send_complete_fn complete, void *context);

#endif /* P2P_CONNECTION_H */

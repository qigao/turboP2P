#ifndef P2P_CNET_TRANSPORT_H
#define P2P_CNET_TRANSPORT_H

#include "connection.h"
#include "../../include/p2p.h"
#include <cnet/cnet.h>

typedef struct p2p_cnet_owner_s p2p_cnet_owner_t;

typedef struct {
    int (*connected)(p2p_connection_t *connection, void *context);
    /* Consume a prefix. The owner routes the remainder to the current callback,
     * so a cookie gate may hand off to its peer without losing a coalesced tail.
     * Zero consumption is valid only after pausing or closing the connection.
     * The bytes are borrowed until return; retain/copy in the protocol if needed. */
    int (*receive)(p2p_connection_t *connection, const uint8_t *bytes,
                   size_t length, size_t *consumed, void *context);
    void (*sent)(p2p_connection_t *connection, size_t length, void *context);
    void (*closed)(p2p_connection_t *connection, int status, void *context);
    void *context;
} p2p_cnet_callbacks_t;

typedef struct {
    cnet_client_config client;
    size_t send_hwm_bytes;
    size_t pending_write_limit;
    size_t accept_budget;
    uint32_t stop_timeout_ms;
} p2p_cnet_config_t;

/* Install callbacks during accept. Rejection detaches callbacks and closes;
 * the rejecting callback retains responsibility for its application context. */
typedef int (*p2p_cnet_accept_fn)(p2p_cnet_owner_t *owner,
                                  p2p_connection_t *connection,
                                  const cnet_stream_peer *peer, void *context);

/* Internal plaintext TCP owner for the P2P Noise protocol. All calls and
 * callbacks belong to one thread. No implicit backend or TLS fallback.
 * Config bounds are mandatory; TLS storage must be zero. Returns P2P errors.
 * This owner is explicit and is not selected by the legacy node constructors. */
int p2p_cnet_owner_create(const p2p_cnet_config_t *config,
                          p2p_cnet_owner_t **output);
int p2p_cnet_owner_listen(p2p_cnet_owner_t *owner, const char *host,
                          uint16_t port, size_t backlog,
                          p2p_cnet_accept_fn accept, void *context,
                          cnet_stream_peer *local);
int p2p_cnet_owner_connect(p2p_cnet_owner_t *owner, const cnet_stream_peer *peer,
                           const p2p_cnet_callbacks_t *callbacks,
                           p2p_connection_t **output);
/* One bounded, nonblocking accept/client/receive pass. Recursive progress is
 * rejected. Paused receive storage is at most one configured receive buffer. */
int p2p_cnet_owner_poll(p2p_cnet_owner_t *owner);
/* Stop inside a callback is deferred to poll return. Destruction inside any
 * callback is rejected. Retry stop/destroy after a drain timeout; retain owner
 * and callback contexts until destroy succeeds. Stopped owners cannot restart. */
int p2p_cnet_owner_stop(p2p_cnet_owner_t *owner);
int p2p_cnet_owner_destroy(p2p_cnet_owner_t *owner);
size_t p2p_cnet_owner_connection_count(const p2p_cnet_owner_t *owner);

/* Copies callback descriptors; the context remains borrowed. May be called
 * during receive for cookie-to-peer handoff. Existing admitted sends keep FIFO
 * ownership and completion is delivered to the callbacks active at completion.
 * Protocols must wait for their own send terminal before publishing readiness. */
int p2p_cnet_connection_handoff(p2p_connection_t *connection,
                                const p2p_cnet_callbacks_t *callbacks);
int p2p_cnet_connection_pause(p2p_connection_t *connection, int paused);
int p2p_cnet_connection_set_send_hwm(p2p_connection_t *connection, size_t bytes);
size_t p2p_cnet_connection_pending_bytes(const p2p_connection_t *connection);
/* p2p_connection_destroy() detaches application callbacks immediately. The
 * owner retains observer storage through CLOSED/FAILED or completed stop and
 * frees it only after returning from CNet progress. Treat the pointer as
 * invalid immediately after destroy; terminal connections otherwise stay
 * queryable until explicit destroy or owner destruction. */

#endif

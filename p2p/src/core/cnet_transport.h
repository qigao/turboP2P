#ifndef P2P_CNET_TRANSPORT_H
#define P2P_CNET_TRANSPORT_H

#include "connection.h"
#include "../../include/p2p.h"
#include <cnet/cnet.h>
#include <cnet/handoff.h>
#include <cnet/owner_placement.h>
#include <cnet/sg_host.h>

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
 * The public v2 lifecycle selects this owner; legacy constructors remain separate. */
int p2p_cnet_owner_create(const p2p_cnet_config_t *config,
                          p2p_cnet_owner_t **output);

/* SG-native Host mode: caller provides one live shard-owned NativeIO backend
 * under a native_io_sharded_host_lease and exclusively drives the callback
 * owner on that shard. CNet will never create/observe/destroy a second backend.
 * Do not share this backend with another observer or with a standalone poller.
 * The caller must not release the SG lease before owner_destroy succeeds. */
int p2p_cnet_owner_create_external(const p2p_cnet_config_t *config,
                                   native_io_backend *borrowed_backend,
                                   native_io_sharded_host_lease lease,
                                   p2p_cnet_owner_t **output);

int p2p_cnet_owner_listen(p2p_cnet_owner_t *owner, const char *host,
                          uint16_t port, size_t backlog,
                          p2p_cnet_accept_fn accept, void *context,
                          cnet_stream_peer *local);
/* A final SG Owner binds real P2P cookie admission without opening another
 * socket/listener on its native SG shard. Exclusive startup only. */
int p2p_cnet_owner_bind_handoff_accept(p2p_cnet_owner_t *owner,
                                       p2p_cnet_accept_fn accept,
                                       void *context);

int p2p_cnet_owner_connect(p2p_cnet_owner_t *owner, const cnet_stream_peer *peer,
                           const p2p_cnet_callbacks_t *callbacks,
                           p2p_connection_t **output);
/* One bounded, nonblocking accept/client/receive pass. Recursive progress is
 * rejected. Paused receive storage is at most one configured receive buffer. */
int p2p_cnet_owner_poll(p2p_cnet_owner_t *owner);

/* Runs one Owner task using ONE authoritative NativeIO SG observe batch.
 * Explicit EXTERNAL clients/listener, not the owned-backend polling path.
 * On the fixed SG Owner: advance client commands, observe through caller's
 * registered host lease ONCE, route the WHOLE batch with cnet_sg_host_route_batch,
 * advance clients and process local accepted/handoff streams and callbacks.
 * Can be used by exactly ONE externally hosted transport per shard; additional
 * cohosted CNet consumers must be composed in a higher-level joint routes[]
 * host and cannot call this standalone function on the same batch.
 * out_observed and out_sg_settled are cleared on entry. */
int p2p_cnet_owner_poll_sg_host(p2p_cnet_owner_t *owner,
                                native_io_sharded_context *context,
                                native_io_sharded_host_lease lease,
                                size_t *out_observed,
                                size_t *out_sg_settled);

/* Host-composed, owner-local SG routing for 1 P2P CNet transport plus at most
 * four other independent CNet clients borrowing THE SAME SG Host backend.
 *
 * These extra clients must already have been initialized with
 * cnet_client_init_external() using the exact borrowed_backend passed to this
 * transport, and their lifecycle/owner affine callbacks remain caller-owned.
 * At most one external listener belongs to this route group (the P2P one).
 *
 * Each call performs ONE native_io_sharded_context_observe_host(), then ONE
 * combined cnet_sg_host_route_batch() with every client. All SG-owned
 * completions remain SG-settled, not re-submitted to any consumer. This API
 * does not install secondary observe loops or create an Actor/backend.
 *
 * No duplicate/NULL CNet clients or P2P client's own internal handle are
 * permitted in extras; wrong lease/shard and invalid configuration fail fast.
 * Extra clients must reach real terminal/stop/destroy BEFORE SG lease release.
 * Do not call the standalone SG poll on any participant in the same batch. */
#define P2P_CNET_SG_MAX_COHOST_CLIENTS 4u
/* Side-effect-free admission check for the P2P Node wrapper. Always check
 * lease, shard and client aliases BEFORE P2P protocol maintenance. */
int p2p_cnet_owner_preflight_sg_host(
    p2p_cnet_owner_t *owner, cnet_client *const *extras, size_t extra_count,
    native_io_sharded_context *context, native_io_sharded_host_lease lease);
int p2p_cnet_owner_poll_sg_host_cohosted(
    p2p_cnet_owner_t *owner, cnet_client *const *extras, size_t extra_count,
    native_io_sharded_context *context,
    native_io_sharded_host_lease lease,
    size_t *out_observed, size_t *out_sg_settled);


/* Stop inside a callback is deferred to poll return. Destruction inside any
 * callback is rejected. Retry stop/destroy after a drain timeout; retain owner
 * and callback contexts until destroy succeeds. Stopped owners cannot restart. */
int p2p_cnet_owner_stop(p2p_cnet_owner_t *owner);
int p2p_cnet_owner_destroy(p2p_cnet_owner_t *owner);
size_t p2p_cnet_owner_connection_count(const p2p_cnet_owner_t *owner);

/*
 * Server SG cross-Owner admission (transport-level phase; NativeIO SG host
 * observation integration remains a separate host contract).
 * Explicit Owner indices are stable. Every target must be a distinct live
 * owner with its own CNet client, real P2P accept/cookie admission callback
 * bound by p2p_cnet_owner_listen(), and single-threaded Owner polling.
 *
 * Only EXPLICIT, ROUND_ROBIN and LOWEST_PRESSURE are supported before Noise.
 * STRICT_KEY is deliberately rejected here: an unauthenticated inbound TCP
 * peer does not yet have a trusted application key. No silent placement
 * fallback, Actor, extra backend, or cross-Owner protocol callback.
 *
 * Create after listener callback binding and before polling. The SG borrows
 * all owners until sg_destroy succeeds. Each final Owner inbox holds a real
 * CNet handoff credit from producer reserve until final CNet terminal AND
 * application callback retirement (or complete client stop). An SG cannot be
 * destroyed while its producer/final owners still run or credits remain.
 * Seal before stopping the acceptor. Stop ALL owners, destroy SG, then destroy
 * the owners; a timeout retains every borrowed object for retry.
 */
#define P2P_CNET_SG_VERSION 1u
#define P2P_CNET_SG_MAX_OWNERS 4u
typedef struct p2p_cnet_sg_s p2p_cnet_sg_t;

typedef struct {
    size_t size;
    uint32_t version;
    p2p_cnet_owner_t *acceptor;
    p2p_cnet_owner_t *final_owners[P2P_CNET_SG_MAX_OWNERS];
    size_t final_owner_count;
    cnet_owner_placement_kind placement;
    size_t explicit_owner;
    size_t queue_capacity;
    size_t connection_capacity;
} p2p_cnet_sg_config_v1_t;

typedef struct {
    size_t size;
    uint32_t version;
    uint64_t routed;
    uint64_t denied;
    cnet_handoff_snapshot handoff;
    uint8_t sealed;
} p2p_cnet_sg_snapshot_v1_t;

int p2p_cnet_sg_create_v1(const p2p_cnet_sg_config_v1_t *config,
                           p2p_cnet_sg_t **output);
int p2p_cnet_sg_seal_v1(p2p_cnet_sg_t *sg);
int p2p_cnet_sg_snapshot_v1(p2p_cnet_sg_t *sg, size_t final_owner_index,
                             p2p_cnet_sg_snapshot_v1_t *output);
int p2p_cnet_sg_destroy_v1(p2p_cnet_sg_t *sg);

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

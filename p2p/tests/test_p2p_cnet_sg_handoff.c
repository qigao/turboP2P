#include "p2p_cnet_node_fixture.h"

#include <cnet/handoff.h>
#include <cnet/owner_placement.h>

/* Real TCP listener + two distinct final P2P CNet Owners. The test never
 * invokes a copied policy output as a proxy for a real adopt/Noise callback. */
static int accidental_accept(p2p_cnet_owner_t *owner,
                              p2p_connection_t *connection,
                              const cnet_stream_peer *peer, void *context) {
    (void)owner; (void)connection; (void)peer; (void)context;
    check_true(0); /* A remote Owner MUST receive the accepted stream. */
    return P2P_ERR_INVALID_STATE;
}

static p2p_cnet_owner_t *open_acceptor(cnet_stream_peer *address) {
    p2p_cnet_owner_t *acceptor = NULL;
    p2p_cnet_config_t policy = config(1024u);
    check_equal(P2P_OK, p2p_cnet_owner_create(&policy, &acceptor));
    check_not_null(acceptor);
    check_equal(P2P_OK, p2p_cnet_owner_listen(
        acceptor, "127.0.0.1", 0u, 8u, accidental_accept, NULL, address));
    check_true(address->port > 0u);
    return acceptor;
}

static void finish_node(endpoint_t *endpoint) {
    check_equal(P2P_OK, p2p_node_cnet_destroy(endpoint->owner));
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(endpoint->node));
    check_true(endpoint->node->network_ops == NULL);
    check_true(endpoint->node->peers_table == NULL);
    check_equal(0, endpoint->node->peer_count);
    check_equal((size_t)0u, endpoint->node->reserved_send_capacity_bytes);
    check_equal(P2P_OK, p2p_node_state_destroy(endpoint->node));
}

static p2p_cnet_sg_config_v1_t policy(
    p2p_cnet_owner_t *acceptor, p2p_cnet_owner_t *first,
    p2p_cnet_owner_t *second, cnet_owner_placement_kind kind) {
    p2p_cnet_sg_config_v1_t cfg = {0};
    cfg.size = sizeof(cfg);
    cfg.version = P2P_CNET_SG_VERSION;
    cfg.acceptor = acceptor;
    cfg.final_owners[0] = first;
    cfg.final_owners[1] = second;
    cfg.final_owner_count = 2u;
    cfg.placement = kind;
    cfg.queue_capacity = 2u;
    cfg.connection_capacity = 4u;
    return cfg;
}

static p2p_cnet_sg_snapshot_v1_t snapshot(p2p_cnet_sg_t *sg, size_t index) {
    p2p_cnet_sg_snapshot_v1_t value = {0};
    check_equal(P2P_OK, p2p_cnet_sg_snapshot_v1(sg, index, &value));
    check_equal(P2P_CNET_SG_VERSION, value.version);
    check_equal(sizeof(value), value.size);
    return value;
}

static void pump_four(endpoint_t *a, endpoint_t *b, endpoint_t *c, endpoint_t *d,
                       p2p_cnet_owner_t *acceptor) {
    check_equal(P2P_OK, p2p_poll(a->node));
    check_equal(P2P_OK, p2p_poll(b->node));
    check_equal(P2P_OK, p2p_cnet_owner_poll(acceptor));
    check_equal(P2P_OK, p2p_poll(c->node));
    check_equal(P2P_OK, p2p_poll(d->node));
    cmeta_sleep_ms(1u);
}

static void test_two_final_owners_real_cookie_noise_and_data(
    cnet_owner_placement_kind kind) {
    endpoint_t client_a = {0}, client_b = {0}, server_a = {0}, server_b = {0};
    cnet_stream_peer addr = {0};
    p2p_cnet_sg_t *sg = NULL;

    client_a.remote = &server_a;
    server_a.remote = &client_a;
    client_b.remote = &server_b;
    server_b.remote = &client_b;
    init_endpoint(&client_a, 17, 7, 0);
    init_endpoint(&client_b, 19, 7, 0);
    init_endpoint(&server_a, 33, 7, 0);
    init_endpoint(&server_b, 39, 7, 0);
    p2p_cnet_owner_t *acceptor = open_acceptor(&addr);
    p2p_cnet_sg_config_v1_t cfg = policy(
        acceptor, p2p_node_cnet_transport_owner(server_a.owner),
        p2p_node_cnet_transport_owner(server_b.owner),
        kind);

    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&cfg, &sg));
    check_not_null(sg);
    check_equal(P2P_ERR_INVALID_STATE, p2p_cnet_owner_destroy(acceptor));
    check_equal(P2P_ERR_INVALID_STATE, p2p_cnet_sg_destroy_v1(sg));

    check_equal(P2P_OK, p2p_connect(client_a.node, "127.0.0.1", (int)addr.port));
    uint64_t deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!client_a.authenticated || !server_a.authenticated) &&
           cmeta_monotonic_ms() < deadline)
        pump_four(&client_a, &client_b, &server_a, &server_b, acceptor);
    check_equal(1, client_a.authenticated);
    check_equal(1, server_a.authenticated);
    check_equal(0, server_b.authenticated);
    p2p_cnet_sg_snapshot_v1_t first = snapshot(sg, 0u);
    check_equal((uint64_t)1u, first.routed);
    check_equal((size_t)1u, first.handoff.taken);
    check_equal((size_t)0u, first.handoff.queued);

    check_equal(P2P_OK, p2p_connect(client_b.node, "127.0.0.1", (int)addr.port));
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!client_b.authenticated || !server_b.authenticated) &&
           cmeta_monotonic_ms() < deadline)
        pump_four(&client_a, &client_b, &server_a, &server_b, acceptor);
    check_equal(1, client_b.authenticated);
    check_equal(1, server_b.authenticated);
    check_equal(1, server_a.authenticated);
    check_equal(1, client_a.authenticated);
    first = snapshot(sg, 0u);
    p2p_cnet_sg_snapshot_v1_t second = snapshot(sg, 1u);
    check_equal((uint64_t)2u, second.routed);
    check_equal((uint64_t)0u, second.denied);
    check_equal((size_t)1u, first.handoff.taken);
    check_equal((size_t)1u, second.handoff.taken);
    check_equal((size_t)0u, second.handoff.queued);

    check_equal(P2P_OK, p2p_send_message(
        client_a.node, client_a.peer, P2P_MSG_CUSTOM, "owner-a", 8u));
    check_equal(P2P_OK, p2p_send_message(
        client_b.node, client_b.peer, P2P_MSG_CUSTOM, "owner-b", 8u));
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!server_a.messages || !server_b.messages) &&
           cmeta_monotonic_ms() < deadline)
        pump_four(&client_a, &client_b, &server_a, &server_b, acceptor);
    check_equal(1, server_a.messages);
    check_equal(1, server_b.messages);
    check_equal(server_a.received, "owner-a", 8u);
    check_equal(server_b.received, "owner-b", 8u);

    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(sg));
    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(sg));
    check_equal(P2P_ERR_INVALID_STATE, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_stop(acceptor));
    check_equal(P2P_OK, p2p_node_cnet_stop(server_a.owner));
    check_equal(P2P_OK, p2p_node_cnet_stop(server_b.owner));
    first = snapshot(sg, 0u);
    second = snapshot(sg, 1u);
    check_true(first.handoff.drained);
    check_true(second.handoff.drained);
    check_equal((size_t)0u, first.handoff.taken);
    check_equal((size_t)0u, second.handoff.taken);
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(acceptor));
    finish_node(&client_a);
    finish_node(&client_b);
    finish_node(&server_a);
    finish_node(&server_b);
}

static void test_unauthenticated_strict_key_and_owner_alias_rejected(void) {
    endpoint_t server_a = {0}, server_b = {0};
    init_endpoint(&server_a, 33, 7, 0);
    init_endpoint(&server_b, 39, 7, 0);
    cnet_stream_peer addr = {0};
    p2p_cnet_owner_t *acceptor = open_acceptor(&addr);
    p2p_cnet_sg_t *sg = NULL;
    p2p_cnet_owner_t *owner_a = p2p_node_cnet_transport_owner(server_a.owner);
    p2p_cnet_owner_t *owner_b = p2p_node_cnet_transport_owner(server_b.owner);
    p2p_cnet_sg_config_v1_t cfg = policy(acceptor, owner_a, owner_b,
                                          CNET_OWNER_PLACE_STRICT_KEY);
    check_equal(P2P_ERR_INVALID_ARG, p2p_cnet_sg_create_v1(&cfg, &sg));
    check_null(sg);
    cfg.placement = CNET_OWNER_PLACE_ROUND_ROBIN;
    cfg.final_owners[1] = owner_a;
    check_equal(P2P_ERR_INVALID_ARG, p2p_cnet_sg_create_v1(&cfg, &sg));
    check_null(sg);
    cfg.final_owners[1] = owner_b;
    cfg.queue_capacity = cfg.connection_capacity + 1u;
    check_equal(P2P_ERR_INVALID_ARG, p2p_cnet_sg_create_v1(&cfg, &sg));
    check_null(sg);
    cfg.queue_capacity = 2u;
    cfg.placement = CNET_OWNER_PLACE_EXPLICIT;
    cfg.explicit_owner = 2u;
    check_equal(P2P_ERR_INVALID_ARG, p2p_cnet_sg_create_v1(&cfg, &sg));
    check_null(sg);
    cfg.explicit_owner = 1u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&cfg, &sg));
    check_equal(P2P_ERR_INVALID_STATE, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_stop(acceptor));
    check_equal(P2P_OK, p2p_node_cnet_stop(server_a.owner));
    check_equal(P2P_OK, p2p_node_cnet_stop(server_b.owner));
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(acceptor));
    finish_node(&server_a);
    finish_node(&server_b);
}

static void test_credited_queue_full_does_not_reroute_pinned_owner(void) {
    endpoint_t server = {0}, client_a = {0}, client_b = {0};
    server.remote = &client_a;
    client_a.remote = &server;
    client_b.remote = &server;
    init_endpoint(&client_a, 17, 7, 0);
    init_endpoint(&client_b, 19, 7, 0);
    init_endpoint(&server, 33, 7, 0);
    cnet_stream_peer addr = {0};
    p2p_cnet_owner_t *acceptor = open_acceptor(&addr);
    p2p_cnet_sg_t *sg = NULL;
    p2p_cnet_sg_config_v1_t cfg = {0};
    cfg.size = sizeof(cfg);
    cfg.version = P2P_CNET_SG_VERSION;
    cfg.acceptor = acceptor;
    cfg.final_owners[0] = p2p_node_cnet_transport_owner(server.owner);
    cfg.final_owner_count = 1u;
    cfg.placement = CNET_OWNER_PLACE_EXPLICIT;
    cfg.queue_capacity = 1u;
    cfg.connection_capacity = 1u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&cfg, &sg));

    check_equal(P2P_OK, p2p_connect(client_a.node, "127.0.0.1", (int)addr.port));
    check_equal(P2P_OK, p2p_connect(client_b.node, "127.0.0.1", (int)addr.port));
    uint64_t deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (snapshot(sg, 0u).routed + snapshot(sg, 0u).denied < 2u &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(client_a.node));
        check_equal(P2P_OK, p2p_poll(client_b.node));
        check_equal(P2P_OK, p2p_cnet_owner_poll(acceptor));
        cmeta_sleep_ms(1u);
    }
    p2p_cnet_sg_snapshot_v1_t state = snapshot(sg, 0u);
    check_equal((uint64_t)1u, state.routed);
    check_equal((uint64_t)1u, state.denied);
    check_equal((size_t)1u, state.handoff.queued);
    check_equal((size_t)0u, state.handoff.taken);
    /* Owner stop closes every still-queued socket and returns every TAKEN
     * credit, even without first invoking protocol/Noise callbacks. */
    check_equal(P2P_OK, p2p_cnet_owner_stop(acceptor));
    check_equal(P2P_OK, p2p_node_cnet_stop(server.owner));
    state = snapshot(sg, 0u);
    check_true(state.handoff.drained);
    check_equal((size_t)0u, state.handoff.queued);
    check_equal((size_t)0u, state.handoff.taken);
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(acceptor));
    finish_node(&server);
    finish_node(&client_a);
    finish_node(&client_b);
}



/* Same upstream CNet Handoff credits are reserved for a second
 * independently managed Cohost CNet client and for real detached TCP
 * streams. FULL at one physical quota refuses P2P admission without
 * migrating/pinning another Owner or bypassing Noise. */
static void test_cohost_credit_strictly_blocks_real_p2p_admission(void) {
    endpoint_t server = {0}, rejected_client = {0}, admitted_client = {0};
    server.remote = &admitted_client;
    rejected_client.remote = &server;
    admitted_client.remote = &server;
    init_endpoint(&rejected_client, 17, 7u, 0);
    init_endpoint(&admitted_client, 19, 7u, 0);
    init_endpoint(&server, 33, 7u, 0);
    cnet_stream_peer listener = {0};
    p2p_cnet_owner_t *acceptor = open_acceptor(&listener);
    p2p_cnet_sg_t *sg = NULL;
    p2p_cnet_sg_config_v1_t config = {0};
    config.size = sizeof(config);
    config.version = P2P_CNET_SG_VERSION;
    config.acceptor = acceptor;
    config.final_owners[0] = p2p_node_cnet_transport_owner(server.owner);
    config.final_owner_count = 1u;
    config.placement = CNET_OWNER_PLACE_EXPLICIT;
    config.queue_capacity = 1u;
    config.connection_capacity = 1u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&config, &sg));

    cnet_handoff_ticket extra = {0}, another = {0};
    check_equal(P2P_OK, p2p_cnet_sg_cohost_credit_reserve_v1(
        sg, 0u, &extra));
    check_true(extra.slot != 0u && extra.generation != 0u);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED,
                p2p_cnet_sg_cohost_credit_reserve_v1(sg, 0u, &another));
    check_equal((size_t)0u, another.slot);
    p2p_cnet_sg_snapshot_v1_t state = snapshot(sg, 0u);
    check_equal((size_t)1u, state.handoff.reserved);
    check_equal((size_t)0u, state.handoff.queued);

    check_equal(P2P_OK, p2p_connect(rejected_client.node,
        "127.0.0.1", (int)listener.port));
    uint64_t deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (snapshot(sg, 0u).denied == 0u &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(rejected_client.node));
        check_equal(P2P_OK, p2p_cnet_owner_poll(acceptor));
        cmeta_sleep_ms(1u);
    }
    state = snapshot(sg, 0u);
    check_equal((uint64_t)1u, state.denied);
    check_equal((uint64_t)0u, state.routed);
    check_equal((size_t)1u, state.handoff.reserved);

    /* Stale generation and duplicate settlement cannot return a live slot. */
    cnet_handoff_ticket stale = extra;
    ++stale.generation;
    check_equal(P2P_ERR_INVALID_STATE,
                p2p_cnet_sg_cohost_credit_release_v1(sg, 0u, stale));
    check_equal(P2P_OK,
                p2p_cnet_sg_cohost_credit_release_v1(sg, 0u, extra));
    check_equal(P2P_ERR_INVALID_STATE,
                p2p_cnet_sg_cohost_credit_release_v1(sg, 0u, extra));
    check_equal((size_t)0u, snapshot(sg, 0u).handoff.reserved);

    /* Once the independent client has returned its physical credit, the
     * next real P2P TCP stream can be handed to its original final Owner
     * and authenticated through cookie/Noise exactly as before. */
    check_equal(P2P_OK, p2p_connect(admitted_client.node,
        "127.0.0.1", (int)listener.port));
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!admitted_client.authenticated || !server.authenticated) &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(admitted_client.node));
        check_equal(P2P_OK, p2p_poll(server.node));
        check_equal(P2P_OK, p2p_cnet_owner_poll(acceptor));
        cmeta_sleep_ms(1u);
    }
    check_equal(1, admitted_client.authenticated);
    check_equal(1, server.authenticated);
    state = snapshot(sg, 0u);
    check_equal((uint64_t)1u, state.routed);
    check_equal((size_t)1u, state.handoff.taken);
    check_equal((size_t)0u, state.handoff.reserved);

    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_stop(acceptor));
    check_equal(P2P_OK, p2p_node_cnet_stop(server.owner));
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(acceptor));
    finish_node(&rejected_client);
    finish_node(&admitted_client);
    finish_node(&server);
}

static void test_cohost_credit_must_drain_before_sg_destroy(void) {
    endpoint_t server = {0};
    init_endpoint(&server, 33, 7u, 0);
    cnet_stream_peer listener = {0};
    p2p_cnet_owner_t *acceptor = open_acceptor(&listener);
    p2p_cnet_sg_t *sg = NULL;
    p2p_cnet_sg_config_v1_t config = {0};
    config.size = sizeof(config);
    config.version = P2P_CNET_SG_VERSION;
    config.acceptor = acceptor;
    config.final_owners[0] = p2p_node_cnet_transport_owner(server.owner);
    config.final_owner_count = 1u;
    config.placement = CNET_OWNER_PLACE_EXPLICIT;
    config.queue_capacity = 1u;
    config.connection_capacity = 1u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&config, &sg));

    cnet_handoff_ticket extra = {0}, declined = {0};
    check_equal(P2P_OK, p2p_cnet_sg_cohost_credit_reserve_v1(
        sg, 0u, &extra));
    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(sg));
    check_equal(P2P_ERR_INVALID_STATE,
                p2p_cnet_sg_cohost_credit_reserve_v1(sg, 0u, &declined));
    check_equal(P2P_OK, p2p_cnet_owner_stop(acceptor));
    check_equal(P2P_OK, p2p_node_cnet_stop(server.owner));
    /* Both owners are stopped, but the host must not free the CNet Handoff
     * while the independent cohost's reserved credit is still borrowed. */
    check_equal(P2P_ERR_INVALID_STATE, p2p_cnet_sg_destroy_v1(sg));
    check_equal((size_t)1u, snapshot(sg, 0u).handoff.reserved);
    check_equal(P2P_OK,
                p2p_cnet_sg_cohost_credit_release_v1(sg, 0u, extra));
    check_equal(P2P_ERR_INVALID_STATE,
                p2p_cnet_sg_cohost_credit_release_v1(sg, 0u, extra));
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(acceptor));
    finish_node(&server);
}


/* A direct same-Owner P2P accept is zero-hop; it must still consume the
 * very SAME CNet Handoff connection credit that an independent SG-hosted
 * CNet connector reserves. No fake publish/take round trip is permitted. */
static void test_same_owner_direct_p2p_uses_strict_cohost_credit(void) {
    endpoint_t server = {0}, denied_client = {0}, authenticated_client = {0};
    server.remote = &authenticated_client;
    denied_client.remote = &server;
    authenticated_client.remote = &server;
    init_endpoint(&denied_client, 17, 7u, 0);
    init_endpoint(&authenticated_client, 19, 7u, 0);
    init_endpoint(&server, 33, 7u, 0);
    p2p_cnet_owner_t *local_owner = p2p_node_cnet_transport_owner(server.owner);
    p2p_cnet_sg_t *sg = NULL;
    p2p_cnet_sg_config_v1_t config = {0};
    config.size = sizeof(config);
    config.version = P2P_CNET_SG_VERSION;
    config.acceptor = local_owner;
    config.final_owners[0] = local_owner; /* same actual CNet Owner */
    config.final_owner_count = 1u;
    config.placement = CNET_OWNER_PLACE_EXPLICIT;
    config.queue_capacity = 1u;
    config.connection_capacity = 1u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&config, &sg));

    cnet_handoff_ticket extra_credit = {0};
    check_equal(P2P_OK, p2p_cnet_sg_cohost_credit_reserve_v1(
        sg, 0u, &extra_credit));
    check_equal((size_t)1u, snapshot(sg, 0u).handoff.reserved);
    check_equal(P2P_OK, p2p_connect(denied_client.node,
        server.node->ip, server.node->port));
    uint64_t deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (snapshot(sg, 0u).denied == 0u &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(denied_client.node));
        check_equal(P2P_OK, p2p_poll(server.node));
        cmeta_sleep_ms(1u);
    }
    p2p_cnet_sg_snapshot_v1_t state = snapshot(sg, 0u);
    check_equal((uint64_t)1u, state.denied);
    check_equal((uint64_t)0u, state.routed);
    check_equal((size_t)1u, state.handoff.reserved);

    check_equal(P2P_OK, p2p_cnet_sg_cohost_credit_release_v1(
        sg, 0u, extra_credit));
    check_equal(P2P_OK, p2p_connect(authenticated_client.node,
        server.node->ip, server.node->port));
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!server.authenticated || !authenticated_client.authenticated) &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(authenticated_client.node));
        check_equal(P2P_OK, p2p_poll(server.node));
        cmeta_sleep_ms(1u);
    }
    check_equal(1, server.authenticated);
    check_equal(1, authenticated_client.authenticated);
    state = snapshot(sg, 0u);
    check_equal((uint64_t)1u, state.routed);
    check_equal((size_t)1u, state.handoff.reserved);
    check_equal((size_t)0u, state.handoff.taken);
    check_equal((size_t)0u, state.handoff.queued);

    /* A CLOSED CNet connection, not a mere close request, releases the
     * same-Owner RESERVED token after its callback storage is quiescent. */
    p2p_peer_disconnect(authenticated_client.peer);
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (snapshot(sg, 0u).handoff.reserved != 0u &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(authenticated_client.node));
        check_equal(P2P_OK, p2p_poll(server.node));
        cmeta_sleep_ms(1u);
    }
    state = snapshot(sg, 0u);
    check_equal((size_t)0u, state.handoff.reserved);
    check_equal((size_t)0u, state.handoff.taken);

    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(sg));
    check_equal(P2P_OK, p2p_node_cnet_stop(server.owner));
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    finish_node(&denied_client);
    finish_node(&authenticated_client);
    finish_node(&server);
}


/* Real two-final-Owner contention: an independent CNet Cohost has reserved
 * the only Handoff credit on Owner 0. Both canonical RR and LOWEST_PRESSURE
 * must place the first new P2P TCP stream on Owner 1 (not replay/reroute
 * after reserve failure). When both Owners are full, deny; after exact credit
 * return, permit an authenticated Noise session on Owner 0. */
static void test_contended_two_final_owners_real_noise(
    cnet_owner_placement_kind kind) {
    endpoint_t clients[2] = {{0}}, servers[2] = {{0}};
    endpoint_t denied_client = {0};
    for (size_t i = 0u; i < 2u; ++i) {
        clients[i].remote = &servers[i];
        servers[i].remote = &clients[i];
        init_endpoint(&clients[i], 17 + (int)i * 2, 7u, 0);
        init_endpoint(&servers[i], 33 + (int)i * 6, 7u, 0);
    }
    denied_client.remote = &servers[0];
    init_endpoint(&denied_client, 23, 7u, 0);
    cnet_stream_peer listener = {0};
    p2p_cnet_owner_t *acceptor = open_acceptor(&listener);
    p2p_cnet_sg_t *sg = NULL;
    p2p_cnet_sg_config_v1_t cfg = policy(
        acceptor, p2p_node_cnet_transport_owner(servers[0].owner),
        p2p_node_cnet_transport_owner(servers[1].owner), kind);
    cfg.connection_capacity = 1u;
    cfg.queue_capacity = 1u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&cfg, &sg));
    cnet_handoff_ticket reserved = {0};
    check_equal(P2P_OK, p2p_cnet_sg_cohost_credit_reserve_v1(
        sg, 0u, &reserved));
    check_equal((size_t)1u, snapshot(sg, 0u).handoff.reserved);
    /* Neither final Owner is permitted to release another inbox's ticket. */
    check_equal(P2P_ERR_INVALID_STATE,
        p2p_cnet_sg_cohost_credit_release_v1(sg, 1u, reserved));
    check_equal((size_t)1u, snapshot(sg, 0u).handoff.reserved);

    check_equal(P2P_OK, p2p_connect(clients[1].node,
        "127.0.0.1", (int)listener.port));
    uint64_t deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!clients[1].authenticated || !servers[1].authenticated) &&
           cmeta_monotonic_ms() < deadline)
        pump_four(&clients[0], &clients[1],
                  &servers[0], &servers[1], acceptor);
    check_equal(1, clients[1].authenticated);
    check_equal(1, servers[1].authenticated);
    check_equal(0, servers[0].authenticated);
    check_equal((uint64_t)1u, snapshot(sg, 0u).routed);
    check_equal((size_t)1u, snapshot(sg, 0u).handoff.reserved);
    check_equal((size_t)1u, snapshot(sg, 1u).handoff.taken);
    cnet_handoff_ticket additional = {0};
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED,
        p2p_cnet_sg_cohost_credit_reserve_v1(sg, 1u, &additional));
    check_equal((size_t)0u, additional.slot);

    /* No eligible final Owner; denial is a decision at accept, not a new
     * handshake, a cross-shard stream migration or an alternative pool. */
    check_equal(P2P_OK, p2p_connect(denied_client.node,
        "127.0.0.1", (int)listener.port));
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (snapshot(sg, 0u).denied == 0u &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(denied_client.node));
        pump_four(&clients[0], &clients[1],
                  &servers[0], &servers[1], acceptor);
    }
    check_equal((uint64_t)1u, snapshot(sg, 0u).denied);
    check_equal((uint64_t)1u, snapshot(sg, 0u).routed);
    check_equal(0, denied_client.authenticated);
    check_equal(0, servers[0].authenticated);

    /* Cohost completion releases its original credit, making Owner 0
     * eligible again. Existing authenticated Owner 1 never migrates. */
    check_equal(P2P_OK,
        p2p_cnet_sg_cohost_credit_release_v1(sg, 0u, reserved));
    check_equal((size_t)0u, snapshot(sg, 0u).handoff.reserved);
    check_equal(P2P_OK, p2p_connect(clients[0].node,
        "127.0.0.1", (int)listener.port));
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!clients[0].authenticated || !servers[0].authenticated) &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(denied_client.node));
        pump_four(&clients[0], &clients[1],
                  &servers[0], &servers[1], acceptor);
    }
    for (size_t i = 0u; i < 2u; ++i) {
        check_equal(1, clients[i].authenticated);
        check_equal(1, servers[i].authenticated);
        check_equal((size_t)1u, snapshot(sg, i).handoff.taken);
        check_equal((size_t)0u, snapshot(sg, i).handoff.reserved);
    }
    check_equal((uint64_t)2u, snapshot(sg, 0u).routed);
    check_equal((uint64_t)1u, snapshot(sg, 0u).denied);
    for (size_t i = 0u; i < 2u; ++i) {
        const char payload[8] = {
            'o', 'w', 'n', 'e', 'r', '-', (char)('0' + i), '\0'
        };
        check_equal(P2P_OK, p2p_send_message(
            clients[i].node, clients[i].peer,
            P2P_MSG_CUSTOM, payload, sizeof(payload)));
    }
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!servers[0].messages || !servers[1].messages) &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(denied_client.node));
        pump_four(&clients[0], &clients[1],
                  &servers[0], &servers[1], acceptor);
    }
    for (size_t i = 0u; i < 2u; ++i) {
        const char payload[8] = {
            'o', 'w', 'n', 'e', 'r', '-', (char)('0' + i), '\0'
        };
        check_equal(1, servers[i].messages);
        check_equal(payload, servers[i].received, sizeof(payload));
    }

    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_stop(acceptor));
    for (size_t i = 0u; i < 2u; ++i) {
        check_equal(P2P_OK, p2p_node_cnet_stop(servers[i].owner));
        check_true(snapshot(sg, i).handoff.drained);
    }
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(acceptor));
    for (size_t i = 0u; i < 2u; ++i) {
        finish_node(&clients[i]);
        finish_node(&servers[i]);
    }
    finish_node(&denied_client);
}

/* LOWEST_PRESSURE must use actual credited pressure, not merely eligibility
 * or a guessed modulo of the number of configured Owner shards. Owner 0
 * still has available headroom (1 of 2 slots RESERVED) but Owner 1 is
 * genuinely idle, so only Owner 1 should receive the new Noise session. */
static void test_lowest_pressure_avoids_nonfull_reserved_owner(void) {
    endpoint_t clients[2] = {{0}}, servers[2] = {{0}};
    for (size_t i = 0u; i < 2u; ++i) {
        clients[i].remote = &servers[i];
        servers[i].remote = &clients[i];
        init_endpoint(&clients[i], 17 + (int)i * 2, 7u, 0);
        init_endpoint(&servers[i], 33 + (int)i * 6, 7u, 0);
    }
    cnet_stream_peer listener = {0};
    p2p_cnet_owner_t *acceptor = open_acceptor(&listener);
    p2p_cnet_sg_t *sg = NULL;
    p2p_cnet_sg_config_v1_t cfg = policy(
        acceptor, p2p_node_cnet_transport_owner(servers[0].owner),
        p2p_node_cnet_transport_owner(servers[1].owner),
        CNET_OWNER_PLACE_LOWEST_PRESSURE);
    cfg.connection_capacity = 2u;
    cfg.queue_capacity = 2u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&cfg, &sg));
    cnet_handoff_ticket reserved = {0};
    check_equal(P2P_OK,
        p2p_cnet_sg_cohost_credit_reserve_v1(sg, 0u, &reserved));
    check_equal((size_t)1u, snapshot(sg, 0u).handoff.reserved);
    check_equal((size_t)0u, snapshot(sg, 1u).handoff.reserved);
    check_equal(P2P_OK, p2p_connect(clients[1].node,
        "127.0.0.1", (int)listener.port));
    const uint64_t deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!clients[1].authenticated || !servers[1].authenticated) &&
           cmeta_monotonic_ms() < deadline)
        pump_four(&clients[0], &clients[1],
                  &servers[0], &servers[1], acceptor);
    check_equal(1, clients[1].authenticated);
    check_equal(1, servers[1].authenticated);
    check_equal(0, servers[0].authenticated);
    check_equal((size_t)1u, snapshot(sg, 0u).handoff.reserved);
    check_equal((size_t)1u, snapshot(sg, 1u).handoff.taken);
    check_equal((uint64_t)1u, snapshot(sg, 0u).routed);
    check_equal(P2P_OK,
        p2p_cnet_sg_cohost_credit_release_v1(sg, 0u, reserved));
    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_stop(acceptor));
    for (size_t i = 0u; i < 2u; ++i) {
        check_equal(P2P_OK, p2p_node_cnet_stop(servers[i].owner));
        check_true(snapshot(sg, i).handoff.drained);
    }
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(acceptor));
    for (size_t i = 0u; i < 2u; ++i) {
        finish_node(&clients[i]);
        finish_node(&servers[i]);
    }
}

/* EXPLICIT is a strict, identity-less pre-Noise Owner pin, not RR with a
 * hidden fallback. Even with an entirely available second final Owner,
 * a Cohost reservation saturating Owner 0 must deny the inbound stream. */
static void test_explicit_pinned_final_owner_refuses_neighbor_fallback(void) {
    endpoint_t blocked = {0}, admitted = {0}, server_a = {0}, server_b = {0};
    admitted.remote = &server_a;
    server_a.remote = &admitted;
    blocked.remote = &server_a;
    init_endpoint(&blocked, 23, 7u, 0);
    init_endpoint(&admitted, 17, 7u, 0);
    init_endpoint(&server_a, 33, 7u, 0);
    init_endpoint(&server_b, 39, 7u, 0);
    cnet_stream_peer listener = {0};
    p2p_cnet_owner_t *acceptor = open_acceptor(&listener);
    p2p_cnet_sg_t *sg = NULL;
    p2p_cnet_sg_config_v1_t cfg = policy(
        acceptor, p2p_node_cnet_transport_owner(server_a.owner),
        p2p_node_cnet_transport_owner(server_b.owner),
        CNET_OWNER_PLACE_EXPLICIT);
    cfg.explicit_owner = 0u;
    cfg.connection_capacity = 1u;
    cfg.queue_capacity = 1u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&cfg, &sg));
    cnet_handoff_ticket reserved = {0};
    check_equal(P2P_OK,
        p2p_cnet_sg_cohost_credit_reserve_v1(sg, 0u, &reserved));
    check_equal(P2P_OK, p2p_connect(blocked.node,
        "127.0.0.1", (int)listener.port));
    uint64_t deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (snapshot(sg, 0u).denied == 0u &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(blocked.node));
        check_equal(P2P_OK, p2p_poll(admitted.node));
        check_equal(P2P_OK, p2p_poll(server_a.node));
        check_equal(P2P_OK, p2p_poll(server_b.node));
        check_equal(P2P_OK, p2p_cnet_owner_poll(acceptor));
        cmeta_sleep_ms(1u);
    }
    check_equal((uint64_t)1u, snapshot(sg, 0u).denied);
    check_equal((uint64_t)0u, snapshot(sg, 0u).routed);
    check_equal((size_t)1u, snapshot(sg, 0u).handoff.reserved);
    check_equal((size_t)0u, snapshot(sg, 1u).handoff.taken);
    check_equal(0, server_b.authenticated);
    check_equal(P2P_OK,
        p2p_cnet_sg_cohost_credit_release_v1(sg, 0u, reserved));
    check_equal(P2P_OK, p2p_connect(admitted.node,
        "127.0.0.1", (int)listener.port));
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!admitted.authenticated || !server_a.authenticated) &&
           cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(blocked.node));
        check_equal(P2P_OK, p2p_poll(admitted.node));
        check_equal(P2P_OK, p2p_poll(server_a.node));
        check_equal(P2P_OK, p2p_poll(server_b.node));
        check_equal(P2P_OK, p2p_cnet_owner_poll(acceptor));
        cmeta_sleep_ms(1u);
    }
    check_equal(1, admitted.authenticated);
    check_equal(1, server_a.authenticated);
    check_equal(0, server_b.authenticated);
    check_equal((uint64_t)1u, snapshot(sg, 0u).routed);
    check_equal((uint64_t)1u, snapshot(sg, 0u).denied);
    check_equal((size_t)1u, snapshot(sg, 0u).handoff.taken);
    check_equal((size_t)0u, snapshot(sg, 1u).handoff.taken);
    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_stop(acceptor));
    check_equal(P2P_OK, p2p_node_cnet_stop(server_a.owner));
    check_equal(P2P_OK, p2p_node_cnet_stop(server_b.owner));
    check_true(snapshot(sg, 0u).handoff.drained);
    check_true(snapshot(sg, 1u).handoff.drained);
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(acceptor));
    finish_node(&blocked);
    finish_node(&admitted);
    finish_node(&server_a);
    finish_node(&server_b);
}

static void pump_four_final_owners(
    endpoint_t clients[4], endpoint_t servers[4],
    p2p_cnet_owner_t *acceptor) {
    for (size_t i = 0u; i < 4u; ++i)
        check_equal(P2P_OK, p2p_poll(clients[i].node));
    check_equal(P2P_OK, p2p_cnet_owner_poll(acceptor));
    for (size_t i = 0u; i < 4u; ++i)
        check_equal(P2P_OK, p2p_poll(servers[i].node));
    cmeta_sleep_ms(1u);
}

/* An explicit 4-owner graph is required in addition to the 2-owner real
 * test: stable RR index chooses one independent final CNet backend each time.
 * No Actor worker or fake CNet completion provider participates. */
static void test_four_distinct_final_owners_cookie_noise_and_data(void) {
    endpoint_t clients[4] = {{0}}, servers[4] = {{0}};
    cnet_stream_peer listener = {0};
    p2p_cnet_sg_t *sg = NULL;
    for (size_t i = 0u; i < 4u; ++i) {
        clients[i].remote = &servers[i];
        servers[i].remote = &clients[i];
        init_endpoint(&clients[i], 17 + (int)i * 2, 7, 0);
        init_endpoint(&servers[i], 41 + (int)i * 2, 7, 0);
    }
    p2p_cnet_owner_t *acceptor = open_acceptor(&listener);
    p2p_cnet_sg_config_v1_t cfg = policy(
        acceptor, p2p_node_cnet_transport_owner(servers[0].owner),
        p2p_node_cnet_transport_owner(servers[1].owner),
        CNET_OWNER_PLACE_ROUND_ROBIN);
    cfg.final_owner_count = 4u;
    cfg.final_owners[2] = p2p_node_cnet_transport_owner(servers[2].owner);
    cfg.final_owners[3] = p2p_node_cnet_transport_owner(servers[3].owner);
    cfg.queue_capacity = 4u;
    cfg.connection_capacity = 4u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&cfg, &sg));

    /* Stage each authenticated connection, ensuring the expected signed
     * identity stays with its single final Owner without depending on OS
     * accept ordering among unrelated sockets. */
    for (size_t i = 0u; i < 4u; ++i) {
        check_equal(P2P_OK, p2p_connect(clients[i].node,
            "127.0.0.1", (int)listener.port));
        uint64_t deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
        while ((!clients[i].authenticated || !servers[i].authenticated) &&
               cmeta_monotonic_ms() < deadline)
            pump_four_final_owners(clients, servers, acceptor);
        check_equal(1, clients[i].authenticated);
        check_equal(1, servers[i].authenticated);
        p2p_cnet_sg_snapshot_v1_t state = snapshot(sg, i);
        check_equal((uint64_t)(i + 1u), state.routed);
        check_equal((uint64_t)0u, state.denied);
        check_equal((size_t)1u, state.handoff.taken);
    }

    for (size_t i = 0u; i < 4u; ++i) {
        char payload[5] = {'s', 'g', '-', (char)('0' + i), '\0'};
        check_equal(P2P_OK, p2p_send_message(clients[i].node, clients[i].peer,
            P2P_MSG_CUSTOM, payload, sizeof(payload)));
    }
    uint64_t deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (cmeta_monotonic_ms() < deadline) {
        int all_done = 1;
        for (size_t i = 0u; i < 4u; ++i)
            if (!servers[i].messages) all_done = 0;
        if (all_done) break;
        pump_four_final_owners(clients, servers, acceptor);
    }
    for (size_t i = 0u; i < 4u; ++i) {
        const char expected[5] = {'s', 'g', '-', (char)('0' + i), '\0'};
        check_equal(1, servers[i].messages);
        check_equal(expected, servers[i].received, sizeof(expected));
    }

    check_equal(P2P_OK, p2p_cnet_owner_stop(acceptor));
    for (size_t i = 0u; i < 4u; ++i) {
        check_equal(P2P_OK, p2p_node_cnet_stop(servers[i].owner));
        p2p_cnet_sg_snapshot_v1_t state = snapshot(sg, i);
        check_true(state.handoff.drained);
        check_equal((size_t)0u, state.handoff.taken);
    }
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sg));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(acceptor));
    for (size_t i = 0u; i < 4u; ++i) {
        finish_node(&clients[i]);
        finish_node(&servers[i]);
    }
}

spec("P2P real SG cross-Owner credited accepted-stream handoff") {
    it("runs real cookie, Noise, identity and data with ROUND_ROBIN") {
        test_two_final_owners_real_cookie_noise_and_data(CNET_OWNER_PLACE_ROUND_ROBIN);
    }
    it("chooses the lower-pressure final Owner with real Noise handoff") {
        /* First admission uses the empty Owner 0. Its TAKEN credit and
         * published live connection then shift LOWEST_PRESSURE to Owner 1.
         * Both still require authenticated cookie/Noise and real TCP DATA. */
        test_two_final_owners_real_cookie_noise_and_data(CNET_OWNER_PLACE_LOWEST_PRESSURE);
    }
    it("runs four distinct final CNet Owners with authenticated FIFO data") {
        test_four_distinct_final_owners_cookie_noise_and_data();
    }
    it("rejects unauthenticated STRICT_KEY and malformed topologies without leaks") {
        test_unauthenticated_strict_key_and_owner_alias_rejected();
    }
    it("denies a full pinned handoff inbox and drains queued TCP on stop") {
        test_credited_queue_full_does_not_reroute_pinned_owner();
    }
    it("shares exact CNet Handoff capacity with a cohosted connector") {
        test_cohost_credit_strictly_blocks_real_p2p_admission();
    }
    it("retains the borrowed SG Handoff until all cohost credits return") {
        test_cohost_credit_must_drain_before_sg_destroy();
    }
    it("keeps same-Owner zero-hop P2P accept under strict shared credits") {
        test_same_owner_direct_p2p_uses_strict_cohost_credit();
    }
    it("skips a saturated cohost Owner under real RR handoff and Noise") {
        test_contended_two_final_owners_real_noise(CNET_OWNER_PLACE_ROUND_ROBIN);
    }
    it("skips a saturated cohost Owner under real LOWEST_PRESSURE and Noise") {
        test_contended_two_final_owners_real_noise(CNET_OWNER_PLACE_LOWEST_PRESSURE);
    }
    it("prefers an idle Owner over an eligible but credited busy Owner") {
        test_lowest_pressure_avoids_nonfull_reserved_owner();
    }
    it("never reroutes a full EXPLICIT pinned Owner to a free neighbor") {
        test_explicit_pinned_final_owner_refuses_neighbor_fallback();
    }
}

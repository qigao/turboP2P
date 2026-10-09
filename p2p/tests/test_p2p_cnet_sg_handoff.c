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

static void test_two_final_owners_real_cookie_noise_and_data(void) {
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
        CNET_OWNER_PLACE_ROUND_ROBIN);

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
    it("runs real cookie, Noise, identity and data on two final P2P Owners") {
        test_two_final_owners_real_cookie_noise_and_data();
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
}

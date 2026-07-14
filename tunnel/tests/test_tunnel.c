/**
 * @file test_tunnel.c
 * @brief Tests for core tunnel packet handling modes
 */

#include <tinytest.h>
#include "../src/core/tunnel_types.h"
#include "../src/nat/tunnel_nat.h"
#include "../src/session/tunnel_session.h"
#include <stdlib.h>

static tunnel_t *mock_tunnel = NULL;

static const uint8_t ipv4_tcp_syn[] = {
    0x45, 0x00, 0x00, 0x28,
    0x1c, 0x46, 0x40, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0x0a, 0x2a, 0x00, 0x02,
    0x0a, 0x2a, 0x00, 0x63,
    0xc0, 0x08, 0x46, 0x98,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x02, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00,
};

void setUp(void)
{
    mock_tunnel = (tunnel_t *)calloc(1, sizeof(tunnel_t));
    mock_tunnel->ctx = coro_context_create(NULL);
    mock_tunnel->nat = tunnel_nat_create(mock_tunnel);
    mock_tunnel->proxy = (tunnel_proxy_t *)calloc(1, sizeof(tunnel_proxy_t));
    mock_tunnel->proxy->tunnel = mock_tunnel;
    mock_tunnel->proxy->type = TUNNEL_PROXY_NONE;
}

void tearDown(void)
{
    if (!mock_tunnel) {
        return;
    }

    if (mock_tunnel->nat) {
        tunnel_nat_destroy(mock_tunnel->nat);
    }
    if (mock_tunnel->ctx) {
        coro_context_destroy(mock_tunnel->ctx);
    }
    free(mock_tunnel->proxy);
    free(mock_tunnel);
    mock_tunnel = NULL;
}

void test_packet_mode_skips_tcp_sessions(void)
{
    mock_tunnel->config.mode = TUNNEL_MODE_PACKET;

    check_int_eq(TUNNEL_OK, tunnel_handle_tun_packet(mock_tunnel, ipv4_tcp_syn,
                                                     sizeof(ipv4_tcp_syn)));
    check_int_eq(0, (int)tunnel_session_count(mock_tunnel));
    check_int_eq(1, (int)mock_tunnel->stats.packets_rx);
}

void test_domain_routes_fail_closed_until_domain_identity_is_available(void)
{
    const char *domains[] = {"example.com"};
    tunnel_route_config_t route = {0};

    route.include_domains = domains;
    route.include_domain_count = 1;

    check_int_eq(TUNNEL_ERR_NOT_SUPPORTED, tunnel_set_routes(mock_tunnel, &route));
    check_null(mock_tunnel->include_rules);
    check_null(mock_tunnel->exclude_rules);
}

spec("tunnel core") {
    before_each() {
        setUp();
    }

    after_each() {
        tearDown();
    }

    describe("packet handling") {
        it("skips tcp sessions in packet mode") {
            test_packet_mode_skips_tcp_sessions();
        }
    }

    describe("route policy") {
        it("rejects domain rules instead of silently bypassing traffic") {
            test_domain_routes_fail_closed_until_domain_identity_is_available();
        }
    }
}

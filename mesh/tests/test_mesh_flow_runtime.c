#include "mesh_flow_runtime.h"
#include "tinytest.h"

#include <string.h>

#define IPV4(a, b, c, d)                                                       \
  (((uint32_t)(a) << 24u) | ((uint32_t)(b) << 16u) |                          \
   ((uint32_t)(c) << 8u) | (uint32_t)(d))

static void make_tcp_packet(uint8_t packet[40], uint16_t dst_port) {
  memset(packet, 0, 40u);
  packet[0] = 0x45u;
  packet[2] = 0u;
  packet[3] = 40u;
  packet[8] = 64u;
  packet[9] = 6u;
  packet[12] = 10u;
  packet[13] = 42u;
  packet[14] = 0u;
  packet[15] = 7u;
  packet[16] = 10u;
  packet[17] = 42u;
  packet[18] = 1u;
  packet[19] = 9u;
  packet[20] = 0x30u;
  packet[21] = 0x39u;
  packet[22] = (uint8_t)(dst_port >> 8u);
  packet[23] = (uint8_t)dst_port;
}

static mesh_flow_rule_v1_t allow_https_rule(void) {
  mesh_flow_rule_v1_t rule;
  memset(&rule, 0, sizeof(rule));
  rule.rule_id = 701u;
  rule.src_network_ip = IPV4(10, 42, 0, 0);
  rule.src_prefix_len = 16u;
  rule.dst_network_ip = IPV4(10, 42, 1, 0);
  rule.dst_prefix_len = 24u;
  rule.dst_port_start = 443u;
  rule.dst_port_end = 443u;
  rule.directions = MESH_FLOW_DIRECTION_OUT;
  rule.ip_proto = 6u;
  rule.action = MESH_FLOW_ACTION_ALLOW;
  return rule;
}

static void test_published_snapshot_controls_packet_decisions(void) {
  mesh_flow_runtime_v1_t runtime;
  mesh_flow_rule_v1_t rule = allow_https_rule();
  mesh_flow_decision_v1_t decision;
  uint8_t packet[40];

  memset(&runtime, 0, sizeof(runtime));
  check_int_eq(mesh_flow_runtime_init_v1(&runtime, 4u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RUNTIME_OK);
  make_tcp_packet(packet, 443u);
  check_int_eq(mesh_flow_runtime_evaluate_ipv4_v1(
                   &runtime, MESH_FLOW_DIRECTION_OUT, packet, sizeof(packet),
                   NULL, &decision),
               MESH_FLOW_RUNTIME_DISABLED);
  check_int_eq(mesh_flow_runtime_publish_v1(
                   &runtime, 41u, 9u, MESH_FLOW_ACTION_DENY, &rule, 1u),
               MESH_FLOW_RUNTIME_OK);
  check_int_eq(mesh_flow_runtime_evaluate_ipv4_v1(
                   &runtime, MESH_FLOW_DIRECTION_OUT, packet, sizeof(packet),
                   NULL, &decision),
               MESH_FLOW_RUNTIME_OK);
  check_int_eq(decision.action, MESH_FLOW_ACTION_ALLOW);
  check_uint_eq(decision.rule_id, 701u);
  check_uint_eq(decision.applied_index, 41u);

  check_int_eq(mesh_flow_runtime_require_index_v1(&runtime, 42u),
               MESH_FLOW_RUNTIME_OK);
  check_int_eq(mesh_flow_runtime_evaluate_ipv4_v1(
                   &runtime, MESH_FLOW_DIRECTION_OUT, packet, sizeof(packet),
                   NULL, &decision),
               MESH_FLOW_RUNTIME_INVALID_STATE);
  check_int_eq(mesh_flow_runtime_publish_v1(
                   &runtime, 42u, 10u, MESH_FLOW_ACTION_DENY, &rule, 1u),
               MESH_FLOW_RUNTIME_OK);
  check_int_eq(mesh_flow_runtime_evaluate_ipv4_v1(
                   &runtime, MESH_FLOW_DIRECTION_OUT, packet, sizeof(packet),
                   NULL, &decision),
               MESH_FLOW_RUNTIME_OK);

  make_tcp_packet(packet, 80u);
  check_int_eq(mesh_flow_runtime_evaluate_ipv4_v1(
                   &runtime, MESH_FLOW_DIRECTION_OUT, packet, sizeof(packet),
                   NULL, &decision),
               MESH_FLOW_RUNTIME_OK);
  check_int_eq(decision.action, MESH_FLOW_ACTION_DENY);
  check_int_eq(decision.reason, MESH_FLOW_REASON_DEFAULT);
  mesh_flow_runtime_destroy_v1(&runtime);
}

static void test_publication_is_monotonic_and_malformed_packets_fail(void) {
  mesh_flow_runtime_v1_t runtime;
  mesh_flow_rule_v1_t rule = allow_https_rule();
  mesh_flow_decision_v1_t decision;
  uint8_t packet[40];

  memset(&runtime, 0, sizeof(runtime));
  check_int_eq(mesh_flow_runtime_init_v1(&runtime, 2u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RUNTIME_OK);
  check_int_eq(mesh_flow_runtime_publish_v1(
                   &runtime, 5u, 3u, MESH_FLOW_ACTION_DENY, &rule, 1u),
               MESH_FLOW_RUNTIME_OK);
  check_int_eq(mesh_flow_runtime_publish_v1(
                   &runtime, 5u, 4u, MESH_FLOW_ACTION_ALLOW, NULL, 0u),
               MESH_FLOW_RUNTIME_OUT_OF_ORDER);
  make_tcp_packet(packet, 443u);
  packet[0] = 0x46u;
  check_int_eq(mesh_flow_runtime_evaluate_ipv4_v1(
                   &runtime, MESH_FLOW_DIRECTION_OUT, packet, 20u, NULL,
                   &decision),
               MESH_FLOW_RUNTIME_INVALID_ARG);
  mesh_flow_runtime_destroy_v1(&runtime);
}

spec("mesh runtime flow policy") {
  it("uses the committed snapshot for packet decisions") {
    test_published_snapshot_controls_packet_decisions();
  }
  it("fences publication and rejects malformed packets") {
    test_publication_is_monotonic_and_malformed_packets_fail();
  }
}

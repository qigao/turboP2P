#include <tinytest.h>

#include "mesh_stream_discovery.h"
#include "mesh_stream_qos.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* P6: service discovery + QoS + bandwidth statistics for the stream mesh.
 * The cluster simulation runs three logical nodes in-process: node A serves
 * mesh-stream/<id>, node B serves mesh-sync/<object>, and node C discovers
 * both, passes the QoS gate for A but is denied by a flow rule, then streams
 * chunks from A while the QoS module accounts bandwidth. The final line is a
 * stable marker that run_mesh_stream_cluster.ps1 asserts on. */

#define NODE_ID_SIZE 32u

static void fill_bytes(uint8_t *bytes, size_t len, uint8_t first) {
  for (size_t i = 0u; i < len; i++)
    bytes[i] = (uint8_t)(first + i);
}

#define IPV4(a, b, c, d)                                                   \
  (((uint32_t)(a) << 24u) | ((uint32_t)(b) << 16u) |                       \
   ((uint32_t)(c) << 8u) | (uint32_t)(d))
static void to_hex(const uint8_t *bytes, size_t len, char *out) {
  static const char digits[] = "0123456789abcdef";

  for (size_t i = 0u; i < len; i++) {
    out[i * 2u] = digits[bytes[i] >> 4u];
    out[i * 2u + 1u] = digits[bytes[i] & 0x0fu];
  }
  out[len * 2u] = '\0';
}

/* ---- discovery: dns-name convention ---- */

static void test_discovery_dns_names(void) {
  char name[MESH_MGMT_SERVICE_DNS_NAME_MAX + 1u];
  char id[MESH_STREAM_DISCOVERY_ID_HEX_SIZE];
  mesh_stream_discovery_service_type_t type = 0u;

  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_dns_name_build_v1(
                   MESH_STREAM_DISCOVERY_SERVICE_STREAM,
                   "aabbccddeeff00112233445566778899", name, sizeof(name)));
  check_str_eq(name, "mesh-stream-aabbccddeeff00112233445566778899");
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_dns_name_parse_v1(
                   name, strlen(name), &type, id, sizeof(id)));
  check_int_eq((int)type, (int)MESH_STREAM_DISCOVERY_SERVICE_STREAM);
  check_str_eq(id, "aabbccddeeff00112233445566778899");

  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_dns_name_build_v1(
                   MESH_STREAM_DISCOVERY_SERVICE_SYNC,
                   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                   name, sizeof(name)));
  check_str_eq(name, "mesh-sync-0123456789abcdef0123456789abcdef.0123456789abcdef0123456789abcdef");
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_dns_name_parse_v1(
                   name, strlen(name), &type, id, sizeof(id)));
  check_int_eq((int)type, (int)MESH_STREAM_DISCOVERY_SERVICE_SYNC);

  check_int_eq(MESH_STREAM_DISCOVERY_INVALID_ARG,
               mesh_stream_discovery_dns_name_build_v1(
                   (mesh_stream_discovery_service_type_t)9, "aabb", name,
                   sizeof(name)));
  check_int_eq(MESH_STREAM_DISCOVERY_INVALID_ARG,
               mesh_stream_discovery_dns_name_build_v1(
                   MESH_STREAM_DISCOVERY_SERVICE_STREAM, "zzbb", name,
                   sizeof(name)));
  check_int_eq(MESH_STREAM_DISCOVERY_INVALID_ARG,
               mesh_stream_discovery_dns_name_parse_v1("node-a.mesh", 11u, &type,
                                                       id, sizeof(id)));
  check_int_eq(MESH_STREAM_DISCOVERY_INVALID_ARG,
               mesh_stream_discovery_dns_name_parse_v1(
                   "mesh-stream/aabb", 15u, &type, id, sizeof(id)));
}

/* ---- discovery: registry ---- */

static void test_discovery_registry(void) {
  mesh_stream_discovery_v1_t registry;
  mesh_stream_discovery_entry_v1_t entry;
  mesh_stream_discovery_entry_v1_t found[4];
  uint8_t node_a[NODE_ID_SIZE];
  uint8_t node_b[NODE_ID_SIZE];
  size_t count = 0u;

  memset(&registry, 0, sizeof(registry));
  fill_bytes(node_a, sizeof(node_a), 0x10u);
  fill_bytes(node_b, sizeof(node_b), 0x20u);

  memset(&entry, 0, sizeof(entry));
  memcpy(entry.node_id, node_a, sizeof(entry.node_id));
  entry.service_type = MESH_STREAM_DISCOVERY_SERVICE_STREAM;
  snprintf(entry.service_id, sizeof(entry.service_id), "%s",
           "aabbccddeeff00112233445566778899");
  entry.port = 9001u;
  entry.epoch = 1u;
  entry.expires_at_ms = 1000u;
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_upsert_v1(&registry, &entry, 0u));
  check_size_eq(mesh_stream_discovery_count(&registry), 1u);

  /* A second node serving the same stream. */
  memset(&entry, 0, sizeof(entry));
  memcpy(entry.node_id, node_b, sizeof(entry.node_id));
  entry.service_type = MESH_STREAM_DISCOVERY_SERVICE_STREAM;
  snprintf(entry.service_id, sizeof(entry.service_id), "%s",
           "aabbccddeeff00112233445566778899");
  entry.port = 9002u;
  entry.epoch = 1u;
  entry.expires_at_ms = 1000u;
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_upsert_v1(&registry, &entry, 0u));

  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_lookup_v1(
                   &registry, MESH_STREAM_DISCOVERY_SERVICE_STREAM,
                   "aabbccddeeff00112233445566778899", 500u, found,
                   sizeof(found) / sizeof(found[0]), &count));
  check_size_eq(count, 2u);
  check_uint_eq(found[0].port, 9001u);
  check_uint_eq(found[1].port, 9002u);

  /* A different object is not found. */
  check_int_eq(MESH_STREAM_DISCOVERY_NOT_FOUND,
               mesh_stream_discovery_lookup_v1(
                   &registry, MESH_STREAM_DISCOVERY_SERVICE_SYNC,
                   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                   500u, found, sizeof(found) / sizeof(found[0]), &count));

  /* Epoch fencing: an equal/older epoch is rejected, a newer one replaces. */
  memset(&entry, 0, sizeof(entry));
  memcpy(entry.node_id, node_a, sizeof(entry.node_id));
  entry.service_type = MESH_STREAM_DISCOVERY_SERVICE_STREAM;
  snprintf(entry.service_id, sizeof(entry.service_id), "%s",
           "aabbccddeeff00112233445566778899");
  entry.port = 9001u;
  entry.epoch = 1u;
  entry.expires_at_ms = 2000u;
  check_int_eq(MESH_STREAM_DISCOVERY_STALE_EPOCH,
               mesh_stream_discovery_upsert_v1(&registry, &entry, 0u));
  entry.epoch = 2u;
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_upsert_v1(&registry, &entry, 0u));
  check_size_eq(mesh_stream_discovery_count(&registry), 2u);
  check_uint_eq(registry.entries[0].epoch, 2u);

  /* TTL expiry drops entries at/after expires_at: the epoch-1 entries expire
   * at 1000, the refreshed epoch-2 entry (node A) survives until 2000. */
  mesh_stream_discovery_expire_v1(&registry, 1000u);
  check_size_eq(mesh_stream_discovery_count(&registry), 1u);
  mesh_stream_discovery_expire_v1(&registry, 2000u);
  check_size_eq(mesh_stream_discovery_count(&registry), 0u);

  /* Already-expired announcements are rejected on upsert. */
  memset(&entry, 0, sizeof(entry));
  memcpy(entry.node_id, node_a, sizeof(entry.node_id));
  entry.service_type = MESH_STREAM_DISCOVERY_SERVICE_STREAM;
  snprintf(entry.service_id, sizeof(entry.service_id), "%s",
           "aabbccddeeff00112233445566778899");
  entry.epoch = 3u;
  entry.expires_at_ms = 100u;
  check_int_eq(MESH_STREAM_DISCOVERY_INVALID_ARG,
               mesh_stream_discovery_upsert_v1(&registry, &entry, 500u));

  check_int_eq(MESH_STREAM_DISCOVERY_INVALID_ARG,
               mesh_stream_discovery_upsert_v1(NULL, &entry, 0u));
  check_int_eq(MESH_STREAM_DISCOVERY_INVALID_ARG,
               mesh_stream_discovery_lookup_v1(&registry, MESH_STREAM_DISCOVERY_SERVICE_STREAM,
                                               NULL, 0u, found, 1u, &count));
  check_uint_eq(mesh_stream_discovery_count(NULL), 0u);
}

/* ---- discovery: service-record bridge ---- */

static void test_discovery_announcement_bridge(void) {
  mesh_stream_discovery_entry_v1_t entry;
  mesh_stream_discovery_entry_v1_t roundtrip;
  mesh_mgmt_service_announcement_v1_t announcement;
  mesh_mgmt_service_announcement_v1_t decoded;
  uint8_t node[NODE_ID_SIZE];
  uint8_t payload[MESH_MGMT_SERVICE_RECORD_V1_MAX_SIZE];
  size_t payload_len = 0u;

  fill_bytes(node, sizeof(node), 0x30u);
  memset(&entry, 0, sizeof(entry));
  memcpy(entry.node_id, node, sizeof(entry.node_id));
  entry.service_type = MESH_STREAM_DISCOVERY_SERVICE_SYNC;
  snprintf(entry.service_id, sizeof(entry.service_id), "%s",
           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  entry.virtual_ip = IPV4(10, 0, 0, 9);
  entry.port = 9090u;
  entry.epoch = 7u;
  entry.expires_at_ms = 12345u;

  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_to_announcement_v1(&entry, &announcement));
  check_str_eq(announcement.dns_name, "mesh-sync-0123456789abcdef0123456789abcdef.0123456789abcdef0123456789abcdef");
  check_int_eq((int)announcement.service_type, (int)MESH_MGMT_SERVICE_RPC);
  check_int_eq((int)announcement.address_family, (int)MESH_MGMT_SERVICE_ADDRESS_IPV4);
  check_uint_eq(((uint32_t)announcement.virtual_address[0] << 24u) |
                    ((uint32_t)announcement.virtual_address[1] << 16u) |
                    ((uint32_t)announcement.virtual_address[2] << 8u) |
                    (uint32_t)announcement.virtual_address[3],
                IPV4(10, 0, 0, 9));
  check_uint_eq(announcement.port, 9090u);
  check_uint_eq(announcement.record_epoch, 7u);
  check_uint_eq(announcement.expires_at_ms, 12345u);
  check_mem_eq(announcement.owner_node_id, node, sizeof(node));

  /* Encode + decode round-trips through the canonical service record. */
  check_int_eq(MESH_MGMT_SERVICE_RECORD_OK,
               mesh_mgmt_service_record_encode_v1(&announcement, payload,
                                                  sizeof(payload), &payload_len));
  check_int_eq(MESH_MGMT_SERVICE_RECORD_OK,
               mesh_mgmt_service_record_decode_v1(payload, payload_len, &decoded));
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_from_announcement_v1(&decoded, &roundtrip));
  check_mem_eq(roundtrip.node_id, entry.node_id, sizeof(entry.node_id));
  check_int_eq((int)roundtrip.service_type, (int)entry.service_type);
  check_str_eq(roundtrip.service_id, entry.service_id);
  check_uint_eq(roundtrip.virtual_ip, entry.virtual_ip);
  check_uint_eq(roundtrip.port, entry.port);
  check_uint_eq(roundtrip.epoch, entry.epoch);
  check_uint_eq(roundtrip.expires_at_ms, entry.expires_at_ms);

  /* A non-mesh dns_name is rejected by the bridge. */
  decoded.dns_name[0] = 'n';
  decoded.dns_name[1] = 'o';
  decoded.dns_name[2] = 'd';
  decoded.dns_name[3] = 'e';
  check_int_eq(MESH_STREAM_DISCOVERY_INVALID_ARG,
               mesh_stream_discovery_from_announcement_v1(&decoded, &roundtrip));
  check_int_eq(MESH_STREAM_DISCOVERY_INVALID_ARG,
               mesh_stream_discovery_from_announcement_v1(NULL, &roundtrip));
}

/* ---- qos: admission ---- */


static void make_deny_rule(mesh_flow_rule_v1_t *rule, uint64_t rule_id,
                           uint32_t src_network, uint8_t prefix) {
  memset(rule, 0, sizeof(*rule));
  rule->rule_id = rule_id;
  rule->src_network_ip = src_network;
  rule->src_prefix_len = prefix;
  rule->directions = MESH_FLOW_DIRECTION_ANY;
  rule->action = MESH_FLOW_ACTION_DENY;
}

static void test_qos_admission(void) {
  mesh_flow_ruleset_v1_t ruleset;
  mesh_flow_rule_v1_t rules[1];
  mesh_stream_qos_v1_t qos;
  uint8_t peer_a[MESH_STREAM_QOS_IDENTITY_SIZE];
  uint8_t peer_c[MESH_STREAM_QOS_IDENTITY_SIZE];

  fill_bytes(peer_a, sizeof(peer_a), 0x40u);
  fill_bytes(peer_c, sizeof(peer_c), 0x50u);

  memset(&ruleset, 0, sizeof(ruleset));
  check_int_eq(MESH_FLOW_RULESET_OK,
               mesh_flow_ruleset_init_v1(&ruleset, 4u, MESH_FLOW_ACTION_ALLOW));
  make_deny_rule(&rules[0], 1u, IPV4(10, 99, 0, 0), 16u);
  check_int_eq(MESH_FLOW_RULESET_OK,
               mesh_flow_ruleset_apply_replace_v1(&ruleset, 1u, 1u,
                                                  MESH_FLOW_ACTION_ALLOW,
                                                  rules, 1u));

  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_init_v1(&qos, 100u, &ruleset));
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_admit_v1(&qos, peer_a, IPV4(10, 0, 0, 1),
                                        MESH_FLOW_DIRECTION_IN));
  check_int_eq(MESH_STREAM_QOS_DENIED,
               mesh_stream_qos_admit_v1(&qos, peer_c, IPV4(10, 99, 0, 1),
                                        MESH_FLOW_DIRECTION_IN));
  /* The same identity behind an allowed virtual IP is admitted. */
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_admit_v1(&qos, peer_c, IPV4(10, 0, 0, 2),
                                        MESH_FLOW_DIRECTION_IN));

  check_int_eq(MESH_STREAM_QOS_INVALID_ARG,
               mesh_stream_qos_admit_v1(NULL, peer_a, IPV4(10, 0, 0, 1),
                                        MESH_FLOW_DIRECTION_IN));
  check_int_eq(MESH_STREAM_QOS_INVALID_ARG,
               mesh_stream_qos_admit_v1(&qos, NULL, IPV4(10, 0, 0, 1),
                                        MESH_FLOW_DIRECTION_IN));

  /* No ruleset -> everyone is admitted. */
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_init_v1(&qos, 100u, NULL));
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_admit_v1(&qos, peer_c, IPV4(10, 99, 0, 1),
                                        MESH_FLOW_DIRECTION_IN));
  check_int_eq(MESH_STREAM_QOS_INVALID_ARG,
               mesh_stream_qos_init_v1(NULL, 100u, NULL));
  check_int_eq(MESH_STREAM_QOS_INVALID_ARG,
               mesh_stream_qos_init_v1(&qos, 0u, NULL));

  mesh_flow_ruleset_destroy_v1(&ruleset);
}

/* ---- qos: bandwidth statistics ---- */

static void test_qos_bandwidth(void) {
  mesh_stream_qos_v1_t qos;
  mesh_stream_qos_peer_v1_t stats;
  uint8_t peer_a[MESH_STREAM_QOS_IDENTITY_SIZE];
  uint8_t peer_b[MESH_STREAM_QOS_IDENTITY_SIZE];
  uint64_t total_bytes = 0u;
  uint64_t total_chunks = 0u;

  fill_bytes(peer_a, sizeof(peer_a), 0x60u);
  fill_bytes(peer_b, sizeof(peer_b), 0x70u);
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_init_v1(&qos, 100u, NULL));

  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_account_v1(&qos, peer_a, 1000u, 0u));
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_account_v1(&qos, peer_a, 1000u, 50u));
  /* At t=100 the window rolls: 2000 bytes over 100 ms -> 160000 bps. */
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_account_v1(&qos, peer_a, 1000u, 100u));
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_account_v1(&qos, peer_a, 1000u, 150u));
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_account_v1(&qos, peer_a, 1000u, 200u));
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_account_v1(&qos, peer_b, 500u, 300u));

  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_peer_stats_v1(&qos, peer_a, &stats));
  check_uint_eq(stats.bytes_total, 5000u);
  check_uint_eq(stats.chunks_total, 5u);
  check_uint_eq(stats.rate_bps, 160000u); /* first window instant, EWMA seed */
  check_uint_eq(stats.last_activity_ms, 200u);

  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_peer_stats_v1(&qos, peer_b, &stats));
  check_uint_eq(stats.bytes_total, 500u);
  check_uint_eq(stats.chunks_total, 1u);

  {
    uint8_t unknown[MESH_STREAM_QOS_IDENTITY_SIZE];

    fill_bytes(unknown, sizeof(unknown), 0x7fu);
    check_int_eq(MESH_STREAM_QOS_NOT_FOUND,
                 mesh_stream_qos_peer_stats_v1(&qos, unknown, &stats));
  }

  mesh_stream_qos_total_v1(&qos, &total_bytes, &total_chunks);
  check_uint_eq(total_bytes, 5500u);
  check_uint_eq(total_chunks, 6u);

  check_int_eq(MESH_STREAM_QOS_INVALID_ARG,
               mesh_stream_qos_account_v1(NULL, peer_a, 100u, 0u));
  check_int_eq(MESH_STREAM_QOS_INVALID_ARG,
               mesh_stream_qos_account_v1(&qos, NULL, 100u, 0u));
  check_int_eq(MESH_STREAM_QOS_INVALID_ARG,
               mesh_stream_qos_peer_stats_v1(&qos, NULL, &stats));
}

/* ---- 3-node cluster simulation ---- */

static void test_cluster_simulation(void) {
  mesh_stream_discovery_v1_t registry;
  mesh_stream_discovery_entry_v1_t entry;
  mesh_stream_discovery_entry_v1_t found[4];
  mesh_flow_ruleset_v1_t ruleset;
  mesh_flow_rule_v1_t rules[1];
  mesh_stream_qos_v1_t qos;
  uint8_t node_a[NODE_ID_SIZE];
  uint8_t node_b[NODE_ID_SIZE];
  uint8_t node_c[MESH_STREAM_QOS_IDENTITY_SIZE];
  uint8_t stream_bytes[16];
  uint8_t object_bytes[32];
  char stream_id_hex[MESH_STREAM_DISCOVERY_ID_HEX_SIZE];
  char object_hex[MESH_STREAM_DISCOVERY_ID_HEX_SIZE];
  mesh_stream_qos_peer_v1_t stats;
  size_t count = 0u;
  uint64_t total_bytes = 0u;
  uint64_t total_chunks = 0u;

  memset(&registry, 0, sizeof(registry));
  fill_bytes(node_a, sizeof(node_a), 0x80u);
  fill_bytes(node_b, sizeof(node_b), 0x90u);
  fill_bytes(node_c, sizeof(node_c), 0xa0u);
  fill_bytes(stream_bytes, sizeof(stream_bytes), 0x11u);
  fill_bytes(object_bytes, sizeof(object_bytes), 0x22u);
  to_hex(stream_bytes, sizeof(stream_bytes), stream_id_hex);
  to_hex(object_bytes, sizeof(object_bytes), object_hex);

  /* Node A advertises mesh-stream/<stream>, node B mesh-sync/<object>. */
  memset(&entry, 0, sizeof(entry));
  memcpy(entry.node_id, node_a, sizeof(entry.node_id));
  entry.service_type = MESH_STREAM_DISCOVERY_SERVICE_STREAM;
  snprintf(entry.service_id, sizeof(entry.service_id), "%s", stream_id_hex);
  entry.virtual_ip = IPV4(10, 0, 0, 1);
  entry.port = 9001u;
  entry.epoch = 1u;
  entry.expires_at_ms = 60000u;
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_upsert_v1(&registry, &entry, 0u));

  memset(&entry, 0, sizeof(entry));
  memcpy(entry.node_id, node_b, sizeof(entry.node_id));
  entry.service_type = MESH_STREAM_DISCOVERY_SERVICE_SYNC;
  snprintf(entry.service_id, sizeof(entry.service_id), "%s", object_hex);
  entry.virtual_ip = IPV4(10, 0, 0, 2);
  entry.port = 9002u;
  entry.epoch = 1u;
  entry.expires_at_ms = 60000u;
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_upsert_v1(&registry, &entry, 0u));
  check_size_eq(mesh_stream_discovery_count(&registry), 2u);

  /* Node C (consumer) discovers both services. */
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_lookup_v1(
                   &registry, MESH_STREAM_DISCOVERY_SERVICE_STREAM,
                   stream_id_hex, 1000u, found, 4u, &count));
  check_size_eq(count, 1u);
  check_mem_eq(found[0].node_id, node_a, sizeof(node_a));
  check_int_eq(MESH_STREAM_DISCOVERY_OK,
               mesh_stream_discovery_lookup_v1(
                   &registry, MESH_STREAM_DISCOVERY_SERVICE_SYNC, object_hex,
                   1000u, found, 4u, &count));
  check_size_eq(count, 1u);
  check_mem_eq(found[0].node_id, node_b, sizeof(node_b));

  /* QoS: default allow; node C's subnet is denied, node A is allowed. */
  memset(&ruleset, 0, sizeof(ruleset));
  check_int_eq(MESH_FLOW_RULESET_OK,
               mesh_flow_ruleset_init_v1(&ruleset, 4u, MESH_FLOW_ACTION_ALLOW));
  make_deny_rule(&rules[0], 1u, IPV4(10, 99, 0, 0), 16u);
  check_int_eq(MESH_FLOW_RULESET_OK,
               mesh_flow_ruleset_apply_replace_v1(&ruleset, 1u, 1u,
                                                  MESH_FLOW_ACTION_ALLOW,
                                                  rules, 1u));
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_init_v1(&qos, 1000u, &ruleset));
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_admit_v1(&qos, node_a, IPV4(10, 0, 0, 1),
                                        MESH_FLOW_DIRECTION_IN));
  check_int_eq(MESH_STREAM_QOS_DENIED,
               mesh_stream_qos_admit_v1(&qos, node_c, IPV4(10, 99, 0, 1),
                                        MESH_FLOW_DIRECTION_IN));

  /* Stream 5 chunks of 1024 bytes from node A and account them. */
  for (uint64_t t = 0u; t < 5000u; t += 1000u) {
    check_int_eq(MESH_STREAM_QOS_OK,
                 mesh_stream_qos_account_v1(&qos, node_a, 1024u, t));
  }
  check_int_eq(MESH_STREAM_QOS_OK,
               mesh_stream_qos_peer_stats_v1(&qos, node_a, &stats));
  check_uint_eq(stats.chunks_total, 5u);
  check_uint_eq(stats.bytes_total, 5120u);
  check_uint_eq(stats.rate_bps, 8192u); /* 1024 B over 1 s -> 8192 bps */
  mesh_stream_qos_total_v1(&qos, &total_bytes, &total_chunks);
  check_uint_eq(total_chunks, 5u);
  check_uint_eq(total_bytes, 5120u);

  mesh_flow_ruleset_destroy_v1(&ruleset);

  /* Stable marker for run_mesh_stream_cluster.ps1. */
  printf("CLUSTER OK nodes=3 streams=1 sync=1 denied=1 chunks=%llu bytes=%llu\n",
         (unsigned long long)total_chunks, (unsigned long long)total_bytes);
}

spec("mesh stream cluster") {
    describe("service discovery + QoS + bandwidth") {
        it("builds and parses mesh-stream/mesh-sync dns names") {
            test_discovery_dns_names();
        }
        it("upserts, fences epochs, expires and looks up registry entries") {
            test_discovery_registry();
        }
        it("bridges discovery entries with the mgmt service record") {
            test_discovery_announcement_bridge();
        }
        it("gates peers through the flow ruleset (QoS)") {
            test_qos_admission();
        }
        it("accounts chunks and estimates bandwidth per peer") {
            test_qos_bandwidth();
        }
        it("runs a 3-node discovery + QoS + bandwidth simulation") {
            test_cluster_simulation();
        }
    }
}
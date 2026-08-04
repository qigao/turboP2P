/* mesh_stream_node_main.c - mesh-stream cluster node executable.
 *
 * Runs one command per process. A node announces a mesh-stream/mesh-sync
 * service and prints the canonical service record; another node decodes those
 * records, discovers the services, applies QoS and accounts bandwidth. The
 * canonical record bytes are the cross-process wire contract.
 *
 * Usage:
 *   mesh_stream_node_main --node <hex32> \
 *       announce <stream|sync> <id-hex> --vip a.b.c.d --port N --epoch N --ttl-ms N
 *   mesh_stream_node_main --node <hex32> \
 *       discover <stream|sync> <id-hex> --record <hex> [--record <hex>...]
 *   mesh_stream_node_main --node <hex32> qos <peer-hex> --vip a.b.c.d --direction in|out
 */

#include "mesh_stream_discovery.h"
#include "mesh_stream_qos.h"

#include "mesh_flow_ruleset.h"
#include "mesh_mgmt_service_record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#define HEX32_SIZE 65u

static uint64_t g_now_ms(void) {
#ifdef _WIN32
  FILETIME ft;
  ULARGE_INTEGER ul;
  GetSystemTimeAsFileTime(&ft);
  ul.LowPart = ft.dwLowDateTime;
  ul.HighPart = ft.dwHighDateTime;
  return (uint64_t)(ul.QuadPart / 10000u) - 11644473600000ULL;
#else
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
#endif
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int hex_to_bytes(const char *text, uint8_t *out, size_t out_size) {
  size_t length = strlen(text);

  if (length != out_size * 2u)
    return -1;
  for (size_t i = 0u; i < out_size; i++) {
    int hi = hex_value(text[i * 2u]);
    int lo = hex_value(text[i * 2u + 1u]);

    if (hi < 0 || lo < 0)
      return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t size, char *output) {
  static const char digits[] = "0123456789abcdef";

  for (size_t i = 0u; i < size; i++) {
    output[i * 2u] = digits[bytes[i] >> 4u];
    output[i * 2u + 1u] = digits[bytes[i] & 0x0fu];
  }
  output[size * 2u] = '\0';
}

static int parse_vip(const char *text, uint32_t *out) {
  unsigned a, b, c, d;

  if (sscanf(text, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255u ||
      b > 255u || c > 255u || d > 255u) {
    return -1;
  }
  *out = ((uint32_t)a << 24u) | ((uint32_t)b << 16u) | ((uint32_t)c << 8u) |
         (uint32_t)d;
  return 0;
}

static void print_vip(uint32_t vip, char *out, size_t cap) {
  snprintf(out, cap, "%u.%u.%u.%u", (unsigned)(vip >> 24u),
           (unsigned)((vip >> 16u) & 0xffu), (unsigned)((vip >> 8u) & 0xffu),
           (unsigned)(vip & 0xffu));
}

static mesh_stream_discovery_service_type_t parse_type(const char *text) {
  if (strcmp(text, "stream") == 0)
    return MESH_STREAM_DISCOVERY_SERVICE_STREAM;
  if (strcmp(text, "sync") == 0)
    return MESH_STREAM_DISCOVERY_SERVICE_SYNC;
  return (mesh_stream_discovery_service_type_t)0;
}

static const char *arg_value(int argc, char **argv, int *index) {
  if (*index + 1 >= argc)
    return NULL;
  *index += 1;
  return argv[*index];
}

static int cmd_announce(const char *node_hex, int argc, char **argv, int start) {
  uint8_t node_id[MESH_STREAM_DISCOVERY_NODE_ID_SIZE];
  mesh_stream_discovery_entry_v1_t entry;
  mesh_mgmt_service_announcement_v1_t announcement;
  mesh_stream_discovery_service_type_t type;
  const char *id_hex;
  uint8_t payload[MESH_MGMT_SERVICE_RECORD_V1_MAX_SIZE];
  size_t payload_len = 0u;
  uint32_t vip = 0u;
  unsigned long port = 0u;
  unsigned long long epoch = 0u;
  unsigned long long ttl_ms = 0u;
  char hex[MESH_MGMT_SERVICE_RECORD_V1_MAX_SIZE * 2u + 1u];

  if (hex_to_bytes(node_hex, node_id, sizeof(node_id)) != 0) {
    fprintf(stderr, "invalid --node hex (need %zu bytes)\n", sizeof(node_id));
    return 1;
  }
  if (start + 2 >= argc)
    return 1;
  type = parse_type(argv[start]);
  id_hex = argv[start + 1];
  if (type == 0u || !id_hex) {
    fprintf(stderr, "announce needs <stream|sync> <id-hex>\n");
    return 1;
  }
  for (int i = start + 2; i < argc; i++) {
    if (strcmp(argv[i], "--vip") == 0 && i + 1 < argc) {
      if (parse_vip(argv[++i], &vip) != 0)
        return 1;
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = strtoul(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--epoch") == 0 && i + 1 < argc) {
      epoch = strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--ttl-ms") == 0 && i + 1 < argc) {
      ttl_ms = strtoull(argv[++i], NULL, 10);
    } else {
      fprintf(stderr, "unknown announce arg: %s\n", argv[i]);
      return 1;
    }
  }
  if (vip == 0u || port == 0u || ttl_ms == 0u)
    return 1;

  memset(&entry, 0, sizeof(entry));
  memcpy(entry.node_id, node_id, sizeof(entry.node_id));
  entry.service_type = type;
  snprintf(entry.service_id, sizeof(entry.service_id), "%s", id_hex);
  entry.virtual_ip = vip;
  entry.port = (uint16_t)port;
  entry.epoch = epoch;
  entry.expires_at_ms = g_now_ms() + ttl_ms;
  if (mesh_stream_discovery_to_announcement_v1(&entry, &announcement) !=
      MESH_STREAM_DISCOVERY_OK) {
    fprintf(stderr, "to_announcement failed\n");
    return 1;
  }
  if (mesh_mgmt_service_record_encode_v1(&announcement, payload, sizeof(payload),
                                         &payload_len) !=
      MESH_MGMT_SERVICE_RECORD_OK) {
    fprintf(stderr, "service record encode failed\n");
    return 1;
  }
  bytes_to_hex(payload, payload_len, hex);
  printf("ANNOUNCE OK dns=%s port=%u epoch=%llu\n", announcement.dns_name,
         (unsigned)announcement.port, (unsigned long long)announcement.record_epoch);
  printf("RECORD %s\n", hex);
  return 0;
}

static int cmd_qos(const char *node_hex, int argc, char **argv, int start) {
  uint8_t peer_identity[MESH_STREAM_QOS_IDENTITY_SIZE];
  uint32_t vip = 0u;
  uint32_t direction = MESH_FLOW_DIRECTION_IN;
  mesh_flow_ruleset_v1_t ruleset;
  mesh_flow_rule_v1_t rules[1];
  mesh_stream_qos_v1_t qos;
  mesh_stream_qos_result_t rc;

  (void)node_hex;
  if (start + 1 >= argc ||
      hex_to_bytes(argv[start], peer_identity, sizeof(peer_identity)) != 0) {
    fprintf(stderr, "qos needs <peer-hex>\n");
    return 1;
  }
  for (int i = start + 1; i < argc; i++) {
    if (strcmp(argv[i], "--vip") == 0 && i + 1 < argc) {
      if (parse_vip(argv[++i], &vip) != 0)
        return 1;
    } else if (strcmp(argv[i], "--direction") == 0 && i + 1 < argc) {
      const char *d = argv[++i];

      if (strcmp(d, "in") == 0)
        direction = MESH_FLOW_DIRECTION_IN;
      else if (strcmp(d, "out") == 0)
        direction = MESH_FLOW_DIRECTION_OUT;
      else
        return 1;
    } else {
      fprintf(stderr, "unknown qos arg: %s\n", argv[i]);
      return 1;
    }
  }
  memset(&ruleset, 0, sizeof(ruleset));
  if (mesh_flow_ruleset_init_v1(&ruleset, 4u, MESH_FLOW_ACTION_ALLOW) !=
      MESH_FLOW_RULESET_OK) {
    return 1;
  }
  memset(&rules[0], 0, sizeof(rules[0]));
  rules[0].rule_id = 1u;
  rules[0].src_network_ip = ((uint32_t)10u << 24u) | ((uint32_t)99u << 16u);
  rules[0].src_prefix_len = 16u;
  rules[0].directions = MESH_FLOW_DIRECTION_ANY;
  rules[0].action = MESH_FLOW_ACTION_DENY;
  (void)mesh_flow_ruleset_apply_replace_v1(&ruleset, 1u, 1u,
                                           MESH_FLOW_ACTION_ALLOW, rules, 1u);
  if (mesh_stream_qos_init_v1(&qos, 1000u, &ruleset) != MESH_STREAM_QOS_OK)
    return 1;
  rc = mesh_stream_qos_admit_v1(&qos, peer_identity, vip, direction);
  mesh_flow_ruleset_destroy_v1(&ruleset);
  if (rc == MESH_STREAM_QOS_DENIED) {
    printf("QOS DENIED\n");
    return 0;
  }
  if (rc == MESH_STREAM_QOS_OK) {
    printf("QOS OK\n");
    return 0;
  }
  return 1;
}

static int cmd_discover(const char *node_hex, int argc, char **argv, int start) {
  mesh_stream_discovery_v1_t registry;
  mesh_stream_discovery_entry_v1_t found[8];
  mesh_stream_discovery_service_type_t type;
  const char *id_hex;
  mesh_flow_ruleset_v1_t ruleset;
  mesh_flow_rule_v1_t rules[1];
  mesh_stream_qos_v1_t qos;
  mesh_stream_qos_peer_v1_t stats;
  size_t count = 0u;
  uint64_t now_ms = g_now_ms();
  char vip_text[16];
  int rc = 0;

  (void)node_hex;
  if (start + 2 >= argc)
    return 1;
  type = parse_type(argv[start]);
  id_hex = argv[start + 1];
  if (type == 0u || !id_hex)
    return 1;
  memset(&registry, 0, sizeof(registry));
  for (int i = start + 2; i < argc; i++) {
    if (strcmp(argv[i], "--record") == 0 && i + 1 < argc) {
      uint8_t payload[MESH_MGMT_SERVICE_RECORD_V1_MAX_SIZE];
      size_t payload_len = 0u;
      mesh_mgmt_service_announcement_v1_t announcement;
      mesh_stream_discovery_entry_v1_t entry;

      payload_len = strlen(argv[i + 1]) / 2u;
      if (payload_len > sizeof(payload) ||
          hex_to_bytes(argv[i + 1], payload, payload_len) != 0) {
        fprintf(stderr, "invalid --record hex\n");
        return 1;
      }
      i++;
      if (mesh_mgmt_service_record_decode_v1(payload, payload_len,
                                             &announcement) !=
          MESH_MGMT_SERVICE_RECORD_OK) {
        fprintf(stderr, "record decode failed\n");
        return 1;
      }
      if (mesh_stream_discovery_from_announcement_v1(&announcement, &entry) !=
          MESH_STREAM_DISCOVERY_OK) {
        fprintf(stderr, "record is not a mesh-stream/sync service\n");
        return 1;
      }
      (void)mesh_stream_discovery_upsert_v1(&registry, &entry, now_ms);
    } else {
      fprintf(stderr, "unknown discover arg: %s\n", argv[i]);
      return 1;
    }
  }
  if (mesh_stream_discovery_lookup_v1(&registry, type, id_hex, now_ms, found,
                                      sizeof(found) / sizeof(found[0]),
                                      &count) != MESH_STREAM_DISCOVERY_OK) {
    fprintf(stderr, "service not found\n");
    return 1;
  }
  printf("DISCOVER OK count=%zu\n", count);
  for (size_t s = 0u; s < count; s++) {
    char node_hex_out[MESH_STREAM_DISCOVERY_NODE_ID_SIZE * 2u + 1u];

    bytes_to_hex(found[s].node_id, sizeof(found[s].node_id), node_hex_out);
    print_vip(found[s].virtual_ip, vip_text, sizeof(vip_text));
    printf("FOUND node=%s port=%u vip=%s\n", node_hex_out, found[s].port,
           vip_text);
  }

  /* QoS + bandwidth stats: the 10.99.0.0/16 subnet is denied; stream chunks
   * from the first found node are accounted. */
  memset(&ruleset, 0, sizeof(ruleset));
  (void)mesh_flow_ruleset_init_v1(&ruleset, 4u, MESH_FLOW_ACTION_ALLOW);
  memset(&rules[0], 0, sizeof(rules[0]));
  rules[0].rule_id = 1u;
  rules[0].src_network_ip = ((uint32_t)10u << 24u) | ((uint32_t)99u << 16u);
  rules[0].src_prefix_len = 16u;
  rules[0].directions = MESH_FLOW_DIRECTION_ANY;
  rules[0].action = MESH_FLOW_ACTION_DENY;
  (void)mesh_flow_ruleset_apply_replace_v1(&ruleset, 1u, 1u,
                                           MESH_FLOW_ACTION_ALLOW, rules, 1u);
  (void)mesh_stream_qos_init_v1(&qos, 1000u, &ruleset);
  rc = 0;
  for (size_t s = 0u; s < count; s++) {
    if (mesh_stream_qos_admit_v1(&qos, found[s].node_id, found[s].virtual_ip,
                                 MESH_FLOW_DIRECTION_IN) ==
        MESH_STREAM_QOS_DENIED) {
      rc++;
    }
    for (uint64_t t = 0u; t < 5000u && s == 0u; t += 1000u) {
      (void)mesh_stream_qos_account_v1(&qos, found[s].node_id, 1024u,
                                       now_ms + t);
    }
  }
  {
    uint8_t blocked[MESH_STREAM_QOS_IDENTITY_SIZE];

    memset(blocked, 0xa5, sizeof(blocked));
    if (mesh_stream_qos_admit_v1(&qos, blocked, ((uint32_t)10u << 24u) |
                                                    ((uint32_t)99u << 16u) |
                                                    (uint32_t)1u,
                                 MESH_FLOW_DIRECTION_IN) == MESH_STREAM_QOS_DENIED) {
      rc++;
    }
  }
  mesh_flow_ruleset_destroy_v1(&ruleset);
  (void)mesh_stream_qos_peer_stats_v1(&qos, found[0].node_id, &stats);
  printf("CLUSTER OK nodes=%zu streams=1 sync=1 denied=%d chunks=%llu bytes=%llu\n",
         mesh_stream_discovery_count(&registry), rc,
         (unsigned long long)stats.chunks_total,
         (unsigned long long)stats.bytes_total);
  return 0;
}

int main(int argc, char **argv) {
  const char *node_hex = NULL;
  const char *command = NULL;
  int i = 1;

  if (argc < 2) {
    fprintf(stderr,
            "usage: mesh_stream_node_main --node <hex32> "
            "<announce|discover|qos> ...\n");
    return 1;
  }
  if (strcmp(argv[1], "--node") == 0 && argc >= 3) {
    node_hex = argv[2];
    i = 3;
  }
  if (i >= argc) {
    fprintf(stderr, "missing command\n");
    return 1;
  }
  command = argv[i];
  i++;
  if (strcmp(command, "announce") == 0)
    return cmd_announce(node_hex, argc, argv, i);
  if (strcmp(command, "discover") == 0)
    return cmd_discover(node_hex, argc, argv, i);
  if (strcmp(command, "qos") == 0)
    return cmd_qos(node_hex, argc, argv, i);
  fprintf(stderr, "unknown command: %s\n", command);
  return 1;
}
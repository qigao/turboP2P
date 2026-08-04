#ifndef TURBO_P2P_MESH_STREAM_DISCOVERY_H
#define TURBO_P2P_MESH_STREAM_DISCOVERY_H

#include "mesh_mgmt_service_record.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P6: mesh-stream / mesh-sync service discovery. The mgmt service record
 * (dns_name + node id + virtual ip + port + epoch + TTL) is the wire fact
 * source; this module derives a lightweight discovery registry from it. The
 * dns_name convention is the canonical DNS form "mesh-stream-<id-hex>" or
 * "mesh-sync-<object-hex>" (ids longer than 32 hex chars are split into two
 * DNS labels), keeping the record schema-canonical; the registry adds epoch
 * fencing and TTL expiry for multi-node lookup. */

#define MESH_STREAM_DISCOVERY_NODE_ID_SIZE 32u
#define MESH_STREAM_DISCOVERY_ID_HEX_SIZE 65u /* 64 hex chars + NUL */
#define MESH_STREAM_DISCOVERY_DNS_NAME_MAX MESH_MGMT_SERVICE_DNS_NAME_MAX
#define MESH_STREAM_DISCOVERY_MAX_ENTRIES 64u

typedef enum {
  MESH_STREAM_DISCOVERY_OK = 0,
  MESH_STREAM_DISCOVERY_INVALID_ARG = -1,
  MESH_STREAM_DISCOVERY_RESOURCE_EXHAUSTED = -2,
  MESH_STREAM_DISCOVERY_NOT_FOUND = -3,
  MESH_STREAM_DISCOVERY_STALE_EPOCH = -4,
} mesh_stream_discovery_result_t;

typedef enum {
  MESH_STREAM_DISCOVERY_SERVICE_STREAM = 1, /* mesh-stream/<stream id hex> */
  MESH_STREAM_DISCOVERY_SERVICE_SYNC = 2,   /* mesh-sync/<object digest hex> */
} mesh_stream_discovery_service_type_t;

typedef struct {
  uint8_t node_id[MESH_STREAM_DISCOVERY_NODE_ID_SIZE];
  mesh_stream_discovery_service_type_t service_type;
  char service_id[MESH_STREAM_DISCOVERY_ID_HEX_SIZE]; /* lowercase hex */
  uint32_t virtual_ip; /* IPv4 virtual service address (flow QoS key) */
  uint16_t port;
  uint64_t epoch;
  uint64_t expires_at_ms;
} mesh_stream_discovery_entry_v1_t;

typedef struct {
  mesh_stream_discovery_entry_v1_t entries[MESH_STREAM_DISCOVERY_MAX_ENTRIES];
  size_t count;
} mesh_stream_discovery_v1_t;

/**
 * Build the canonical service dns_name: "mesh-stream-<hex>" or
 * "mesh-sync-<hex>" (ids over 32 hex chars are split with a '.' after 32
 * chars to stay within the DNS 63-char label bound). service_id_hex must be
 * 1..64 lowercase hex chars.
 */
mesh_stream_discovery_result_t mesh_stream_discovery_dns_name_build_v1(
    mesh_stream_discovery_service_type_t type, const char *service_id_hex,
    char *out, size_t out_capacity);

/** Parse a dns_name back into service type + service id hex. */
mesh_stream_discovery_result_t mesh_stream_discovery_dns_name_parse_v1(
    const char *dns_name, size_t name_len,
    mesh_stream_discovery_service_type_t *out_type, char *out_service_id_hex,
    size_t service_id_capacity);

/** Bridge a decoded mgmt service announcement (dns_name convention + epoch +
 * TTL) into a discovery entry. */
mesh_stream_discovery_result_t mesh_stream_discovery_from_announcement_v1(
    const mesh_mgmt_service_announcement_v1_t *announcement,
    mesh_stream_discovery_entry_v1_t *out_entry);

/** Build the announcement a node would advertise for this entry. */
mesh_stream_discovery_result_t mesh_stream_discovery_to_announcement_v1(
    const mesh_stream_discovery_entry_v1_t *entry,
    mesh_mgmt_service_announcement_v1_t *out_announcement);

/**
 * Upsert one entry into the registry (caller zero-initializes the registry).
 * A duplicate (node, service) with an older or equal epoch is rejected; a
 * newer epoch replaces it and refreshes the TTL.
 */
mesh_stream_discovery_result_t mesh_stream_discovery_upsert_v1(
    mesh_stream_discovery_v1_t *registry,
    const mesh_stream_discovery_entry_v1_t *entry, uint64_t now_ms);

/** Drop entries whose TTL expired at or before now_ms. */
void mesh_stream_discovery_expire_v1(mesh_stream_discovery_v1_t *registry,
                                     uint64_t now_ms);

/** List all live entries serving (type, service_id), newest epoch first. */
mesh_stream_discovery_result_t mesh_stream_discovery_lookup_v1(
    const mesh_stream_discovery_v1_t *registry,
    mesh_stream_discovery_service_type_t type, const char *service_id_hex,
    uint64_t now_ms, mesh_stream_discovery_entry_v1_t *out_entries,
    size_t out_capacity, size_t *out_count);

/** Number of live entries in the registry. */
size_t mesh_stream_discovery_count(const mesh_stream_discovery_v1_t *registry);

#ifdef __cplusplus
}
#endif

#endif
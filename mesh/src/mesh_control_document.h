#ifndef MESH_CONTROL_DOCUMENT_H
#define MESH_CONTROL_DOCUMENT_H

#include "mesh_control_mmp.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_INTENT_MAGIC_SIZE_V1 4u
#define MESH_CONTROL_INTENT_HEADER_SIZE_V1 8u
#define MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1 232u
#define MESH_CONTROL_NETWORK_TICKET_SIZE_V1 300u
#define MESH_CONTROL_NETWORK_NAME_CAPACITY_V1 64u
#define MESH_CONTROL_NETWORK_MAX_PEERS_V1 256u
#define MESH_CONTROL_NETWORK_MAX_ROUTES_V1 256u
#define MESH_CONTROL_NETWORK_ROUTE_SIZE_V1 40u
#define MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 632u
#define MESH_CONTROL_NETWORK_DOCUMENT_MAX_SIZE_V1                         \
  (MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 +                           \
   MESH_CONTROL_NETWORK_MAX_PEERS_V1 * MESH_CONTROL_NODE_ID_SIZE +        \
   MESH_CONTROL_NETWORK_MAX_ROUTES_V1 * MESH_CONTROL_NETWORK_ROUTE_SIZE_V1)

typedef enum {
  MESH_CONTROL_NETWORK_ROUTE_SUBNET_V1 = 1,
  MESH_CONTROL_NETWORK_ROUTE_EXIT_V1 = 2
} mesh_control_network_route_kind_v1_t;

typedef struct {
  uint32_t destination_network;
  uint8_t prefix_length;
  uint8_t kind;
  uint16_t metric;
  uint8_t next_hop_node_id[MESH_CONTROL_NODE_ID_SIZE];
} mesh_control_network_route_v1_t;

typedef enum {
  MESH_CONTROL_NETWORK_ACTIVE_V1 = 1,
  MESH_CONTROL_NETWORK_DRAINING_V1 = 2,
  MESH_CONTROL_NETWORK_TOMBSTONED_V1 = 3
} mesh_control_network_lifecycle_v1_t;

typedef enum {
  MESH_CONTROL_NETWORK_USERSPACE_V1 = 1,
  MESH_CONTROL_NETWORK_OS_SHARED_V1 = 2,
  MESH_CONTROL_NETWORK_OS_ISOLATED_V1 = 3
} mesh_control_network_attach_mode_v1_t;

/** Typed per-node Network snapshot. Peer IDs are a contiguous borrowed array. */
typedef struct {
  uint16_t schema_version;
  uint16_t lifecycle;
  uint16_t attach_mode;
  uint16_t reserved;
  uint32_t flags;
  uint8_t network_uid[MESH_CONTROL_ID_SIZE];
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t managed_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint64_t generation;
  uint64_t policy_epoch;
  uint64_t route_epoch;
  uint64_t key_epoch;
  uint32_t ipv4_address;
  uint8_t ipv4_prefix;
  uint16_t mtu;
  char name[MESH_CONTROL_NETWORK_NAME_CAPACITY_V1];
  uint8_t policy_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t address_pool_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t route_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t dns_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t membership_ticket[MESH_CONTROL_NETWORK_TICKET_SIZE_V1];
  const uint8_t *authorized_peer_node_ids;
  size_t authorized_peer_count;
  /** Canonical 40-byte route records; borrowed by encode and decode. */
  const uint8_t *route_entries;
  size_t route_count;
} mesh_control_network_document_v1_t;

typedef struct {
  mesh_control_desired_action_v1_t action;
  const uint8_t *document;
  size_t document_size;
} mesh_control_intent_view_v1_t;

/** Encodes a canonical intent header followed by caller-borrowed document bytes. */
mesh_control_result_t mesh_control_intent_encode_v1(
    mesh_control_desired_action_v1_t action, const uint8_t *document,
    size_t document_size, uint8_t *output, size_t output_capacity,
    size_t *out_size);

/** Decodes an intent and returns a document view borrowed from payload. */
mesh_control_result_t mesh_control_intent_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_control_intent_view_v1_t *out_intent);

/** Encodes the fixed-size canonical function assignment document. */
mesh_control_result_t mesh_control_function_document_encode_v1(
    const mesh_control_function_spec_v1_t *spec, uint8_t *output,
    size_t output_capacity, size_t *out_size);

/** Decodes and validates one exact-size canonical function document. */
mesh_control_result_t mesh_control_function_document_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_control_function_spec_v1_t *out_spec);

/** Encode/decode a bounded canonical Network snapshot. Decoded peer IDs borrow input. */
mesh_control_result_t mesh_control_network_route_encode_v1(
    const mesh_control_network_route_v1_t *route,
    uint8_t output[MESH_CONTROL_NETWORK_ROUTE_SIZE_V1]);
mesh_control_result_t mesh_control_network_route_decode_v1(
    const uint8_t input[MESH_CONTROL_NETWORK_ROUTE_SIZE_V1],
    mesh_control_network_route_v1_t *out_route);
mesh_control_result_t mesh_control_network_routes_digest_v1(
    const uint8_t *route_entries, size_t route_count,
    uint8_t out_digest[MESH_CONTROL_DIGEST_SIZE]);

/** Encode/decode a bounded canonical Network snapshot. Decoded arrays borrow input. */
mesh_control_result_t mesh_control_network_document_encode_v1(
    const mesh_control_network_document_v1_t *document, uint8_t *output,
    size_t output_capacity, size_t *out_size);
mesh_control_result_t mesh_control_network_document_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_control_network_document_v1_t *out_document);

#ifdef __cplusplus
}
#endif

#endif

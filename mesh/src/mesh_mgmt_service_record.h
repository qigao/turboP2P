#ifndef TURBO_P2P_MESH_MGMT_SERVICE_RECORD_H
#define TURBO_P2P_MESH_MGMT_SERVICE_RECORD_H

#include "mesh_mgmt_identity.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_SERVICE_DNS_NAME_MAX 127u
#define MESH_MGMT_SERVICE_VIRTUAL_IP_MAX 64u
#define MESH_MGMT_SERVICE_RECORD_IPV4_V1_MIN_SIZE 93u
#define MESH_MGMT_SERVICE_RECORD_IPV6_V1_MIN_SIZE 105u
#define MESH_MGMT_SERVICE_RECORD_V1_MAX_SIZE 232u
#define MESH_MGMT_SERVICE_RECORD_MAX_TTL_MS 86400000u
#define MESH_MGMT_SERVICE_DHT_KEY_V1_LENGTH 151u
#define MESH_MGMT_SERVICE_DHT_KEY_V1_SIZE 152u

typedef enum {
  MESH_MGMT_SERVICE_RECORD_OK = 0,
  MESH_MGMT_SERVICE_RECORD_INVALID_ARG = -1,
  MESH_MGMT_SERVICE_RECORD_INVALID_SCHEMA = -2,
  MESH_MGMT_SERVICE_RECORD_RESOURCE_EXHAUSTED = -3,
  MESH_MGMT_SERVICE_RECORD_AUTH_FAILED = -4,
  MESH_MGMT_SERVICE_RECORD_EXPIRED = -5,
  MESH_MGMT_SERVICE_RECORD_CRYPTO_FAILURE = -6,
  MESH_MGMT_SERVICE_RECORD_ADDRESS_FAILURE = -7,
} mesh_mgmt_service_record_result_t;

typedef enum {
  MESH_MGMT_SERVICE_RPC = 1,
} mesh_mgmt_service_type_t;

typedef enum {
  MESH_MGMT_SERVICE_ADDRESS_IPV4 = 4,
  MESH_MGMT_SERVICE_ADDRESS_IPV6 = 6,
} mesh_mgmt_service_address_family_t;

typedef struct {
  uint8_t owner_node_id[32];
  mesh_mgmt_service_type_t service_type;
  mesh_mgmt_service_address_family_t address_family;
  uint8_t virtual_address[16];
  char dns_name[MESH_MGMT_SERVICE_DNS_NAME_MAX + 1u];
  uint16_t port;
  uint64_t record_epoch;
  uint64_t expires_at_ms;
} mesh_mgmt_service_announcement_v1_t;

typedef struct {
  uint8_t owner_node_id[32];
  mesh_mgmt_service_type_t service_type;
  char virtual_ip[MESH_MGMT_SERVICE_VIRTUAL_IP_MAX];
  char dns_name[MESH_MGMT_SERVICE_DNS_NAME_MAX + 1u];
  char virtual_host[MESH_MGMT_SERVICE_DNS_NAME_MAX + 1u];
  uint16_t port;
  uint64_t record_epoch;
  uint64_t expires_at_ms;
} mesh_mgmt_service_record_v1_t;

typedef struct {
  const uint8_t *frame;
  size_t frame_len;
  const uint8_t *certificate;
  size_t certificate_len;
  const uint8_t *trusted_issuer_key;
  const uint8_t *expected_mesh_id_hash;
  const uint8_t *expected_owner_node_id;
  uint64_t now_ms;
  uint64_t max_ttl_ms;
} mesh_mgmt_service_record_verify_input_v1_t;

/** Build the canonical mgmt:<mesh>:node:<node>:service:rpc DHT key. */
mesh_mgmt_service_record_result_t
mesh_mgmt_service_dht_key_build_v1(const uint8_t mesh_id_hash[32],
                                   const uint8_t owner_node_id[32], char *output,
                                   size_t output_capacity, size_t *out_len);

/** Parse one exact lowercase canonical RPC service DHT key. */
mesh_mgmt_service_record_result_t
mesh_mgmt_service_dht_key_parse_v1(const char *key, size_t key_len,
                                   uint8_t out_mesh_id_hash[32],
                                   uint8_t out_owner_node_id[32]);

/** Encode the canonical RPC virtual-service payload. */
mesh_mgmt_service_record_result_t
mesh_mgmt_service_record_encode_v1(const mesh_mgmt_service_announcement_v1_t *announcement,
                                   uint8_t *output, size_t output_capacity,
                                   size_t *out_len);

/** Decode one exact canonical RPC virtual-service payload. */
mesh_mgmt_service_record_result_t
mesh_mgmt_service_record_decode_v1(const uint8_t *payload, size_t payload_len,
                                   mesh_mgmt_service_announcement_v1_t *out_announcement);

/**
 * Verify an untrusted signed service frame against direct enrollment trust.
 * The returned virtual service record is query data only and must never be
 * inserted into the physical transport endpoint pool.
 */
mesh_mgmt_service_record_result_t
mesh_mgmt_service_record_verify_v1(const mesh_mgmt_service_record_verify_input_v1_t *input,
                                   mesh_mgmt_service_record_v1_t *out_record);

#ifdef __cplusplus
}
#endif

#endif

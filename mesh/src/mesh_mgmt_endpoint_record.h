#ifndef TURBO_P2P_MESH_MGMT_ENDPOINT_RECORD_H
#define TURBO_P2P_MESH_MGMT_ENDPOINT_RECORD_H

#include "mesh_mgmt_endpoint_pool.h"
#include "mesh_mgmt_identity.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_ENDPOINT_RECORD_IPV4_V1_SIZE 120u
#define MESH_MGMT_ENDPOINT_RECORD_IPV6_V1_SIZE 132u
#define MESH_MGMT_ENDPOINT_RECORD_MAX_TTL_MS 86400000u
#define MESH_MGMT_ENDPOINT_DHT_KEY_V1_LENGTH 139u
#define MESH_MGMT_ENDPOINT_DHT_KEY_V1_SIZE 140u

typedef enum {
  MESH_MGMT_ENDPOINT_RECORD_OK = 0,
  MESH_MGMT_ENDPOINT_RECORD_INVALID_ARG = -1,
  MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA = -2,
  MESH_MGMT_ENDPOINT_RECORD_RESOURCE_EXHAUSTED = -3,
  MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED = -4,
  MESH_MGMT_ENDPOINT_RECORD_EXPIRED = -5,
  MESH_MGMT_ENDPOINT_RECORD_CRYPTO_FAILURE = -6,
  MESH_MGMT_ENDPOINT_RECORD_ADDRESS_FAILURE = -7,
} mesh_mgmt_endpoint_record_result_t;

typedef enum {
  MESH_MGMT_ENDPOINT_ADDRESS_IPV4 = 4,
  MESH_MGMT_ENDPOINT_ADDRESS_IPV6 = 6,
} mesh_mgmt_endpoint_address_family_t;

typedef struct {
  uint8_t owner_node_id[32];
  uint8_t transport_peer_id[P2P_KEY_SIZE];
  mesh_mgmt_endpoint_address_family_t address_family;
  uint8_t address[16];
  uint16_t port;
  uint64_t record_epoch;
  uint64_t expires_at_ms;
} mesh_mgmt_endpoint_announcement_v1_t;

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
} mesh_mgmt_endpoint_record_verify_input_v1_t;

/** Build the lowercase canonical mgmt:<mesh>:node:<node> DHT key. */
mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_dht_key_build_v1(const uint8_t mesh_id_hash[32], const uint8_t owner_node_id[32],
                                    char *output, size_t output_capacity, size_t *out_len);

/** Parse one exact lowercase canonical DHT key. Outputs are zeroed on failure. */
mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_dht_key_parse_v1(const char *key, size_t key_len, uint8_t out_mesh_id_hash[32],
                                    uint8_t out_owner_node_id[32]);

/** Encode the exact canonical endpoint SignedRecord payload. */
mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_record_encode_v1(const mesh_mgmt_endpoint_announcement_v1_t *announcement,
                                    uint8_t *output, size_t output_capacity, size_t *out_len);

/** Decode one exact payload. Output is zeroed on every failure. */
mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_record_decode_v1(const uint8_t *payload, size_t payload_len,
                                    mesh_mgmt_endpoint_announcement_v1_t *out_announcement);

/**
 * Verify an untrusted DHT frame and its enrollment certificate, bind the
 * envelope and payload to the DHT key's expected node, and produce the only
 * record type accepted by endpoint_pool_apply_verified. Output is zeroed on
 * failure. The certificate and frame remain caller-owned.
 */
mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_record_verify_v1(const mesh_mgmt_endpoint_record_verify_input_v1_t *input,
                                    mesh_mgmt_endpoint_record_v1_t *out_record);

#ifdef __cplusplus
}
#endif

#endif

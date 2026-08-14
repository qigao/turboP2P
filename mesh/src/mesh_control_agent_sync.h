#ifndef MESH_CONTROL_AGENT_SYNC_H
#define MESH_CONTROL_AGENT_SYNC_H

#include "mesh_control_primitives.h"
#include "mesh_mgmt_crypto.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_AGENT_SYNC_VERSION_V1 1u
#define MESH_CONTROL_AGENT_SYNC_HEADER_SIZE_V1 148u
#define MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1 184u
#define MESH_CONTROL_AGENT_SYNC_MAX_PAYLOAD_V1 \
  (MESH_CONTROL_MAX_FRAME_SIZE_V1 - MESH_CONTROL_AGENT_SYNC_HEADER_SIZE_V1)
#define MESH_CONTROL_AGENT_SYNC_NONCE_SIZE_V1 32u

typedef enum {
  MESH_CONTROL_AGENT_SYNC_OK = 0,
  MESH_CONTROL_AGENT_SYNC_INVALID_ARG = -1,
  MESH_CONTROL_AGENT_SYNC_INVALID_SCHEMA = -2,
  MESH_CONTROL_AGENT_SYNC_RESOURCE_EXHAUSTED = -3,
  MESH_CONTROL_AGENT_SYNC_DIGEST_MISMATCH = -4,
  MESH_CONTROL_AGENT_SYNC_AUTH_FAILED = -5,
  MESH_CONTROL_AGENT_SYNC_EXPIRED = -6,
  MESH_CONTROL_AGENT_SYNC_FENCED = -7
} mesh_control_agent_sync_result_t;

typedef enum {
  MESH_CONTROL_AGENT_SYNC_HELLO = 1,
  MESH_CONTROL_AGENT_SYNC_HELLO_ACK = 2,
  MESH_CONTROL_AGENT_SYNC_CLAIM_REQUEST = 3,
  MESH_CONTROL_AGENT_SYNC_COMMAND = 4,
  MESH_CONTROL_AGENT_SYNC_RECEIPT = 5,
  MESH_CONTROL_AGENT_SYNC_HEARTBEAT = 6,
  MESH_CONTROL_AGENT_SYNC_CLOSE = 7,
  MESH_CONTROL_AGENT_SYNC_ERROR = 8
} mesh_control_agent_sync_kind_v1_t;

/**
 * Transport-neutral message. payload is a borrowed view after decode. The
 * mTLS connection authenticates transport; node/session generations fence
 * application messages and COMMAND payloads remain signed MMP frames.
 */
typedef struct {
  mesh_control_agent_sync_kind_v1_t kind;
  uint32_t flags;
  int32_t status;
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t session_id[MESH_CONTROL_ID_SIZE];
  uint64_t session_generation;
  uint64_t request_token;
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint64_t lease_generation;
  uint64_t sent_at_ms;
  uint8_t payload_digest[MESH_CONTROL_DIGEST_SIZE];
  const uint8_t *payload;
  size_t payload_size;
} mesh_control_agent_sync_message_v1_t;

/** Canonical signed HELLO payload bound to the actual mTLS leaf certificate. */
typedef struct {
  uint64_t certificate_serial;
  uint64_t not_before_ms;
  uint64_t expires_at_ms;
  uint8_t nonce[MESH_CONTROL_AGENT_SYNC_NONCE_SIZE_V1];
  uint8_t tls_certificate_sha256[MESH_CONTROL_DIGEST_SIZE];
  uint8_t management_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t signature[MESH_MGMT_ED25519_SIGNATURE_SIZE];
} mesh_control_agent_sync_hello_v1_t;

typedef struct {
  uint8_t expected_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t expected_management_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t actual_tls_certificate_sha256[MESH_CONTROL_DIGEST_SIZE];
  uint64_t minimum_certificate_serial;
  uint64_t maximum_certificate_serial;
  /** Monotonic Controller identity-policy generation; zero is invalid. */
  uint64_t identity_policy_generation;
  uint64_t now_ms;
  uint64_t maximum_clock_skew_ms;
  uint64_t maximum_hello_lifetime_ms;
} mesh_control_agent_sync_hello_policy_v1_t;

mesh_control_agent_sync_result_t mesh_control_agent_sync_encode_v1(
    const mesh_control_agent_sync_message_v1_t *message, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_control_agent_sync_result_t mesh_control_agent_sync_decode_v1(
    const uint8_t *frame, size_t frame_size,
    mesh_control_agent_sync_message_v1_t *out_message);

/**
 * Builds and signs a HELLO payload. The private key is borrowed for this call
 * and is never retained. The caller supplies a cryptographically random,
 * nonzero nonce and the fingerprint obtained from its configured leaf cert.
 */
mesh_control_agent_sync_result_t mesh_control_agent_sync_hello_sign_v1(
    const mesh_control_agent_sync_message_v1_t *hello_message,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    mesh_control_agent_sync_hello_v1_t *hello);

mesh_control_agent_sync_result_t mesh_control_agent_sync_hello_encode_v1(
    const mesh_control_agent_sync_hello_v1_t *hello, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_control_agent_sync_result_t mesh_control_agent_sync_hello_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_control_agent_sync_hello_v1_t *out_hello);

/**
 * Verifies signature, time bounds, certificate serial, node/key registry
 * binding and equality with the TLS peer certificate observed by transport.
 */
mesh_control_agent_sync_result_t mesh_control_agent_sync_hello_verify_v1(
    const mesh_control_agent_sync_message_v1_t *hello_message,
    const mesh_control_agent_sync_hello_v1_t *hello,
    const mesh_control_agent_sync_hello_policy_v1_t *policy);

#ifdef __cplusplus
}
#endif

#endif

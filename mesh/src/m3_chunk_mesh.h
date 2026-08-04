#ifndef M3_CHUNK_MESH_H
#define M3_CHUNK_MESH_H

#include "m3_store_node.h"
#include "p2p.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The p2p message frame carries at most 65536 bytes; keep the chunk payload
 * well below that after the frame header, canonical claims and signature. */
#define M3_CHUNK_MESH_MAX_PAYLOAD 61440u
#define M3_CHUNK_MESH_FRAME_MAX (M3_CHUNK_MESH_MAX_PAYLOAD + 512u)
#define M3_CHUNK_MESH_CLAIMS_SIZE 168u
#define M3_CHUNK_MESH_SIGNATURE_SIZE 64u
#define M3_CHUNK_MESH_SIGNER_KEY_SIZE 32u
#define M3_CHUNK_MESH_CHANNEL_KEY_SIZE 32u
#define M3_CHUNK_MESH_MAX_TRUSTED_KEYS 8u

typedef enum {
  M3_CHUNK_MESH_OK = 0,
  M3_CHUNK_MESH_INVALID_ARG = -1,
  M3_CHUNK_MESH_CORRUPT = -2,
  M3_CHUNK_MESH_AUTH_FAILED = -3,
  M3_CHUNK_MESH_RESOURCE_EXHAUSTED = -4,
  M3_CHUNK_MESH_NETWORK = -5,
  M3_CHUNK_MESH_TIMEOUT = -6,
  M3_CHUNK_MESH_STORE_ERROR = -7,
  M3_CHUNK_MESH_NOT_READY = -8,
  M3_CHUNK_MESH_OVERFLOW = -9,
} m3_chunk_mesh_result_t;

typedef enum {
  M3_CHUNK_MESH_OP_PUT = 1,
  M3_CHUNK_MESH_OP_GET = 2,
} m3_chunk_mesh_operation_t;

typedef enum {
  M3_CHUNK_MESH_FRAME_REQUEST = 1,
  M3_CHUNK_MESH_FRAME_RESPONSE = 2,
} m3_chunk_mesh_frame_type_t;

/* ---- wire codec --------------------------------------------------------- */

/** Canonical big-endian claims encoding (168 bytes). */
m3_chunk_mesh_result_t m3_chunk_mesh_claims_encode_v1(
    const m3_chunk_capability_claims_v1_t *claims,
    uint8_t out[M3_CHUNK_MESH_CLAIMS_SIZE]);
m3_chunk_mesh_result_t m3_chunk_mesh_claims_decode_v1(
    const uint8_t bytes[M3_CHUNK_MESH_CLAIMS_SIZE],
    m3_chunk_capability_claims_v1_t *out_claims);
/** Ed25519 signature of the gateway over the canonical claims. */
m3_chunk_mesh_result_t m3_chunk_mesh_claims_sign_v1(
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    const m3_chunk_capability_claims_v1_t *claims,
    uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE]);
m3_chunk_mesh_result_t m3_chunk_mesh_claims_verify_v1(
    const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const m3_chunk_capability_claims_v1_t *claims,
    const uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE]);

/**
 * Encode one request/response frame. channel_public_key is the gateway's
 * p2p X25519 identity and signer_public_key its Ed25519 capability key;
 * the store binds the signer to the authenticated channel and to an
 * allowlisted key. status is the response result code (M3_CHUNK_MESH_OK on
 * success, otherwise a m3_store_node_result_t or m3_chunk_mesh_result_t).
 * Returns M3_CHUNK_MESH_OVERFLOW when the payload does not fit the p2p cap.
 */
m3_chunk_mesh_result_t m3_chunk_mesh_frame_encode_v1(
    m3_chunk_mesh_frame_type_t type, m3_chunk_mesh_operation_t operation,
    int32_t status, const uint8_t correlation_id[16],
    const uint8_t claims[M3_CHUNK_MESH_CLAIMS_SIZE],
    const uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE],
    const uint8_t channel_public_key[M3_CHUNK_MESH_CHANNEL_KEY_SIZE],
    const uint8_t signer_public_key[M3_CHUNK_MESH_SIGNER_KEY_SIZE],
    const uint8_t *payload, size_t payload_len, uint8_t *out_frame,
    size_t frame_cap, size_t *out_frame_size);

/** Decode a frame; claims/signature/keys/payload borrow the input bytes. */
m3_chunk_mesh_result_t m3_chunk_mesh_frame_decode_v1(
    const uint8_t *frame, size_t frame_size, m3_chunk_mesh_frame_type_t *out_type,
    m3_chunk_mesh_operation_t *out_operation, int32_t *out_status,
    uint8_t correlation_id[16], const uint8_t **out_claims,
    const uint8_t **out_signature,
    const uint8_t **out_channel_public_key,
    const uint8_t **out_signer_public_key, const uint8_t **out_payload,
    size_t *out_payload_len);

/* ---- store-side service -------------------------------------------------- */

/**
 * Authenticated chunk service over one p2p node. It verifies the capability
 * signature against an allowlisted gateway Ed25519 key and binds the signer
 * to the authenticated p2p channel (X25519 peer identity), then authorizes
 * against this store node's audience, executes PUT/READ and replies on the
 * same peer link. The node loop must be pumped externally.
 */
typedef struct {
  p2p_node_t *node;
  m3_store_node_v1_t *store;
  uint8_t trusted_keys[M3_CHUNK_MESH_MAX_TRUSTED_KEYS][M3_CHUNK_MESH_SIGNER_KEY_SIZE];
  size_t trusted_count;
} m3_chunk_mesh_service_v1_t;

m3_chunk_mesh_result_t m3_chunk_mesh_service_init_v1(
    m3_chunk_mesh_service_v1_t *service, p2p_node_t *node,
    m3_store_node_v1_t *store);
m3_chunk_mesh_result_t m3_chunk_mesh_service_add_trusted_key_v1(
    m3_chunk_mesh_service_v1_t *service,
    const uint8_t signer_public_key[M3_CHUNK_MESH_SIGNER_KEY_SIZE]);
void m3_chunk_mesh_service_destroy_v1(m3_chunk_mesh_service_v1_t *service);

/* ---- gateway-side client ------------------------------------------------- */

typedef struct m3_chunk_mesh_client_s {
  p2p_node_t *node;
  p2p_peer_t *peer;
  char host[128];
  int port;
  uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE];
  uint8_t store_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t pending_correlation[16];
  uint8_t *response_storage;
  size_t response_storage_cap;
  size_t response_len;
  m3_chunk_receipt_v1_t receipt;
  int done;
  int status;
  struct m3_chunk_mesh_client_s *next;
} m3_chunk_mesh_client_v1_t;

/**
 * Response router installed on the gateway's p2p node. It routes response
 * frames to the matching pending client. The node loop must be pumped
 * externally; the synchronous client calls sleep-poll their completion.
 */
typedef struct {
  p2p_node_t *node;
  m3_chunk_mesh_client_v1_t *clients;
} m3_chunk_mesh_router_v1_t;

m3_chunk_mesh_result_t m3_chunk_mesh_router_init_v1(
    m3_chunk_mesh_router_v1_t *router, p2p_node_t *node);
void m3_chunk_mesh_router_destroy_v1(m3_chunk_mesh_router_v1_t *router);
m3_chunk_mesh_result_t m3_chunk_mesh_router_add_client_v1(
    m3_chunk_mesh_router_v1_t *router, m3_chunk_mesh_client_v1_t *client);

/** Zero-init the client, allocate response storage and dial the store. */
m3_chunk_mesh_result_t m3_chunk_mesh_client_connect_v1(
    m3_chunk_mesh_client_v1_t *client, p2p_node_t *node,
    const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
    const uint8_t store_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const char *host, int port);
void m3_chunk_mesh_client_destroy_v1(m3_chunk_mesh_client_v1_t *client);

/**
 * Synchronous PUT/GET over the peer link. The p2p node loop must be pumped
 * externally (background thread or harness); these calls sleep-poll the
 * response until timeout_ms. PUT returns the store's signed receipt; GET
 * returns the requested range bytes.
 */
m3_chunk_mesh_result_t m3_chunk_mesh_client_put_v1(
    m3_chunk_mesh_client_v1_t *client,
    const m3_chunk_capability_claims_v1_t *claims,
    const uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE],
    const uint8_t signer_public_key[M3_CHUNK_MESH_SIGNER_KEY_SIZE],
    const uint8_t *bytes, size_t size, uint64_t timeout_ms,
    m3_chunk_receipt_v1_t *out_receipt);
m3_chunk_mesh_result_t m3_chunk_mesh_client_get_v1(
    m3_chunk_mesh_client_v1_t *client,
    const m3_chunk_capability_claims_v1_t *claims,
    const uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE],
    const uint8_t signer_public_key[M3_CHUNK_MESH_SIGNER_KEY_SIZE],
    uint8_t *buffer, size_t buffer_size, size_t *out_read, uint64_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif

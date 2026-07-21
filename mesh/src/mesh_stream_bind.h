#ifndef TURBO_P2P_MESH_STREAM_BIND_H
#define TURBO_P2P_MESH_STREAM_BIND_H

#include "mesh_mgmt_crypto.h"
#include "mesh_stream_codec.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_STREAM_BIND_ID_SIZE 32u
#define MESH_STREAM_BIND_NODE_ID_SIZE 32u
#define MESH_STREAM_BIND_CHANNEL_BINDING_SIZE 32u
#define MESH_STREAM_BIND_NONCE_SIZE 32u
#define MESH_STREAM_BIND_MAX_TICKETS 4096u
#define MESH_STREAM_BIND_MAX_TTL_MS 60000u

#define MESH_STREAM_BIND_INIT_SIZE 368u
#define MESH_STREAM_BIND_ACCEPT_SIZE 232u
#define MESH_STREAM_BIND_CONFIRM_SIZE 200u

typedef enum {
  MESH_STREAM_BIND_OK = 0,
  MESH_STREAM_BIND_INVALID_ARG = -1,
  MESH_STREAM_BIND_INVALID_STATE = -2,
  MESH_STREAM_BIND_RESOURCE_EXHAUSTED = -3,
  MESH_STREAM_BIND_RANDOM_FAILURE = -4,
  MESH_STREAM_BIND_CRYPTO_FAILURE = -5,
  MESH_STREAM_BIND_AUTH_FAILED = -6,
  MESH_STREAM_BIND_NOT_FOUND = -7,
  MESH_STREAM_BIND_EXPIRED = -8,
  MESH_STREAM_BIND_REPLAY = -9,
  MESH_STREAM_BIND_CHANNEL_MISMATCH = -10,
  MESH_STREAM_BIND_INVALID_FRAME = -11,
  MESH_STREAM_BIND_TLS_REQUIRED = -12,
  MESH_STREAM_BIND_CHANNEL_EXPORT_FAILED = -13,
  MESH_STREAM_BIND_IO_FAILED = -14,
} mesh_stream_bind_result_t;

typedef struct {
  uint8_t mesh_id_hash[32];
  uint8_t initiator_node_id[MESH_STREAM_BIND_NODE_ID_SIZE];
  uint8_t initiator_principal_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t responder_node_id[MESH_STREAM_BIND_NODE_ID_SIZE];
  uint8_t responder_principal_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t stream_id[MESH_STREAM_ID_SIZE];
  uint64_t stream_epoch;
  uint64_t admission_generation;
} mesh_stream_bind_claims_v1_t;

/**
 * One-time authorization created by the responder and delivered through the
 * authenticated management channel. The random ID is not a bearer secret:
 * use also requires the expected initiator signature.
 */
typedef struct {
  uint8_t ticket_id[MESH_STREAM_BIND_ID_SIZE];
  mesh_stream_bind_claims_v1_t claims;
  uint64_t issued_at_ms;
  uint64_t expires_at_ms;
} mesh_stream_bind_ticket_v1_t;

typedef struct {
  size_t capacity;
  uint64_t max_ttl_ms;
} mesh_stream_bind_store_config_v1_t;

typedef enum {
  MESH_STREAM_BIND_TICKET_FREE = 0,
  MESH_STREAM_BIND_TICKET_ISSUED = 1,
  MESH_STREAM_BIND_TICKET_CHALLENGE = 2,
  MESH_STREAM_BIND_TICKET_CONSUMED = 3,
} mesh_stream_bind_ticket_state_t;

typedef struct {
  mesh_stream_bind_ticket_v1_t ticket;
  uint8_t init_hash[32];
  uint8_t accept_hash[32];
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  mesh_stream_bind_ticket_state_t state;
} mesh_stream_bind_store_entry_v1_t;

/** Single-owner, fixed-capacity responder ticket fact source. */
typedef struct {
  mesh_stream_bind_store_entry_v1_t *entries;
  size_t capacity;
  uint64_t max_ttl_ms;
} mesh_stream_bind_store_v1_t;

typedef enum {
  MESH_STREAM_BIND_INITIATOR_UNINITIALIZED = 0,
  MESH_STREAM_BIND_INITIATOR_STARTED = 1,
  MESH_STREAM_BIND_INITIATOR_CONFIRM_READY = 2,
} mesh_stream_bind_initiator_state_t;

typedef struct {
  mesh_stream_bind_ticket_v1_t ticket;
  uint8_t init_hash[32];
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  mesh_stream_bind_initiator_state_t state;
} mesh_stream_bind_initiator_v1_t;

mesh_stream_bind_result_t
mesh_stream_bind_store_init_v1(mesh_stream_bind_store_v1_t *store,
                               const mesh_stream_bind_store_config_v1_t *config);

void mesh_stream_bind_store_destroy_v1(mesh_stream_bind_store_v1_t *store);

mesh_stream_bind_result_t
mesh_stream_bind_ticket_issue_v1(mesh_stream_bind_store_v1_t *store,
                                 const mesh_stream_bind_claims_v1_t *claims, uint64_t now_ms,
                                 uint64_t ttl_ms, mesh_stream_bind_ticket_v1_t *out_ticket);

size_t mesh_stream_bind_ticket_sweep_v1(mesh_stream_bind_store_v1_t *store, uint64_t now_ms);

mesh_stream_bind_result_t
mesh_stream_bind_ticket_invalidate_v1(mesh_stream_bind_store_v1_t *store,
                                      const uint8_t ticket_id[MESH_STREAM_BIND_ID_SIZE],
                                      uint64_t now_ms);

/** Invalidate the ticket named by a structurally valid INIT after send/I/O ambiguity. */
mesh_stream_bind_result_t
mesh_stream_bind_responder_abort_init_v1(mesh_stream_bind_store_v1_t *store,
                                         const uint8_t *input, size_t input_len,
                                         uint64_t now_ms);

mesh_stream_bind_result_t mesh_stream_bind_initiator_start_v1(
    mesh_stream_bind_initiator_v1_t *initiator, const mesh_stream_bind_ticket_v1_t *ticket,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    const uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE],
    uint8_t output[MESH_STREAM_BIND_INIT_SIZE]);

mesh_stream_bind_result_t mesh_stream_bind_responder_accept_v1(
    mesh_stream_bind_store_v1_t *store, const uint8_t *input, size_t input_len,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    const uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE], uint64_t now_ms,
    uint8_t output[MESH_STREAM_BIND_ACCEPT_SIZE]);

mesh_stream_bind_result_t
mesh_stream_bind_initiator_confirm_v1(mesh_stream_bind_initiator_v1_t *initiator,
                                      const uint8_t *input, size_t input_len,
                                      const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
                                      const uint8_t channel_binding
                                          [MESH_STREAM_BIND_CHANNEL_BINDING_SIZE],
                                      uint8_t output[MESH_STREAM_BIND_CONFIRM_SIZE]);

mesh_stream_bind_result_t
mesh_stream_bind_responder_finish_v1(mesh_stream_bind_store_v1_t *store, const uint8_t *input,
                                     size_t input_len,
                                     const uint8_t channel_binding
                                         [MESH_STREAM_BIND_CHANNEL_BINDING_SIZE],
                                     uint64_t now_ms,
                                     mesh_stream_bind_ticket_v1_t *out_ticket);

#ifdef __cplusplus
}
#endif

#endif

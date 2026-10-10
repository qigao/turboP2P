#ifndef MESH_MGMT_EXECUTION_SENDER_H
#define MESH_MGMT_EXECUTION_SENDER_H

#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_connection.h"
#include "mesh_mgmt_execution_egress.h"
#include "mesh_mgmt_peer_signer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum mesh_mgmt_execution_sender_result {
  MESH_MGMT_EXECUTION_SENDER_OK = 0,
  MESH_MGMT_EXECUTION_SENDER_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_SENDER_EMPTY = -2,
  MESH_MGMT_EXECUTION_SENDER_TARGET_MISMATCH = -3,
  MESH_MGMT_EXECUTION_SENDER_UNSUPPORTED_RESULT = -4,
  MESH_MGMT_EXECUTION_SENDER_SIGN_FAILED = -5,
  MESH_MGMT_EXECUTION_SENDER_SEND_FAILED = -6,
  MESH_MGMT_EXECUTION_SENDER_COMMIT_FAILED = -7,
  MESH_MGMT_EXECUTION_SENDER_ENCODE_FAILED = -8,
  /* Admission has happened, but native CNet has NOT issued the terminal. */
  MESH_MGMT_EXECUTION_SENDER_IN_FLIGHT = -9,
  /* Native response write has definitively failed; no implicit replay. */
  MESH_MGMT_EXECUTION_SENDER_TERMINAL_FAILED = -10
} mesh_mgmt_execution_sender_result_t;

/* Exactly one retained Egress head, owned by the same MMP runtime thread
 * that drives native CNet progression. No additional Queue/Pool or polling
 * authority. Never move/copy this state while a terminal is outstanding. */
typedef enum {
  MESH_MGMT_EXECUTION_SEND_IDLE = 0,
  MESH_MGMT_EXECUTION_SEND_IN_FLIGHT,
  MESH_MGMT_EXECUTION_SEND_WIRE_OK,
  MESH_MGMT_EXECUTION_SEND_WIRE_FAILED,
  MESH_MGMT_EXECUTION_SEND_ADMISSION_FAILED
} mesh_mgmt_execution_send_state_v5_t;

typedef struct {
  mesh_mgmt_execution_egress_v1_t *egress; /* borrowed through callback */
  mesh_mgmt_agent_runtime_v1_t *runtime;  /* borrowed through callback */
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  mesh_mgmt_execution_send_state_v5_t state;
  uint64_t ticket;
  uint64_t last_terminal_ticket;
  int terminal_status; /* exact P2P native terminal code, not remote ACK */
} mesh_mgmt_execution_sender_pending_v5_t;

/*
 * Event-loop-only transactional send. The egress head is consumed only after
 * the connection synchronously accepts the signed frame.
 */
mesh_mgmt_execution_sender_result_t mesh_mgmt_execution_sender_send_next_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_peer_signer_v1_t *signer,
    mesh_mgmt_connection_v1_t *connection);

/**
 * Send one production Worker RESULT or STATUS via the unique authenticated
 * MMP runtime session. Admission merely creates a retained native CNet write
 * continuation and returns IN_FLIGHT; another owner turn commits exactly one
 * Egress head ONLY after the original wire completion returned P2P_OK.
 *
 * On rejected admission or failed native terminal, the Egress head is kept
 * and this sender remains in a terminal FAILED state. Never auto-resend:
 * Noise's nonce and the authenticated physical generation may have changed.
 * Owner must first arrange an explicit higher-level reconciliation.
 *
 * pending is address-stable until the callback has returned; Runtime checked
 * Stop/Destroy cannot succeed while its native callback is outstanding.
 * This is NOT proof the remote requester received or ACKed the result.
 */
mesh_mgmt_execution_sender_result_t
mesh_mgmt_execution_sender_send_next_runtime_v5(
    mesh_mgmt_execution_sender_pending_v5_t *pending,
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_agent_runtime_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif

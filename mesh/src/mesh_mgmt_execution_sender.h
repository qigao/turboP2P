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
  MESH_MGMT_EXECUTION_SENDER_ENCODE_FAILED = -8
} mesh_mgmt_execution_sender_result_t;

/*
 * Event-loop-only transactional send. The egress head is consumed only after
 * the connection synchronously accepts the signed frame.
 */
mesh_mgmt_execution_sender_result_t mesh_mgmt_execution_sender_send_next_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_peer_signer_v1_t *signer,
    mesh_mgmt_connection_v1_t *connection);

/**
 * Event-loop-only transactional send through the unique authenticated runtime
 * session for the egress target node. A failed send leaves the queue head
 * available for retry.
 */
mesh_mgmt_execution_sender_result_t
mesh_mgmt_execution_sender_send_next_runtime_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_agent_runtime_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif

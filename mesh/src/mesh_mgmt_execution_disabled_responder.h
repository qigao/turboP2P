#ifndef MESH_MGMT_EXECUTION_DISABLED_RESPONDER_H
#define MESH_MGMT_EXECUTION_DISABLED_RESPONDER_H

#include "mesh_mgmt_connection.h"
#include "mesh_mgmt_execution_consumer.h"
#include "mesh_mgmt_peer_signer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_EXECUTION_DISABLED_RESPONDER_OK = 0,
  MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_STATE = -2,
  MESH_MGMT_EXECUTION_DISABLED_RESPONDER_CONSUMER_FAILED = -3,
  MESH_MGMT_EXECUTION_DISABLED_RESPONDER_TARGET_MISMATCH = -4,
  MESH_MGMT_EXECUTION_DISABLED_RESPONDER_ENCODE_FAILED = -5,
  MESH_MGMT_EXECUTION_DISABLED_RESPONDER_SIGN_FAILED = -6,
  MESH_MGMT_EXECUTION_DISABLED_RESPONDER_SEND_FAILED = -7
} mesh_mgmt_execution_disabled_responder_result_t;

/**
 * Builds the immutable COMMAND_STATUS fields for a verified shadow command.
 * The caller still owns transport/session identity checks.
 */
mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_execution_disabled_status_from_command_v1(
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    mesh_mgmt_execution_status_v1_t *out_status);

/**
 * Binds a status to an already verified command and sends it synchronously
 * through the same authenticated connection that supplied the command.
 */
mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_execution_status_response_from_command_v1(
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    uint16_t status_code,
    mesh_mgmt_peer_signer_v1_t *signer,
    mesh_mgmt_connection_v1_t *connection);

/**
 * Revalidates an inbound request event, binds STATUS_DISABLED to the request,
 * signs it with the connected peer signer, and synchronously sends it back
 * through the same authenticated connection.
 */
mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_execution_disabled_response_from_event_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms,
    mesh_mgmt_peer_signer_v1_t *signer,
    mesh_mgmt_connection_v1_t *connection);

#ifdef __cplusplus
}
#endif

#endif

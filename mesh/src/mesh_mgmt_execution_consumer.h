#ifndef TURBO_P2P_MESH_MGMT_EXECUTION_CONSUMER_H
#define TURBO_P2P_MESH_MGMT_EXECUTION_CONSUMER_H

#include "mesh_mgmt_dispatch.h"
#include "mesh_mgmt_execution_wire.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_EXECUTION_CONSUMER_OK = 0,
  MESH_MGMT_EXECUTION_CONSUMER_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_CONSUMER_INVALID_SCHEMA = -2,
  MESH_MGMT_EXECUTION_CONSUMER_AUTH_FAILED = -3,
  MESH_MGMT_EXECUTION_CONSUMER_EXPIRED = -4,
  MESH_MGMT_EXECUTION_CONSUMER_UNSUPPORTED_FEATURE = -5,
  MESH_MGMT_EXECUTION_CONSUMER_INVALID_STATE = -6,
  MESH_MGMT_EXECUTION_CONSUMER_CRYPTO_FAILED = -7,
} mesh_mgmt_execution_consumer_result_t;

typedef struct {
  mesh_mgmt_execution_grant_v1_t grant;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_lease_proof_v2_t lease_proof;
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t reply_node_id[32];
  uint16_t command_version;
} mesh_mgmt_execution_shadow_command_v1_t;

/**
 * Convert one borrowed shadow event into an owned typed command. This function
 * revalidates the session and Grant but performs no journal write, callback,
 * runtime invocation, or other external side effect.
 */
mesh_mgmt_execution_consumer_result_t
mesh_mgmt_execution_shadow_command_from_event_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms,
    mesh_mgmt_execution_shadow_command_v1_t *out_command);

#ifdef __cplusplus
}
#endif

#endif

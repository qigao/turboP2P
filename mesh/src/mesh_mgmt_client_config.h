#ifndef TURBOP2P_MESH_MGMT_CLIENT_CONFIG_H
#define TURBOP2P_MESH_MGMT_CLIENT_CONFIG_H

#include "mesh_mgmt_endpoint_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_CLIENT_CONFIG_MAX_BYTES 4096u

typedef enum {
  MESH_MGMT_CLIENT_CONFIG_OK = 0,
  MESH_MGMT_CLIENT_CONFIG_INVALID_ARG = -1,
  MESH_MGMT_CLIENT_CONFIG_SCHEMA_FAILED = -2,
  MESH_MGMT_CLIENT_CONFIG_RECORD_FAILED = -3,
  MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID = -4,
} mesh_mgmt_client_config_result_t;

/** Application-level ACE Configurator admission, never a CNet parser.
 * Parses one strictly typed, versioned DataBind 4.3 JSON record against a
 * trusted compiled schema and immutable ValidationPlan. Unknown fields and
 * scalar coercion fail. The output contains no borrowed DataBind storage;
 * all codec/record/plan leases end before this call returns.
 *
 * Required JSON shape:
 * {"schema_version":1,"kind":"ROUND_ROBIN","key_hash":0,
 *  "transport_peer_id":""}
 * kind=EXPLICIT requires lowercase 64-hex peer id and zero key_hash.
 * kind=STRICT_KEY requires empty peer id (zero key_hash is permitted).
 * Configuration cannot change Owner or retry state; pass it once to
 * mesh_mgmt_agent_runtime_set_client_policy_v2 before runtime start.
 * Failure clears the complete output, never committing a partial policy. */
mesh_mgmt_client_config_result_t mesh_mgmt_client_policy_from_json_v1(
    const char *json, size_t json_length,
    mesh_mgmt_client_destination_policy_v2_t *out_policy);

#ifdef __cplusplus
}
#endif

#endif

#ifndef MESH_MGMT_SERVICE_COMPONENT_RUNTIME_H
#define MESH_MGMT_SERVICE_COMPONENT_RUNTIME_H

#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_service_component.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Admission/control-plane call on the agent Owner. The bound view's scope
 * must remain live until return. Provider metadata supplies service data only;
 * the existing agent signer/trust/epoch and P2P/CNet owners perform publication.
 * No provider pointer survives into an asynchronous transport callback. Returns
 * the existing runtime errors; provider/scope rejection is INVALID_ARG and
 * leaves out_record_epoch=0 without signing, allocating an epoch or sending. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_publish_component_service_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_service_component_view_v1_t *view, uint64_t *out_record_epoch);
#ifdef __cplusplus
}
#endif
#endif

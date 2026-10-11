#ifndef MESHD_RPC_SERVICE_COMPONENT_H
#define MESHD_RPC_SERVICE_COMPONENT_H

#include "mesh_mgmt_service_component_runtime.h"
#include <salts/thread.h>
#include <vstr.h>

#define MESHD_MGMT_SERVICE_PUBLISH_INTERVAL_MS UINT64_C(10000)

/* Concrete meshd Owner for one built-in RPC service. Initialize to zero and
 * keep address-stable/noncopyable on the daemon Owner thread. SDK runtime,
 * generation and scope are the lifecycle facts; no mirrored lease counts or
 * module loader. One immutable config allocation is owned by Component.
 * Config input may expire after init; publish retains no agent or payload. */
typedef struct {
  cmeta_thread_affine_state affinity;
  salts_component_plugin_runtime runtime;
  salts_component_plugin_generation generation;
  salts_component_plugin_scope scope;
  mesh_mgmt_service_component_view_v1_t view;
  salts_component_deployment deployments[1];
  salts_component_instance instances[1];
  size_t order[1];
  uint64_t last_refresh_attempt_ms;
  bool refresh_attempted;
} meshd_rpc_service_component_t;
#define MESHD_RPC_SERVICE_COMPONENT_INIT {0}

#ifdef __cplusplus
extern "C" {
#endif
/* No signing/network I/O. Rejects live reinit. Returns SDK admission errors;
 * failure rolls back, or retains storage if cleanup itself fails. */
salts_component_plugin_status meshd_rpc_service_component_init(
    meshd_rpc_service_component_t *owner, const mesh_mgmt_service_config_v1_t *config);

/* Admit meshd's native fixed-capacity IPv4/virtual-host fields. Each view covers
 * readable storage containing a NUL terminator; bytes after it are ignored.
 * Storage is borrowed only during this call and may be changed/freed afterward.
 * The exact textual IP host is encoded as empty DNS, as in the existing daemon.
 * Reject missing terminators, invalid IPv4 and canonical service violations
 * without publishing or reserving an epoch. Existing live Owners are preserved.
 * Returns INVALID_ARGUMENT for storage/IP/zero-port errors, INVALID_STATE for
 * a live Owner, and init's SDK status for Component policy/admission failures.
 * Cleanup failure retains the Owner storage under the same init contract.
 * IPv4 parsing uses the same native inet_pton boundary as meshd; policy and
 * config ownership remain with the existing Component admission. */
salts_component_plugin_status meshd_rpc_service_component_init_native(
    meshd_rpc_service_component_t *owner, vstr virtual_ip_storage,
    vstr virtual_host_storage, uint16_t port);

/* Synchronous publication/refresh on the agent Owner with its existing signer
 * and durable epoch allocator. Rejects withdrawn/uninitialized Owners without
 * advancing an epoch. Output is zero on failure. */
mesh_mgmt_agent_runtime_result_t meshd_rpc_service_component_publish(
    meshd_rpc_service_component_t *owner, mesh_mgmt_agent_runtime_v1_t *agent,
    uint64_t *out_record_epoch);

/* Called by the existing daemon loop with its monotonic millisecond clock.
 * First call publishes immediately; subsequent attempts are at least 10 seconds
 * after the previous attempt returned, including failed attempts. Late polling
 * emits at most one record. The clock is borrowed only for this call, must be
 * nondecreasing, and is sampled again after publication to preserve meshd's
 * completion-based cadence even when synchronous storage/signing is slow.
 * OK with epoch zero means not due: no signer/epoch/network call occurred.
 * A backward sample is INVALID_ARG and preserves the retry deadline. Copied,
 * foreign-thread, withdrawn or reentrant Owners are rejected even when not due.
 * This stores cadence only; it creates no timer, callback or agent ownership.
 * Unconditional publish above does not change the refresh cadence. */
mesh_mgmt_agent_runtime_result_t meshd_rpc_service_component_refresh(
    meshd_rpc_service_component_t *owner, mesh_mgmt_agent_runtime_v1_t *agent,
    uint64_t (*clock_ms)(void), uint64_t *out_record_epoch);

/* Close admission, release the Owner's borrowed view/scope, drain objects then
 * destroy runtime. Idempotent after success. BUSY from additional live scopes
 * preserves generation/runtime storage for retry; callers must not reset/free
 * it. Additional scopes must be released before final destruction. Callback
 * reentry during publish returns BUSY; foreign Owner threads are rejected. */
salts_component_plugin_status meshd_rpc_service_component_destroy(
    meshd_rpc_service_component_t *owner);
#ifdef __cplusplus
}
#endif
#endif

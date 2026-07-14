#ifndef MESH_RUNTIME_HEALTH_H
#define MESH_RUNTIME_HEALTH_H

#include <turbo_mesh.h>

typedef enum {
    MESH_RUNTIME_HEALTH_HEALTHY = 0,
    MESH_RUNTIME_HEALTH_DEGRADED,
    MESH_RUNTIME_HEALTH_UNHEALTHY,
} mesh_runtime_health_state_t;

typedef enum {
    MESH_RUNTIME_HEALTH_REASON_NONE = 0,
    MESH_RUNTIME_HEALTH_REASON_DIRECT_ONLY,
    MESH_RUNTIME_HEALTH_REASON_HYBRID,
    MESH_RUNTIME_HEALTH_REASON_RELAY_ONLY,
    MESH_RUNTIME_HEALTH_REASON_DIRECT_UPGRADE_PENDING,
    MESH_RUNTIME_HEALTH_REASON_BOOTSTRAP_RECONNECT_PENDING,
    MESH_RUNTIME_HEALTH_REASON_AWAITING_PEERS,
    MESH_RUNTIME_HEALTH_REASON_STARTING,
    MESH_RUNTIME_HEALTH_REASON_NO_CONNECTED_PATH,
    MESH_RUNTIME_HEALTH_REASON_BOOTSTRAP_UNREACHABLE,
} mesh_runtime_health_reason_t;

typedef struct {
    mesh_runtime_health_state_t state;
    mesh_runtime_health_reason_t reason;
    mesh_path_mode_t path_mode;
    int bootstrap_configured;
    int bootstrap_reconnect_pending;
    int has_direct_peer;
    int has_relay_path;
    int has_any_path;
    int ice_enabled;
    int ice_progressing;
    int ice_failed;
} mesh_runtime_health_t;

int mesh_runtime_health_eval(mesh_network_t *mesh,
                             int bootstrap_count,
                             mesh_runtime_health_t *out);

const char *mesh_runtime_health_state_string(mesh_runtime_health_state_t state);
const char *mesh_runtime_health_reason_string(mesh_runtime_health_reason_t reason);
const char *mesh_runtime_health_summary(const mesh_runtime_health_t *health);

#endif

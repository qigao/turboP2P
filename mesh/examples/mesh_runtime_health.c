#include "mesh_runtime_health.h"

#include <string.h>

static int mesh_runtime_health_ice_progressing(const mesh_diag_info_t *diag) {
    if (!diag || !diag->ice_enabled || diag->ice_peer_count == 0) {
        return 0;
    }

    return strcmp(diag->last_ice_state, "NEW") == 0 ||
           strcmp(diag->last_ice_state, "GATHERING") == 0 ||
           strcmp(diag->last_ice_state, "CONNECTING") == 0;
}

static int mesh_runtime_health_ice_failed(const mesh_diag_info_t *diag) {
    if (!diag || !diag->ice_enabled || diag->ice_peer_count == 0) {
        return 0;
    }

    return strcmp(diag->last_ice_state, "FAILED") == 0 ||
           strcmp(diag->last_ice_state, "DISCONNECTED") == 0 ||
           strcmp(diag->last_ice_state, "CLOSED") == 0;
}

int mesh_runtime_health_eval(mesh_network_t *mesh,
                             int bootstrap_count,
                             mesh_runtime_health_t *out) {
    mesh_diag_info_t diag;

    if (!mesh || !out) {
        return -1;
    }

    memset(&diag, 0, sizeof(diag));
    memset(out, 0, sizeof(*out));
    out->state = MESH_RUNTIME_HEALTH_UNHEALTHY;
    out->reason = MESH_RUNTIME_HEALTH_REASON_NO_CONNECTED_PATH;

    if (mesh_get_diag_info(mesh, &diag) != MESH_OK) {
        return -1;
    }

    out->path_mode = diag.path_mode;
    out->bootstrap_configured = bootstrap_count > 0;
    out->bootstrap_reconnect_pending = diag.bootstrap_reconnect_pending;
    out->has_direct_peer = diag.direct_peer_count > 0;
    out->has_relay_path = diag.connected_relay_route_count > 0;
    out->has_any_path = out->has_direct_peer || out->has_relay_path;
    out->ice_enabled = diag.ice_enabled;
    out->ice_progressing = mesh_runtime_health_ice_progressing(&diag);
    out->ice_failed = mesh_runtime_health_ice_failed(&diag);

    if (out->has_direct_peer) {
        if (diag.bootstrap_reconnect_pending) {
            out->state = MESH_RUNTIME_HEALTH_DEGRADED;
            out->reason = MESH_RUNTIME_HEALTH_REASON_BOOTSTRAP_RECONNECT_PENDING;
            return 0;
        }

        out->state = MESH_RUNTIME_HEALTH_HEALTHY;
        out->reason = out->has_relay_path ? MESH_RUNTIME_HEALTH_REASON_HYBRID
                                          : MESH_RUNTIME_HEALTH_REASON_DIRECT_ONLY;
        return 0;
    }

    if (out->has_relay_path) {
        out->state = MESH_RUNTIME_HEALTH_DEGRADED;
        out->reason = (out->ice_enabled && out->ice_progressing)
                          ? MESH_RUNTIME_HEALTH_REASON_DIRECT_UPGRADE_PENDING
                          : MESH_RUNTIME_HEALTH_REASON_RELAY_ONLY;
        return 0;
    }

    if (!out->bootstrap_configured) {
        out->state = MESH_RUNTIME_HEALTH_DEGRADED;
        out->reason = MESH_RUNTIME_HEALTH_REASON_AWAITING_PEERS;
        return 0;
    }

    if (diag.bootstrap_retry_rounds == 0 &&
        !diag.bootstrap_reconnect_pending &&
        diag.peer_connect_events == 0 &&
        diag.peer_disconnect_events == 0) {
        out->state = MESH_RUNTIME_HEALTH_DEGRADED;
        out->reason = MESH_RUNTIME_HEALTH_REASON_STARTING;
        return 0;
    }

    if (diag.bootstrap_reconnect_pending || diag.bootstrap_retry_rounds > 0) {
        out->state = MESH_RUNTIME_HEALTH_UNHEALTHY;
        out->reason = MESH_RUNTIME_HEALTH_REASON_BOOTSTRAP_UNREACHABLE;
        return 0;
    }

    out->state = MESH_RUNTIME_HEALTH_UNHEALTHY;
    out->reason = MESH_RUNTIME_HEALTH_REASON_NO_CONNECTED_PATH;
    return 0;
}

const char *mesh_runtime_health_state_string(mesh_runtime_health_state_t state) {
    switch (state) {
        case MESH_RUNTIME_HEALTH_HEALTHY:
            return "healthy";
        case MESH_RUNTIME_HEALTH_DEGRADED:
            return "degraded";
        case MESH_RUNTIME_HEALTH_UNHEALTHY:
            return "unhealthy";
        default:
            return "unknown";
    }
}

const char *mesh_runtime_health_reason_string(mesh_runtime_health_reason_t reason) {
    switch (reason) {
        case MESH_RUNTIME_HEALTH_REASON_NONE:
            return "none";
        case MESH_RUNTIME_HEALTH_REASON_DIRECT_ONLY:
            return "direct_only";
        case MESH_RUNTIME_HEALTH_REASON_HYBRID:
            return "hybrid";
        case MESH_RUNTIME_HEALTH_REASON_RELAY_ONLY:
            return "relay_only";
        case MESH_RUNTIME_HEALTH_REASON_DIRECT_UPGRADE_PENDING:
            return "direct_upgrade_pending";
        case MESH_RUNTIME_HEALTH_REASON_BOOTSTRAP_RECONNECT_PENDING:
            return "bootstrap_reconnect_pending";
        case MESH_RUNTIME_HEALTH_REASON_AWAITING_PEERS:
            return "awaiting_peers";
        case MESH_RUNTIME_HEALTH_REASON_STARTING:
            return "starting";
        case MESH_RUNTIME_HEALTH_REASON_NO_CONNECTED_PATH:
            return "no_connected_path";
        case MESH_RUNTIME_HEALTH_REASON_BOOTSTRAP_UNREACHABLE:
            return "bootstrap_unreachable";
        default:
            return "unknown";
    }
}

const char *mesh_runtime_health_summary(const mesh_runtime_health_t *health) {
    if (!health) {
        return "health unavailable";
    }

    switch (health->reason) {
        case MESH_RUNTIME_HEALTH_REASON_DIRECT_ONLY:
            return "direct mesh path available";
        case MESH_RUNTIME_HEALTH_REASON_HYBRID:
            return "direct and relay paths available";
        case MESH_RUNTIME_HEALTH_REASON_RELAY_ONLY:
            return "relay path available, no direct peer selected";
        case MESH_RUNTIME_HEALTH_REASON_DIRECT_UPGRADE_PENDING:
            return "relay path available while ICE direct upgrade is still in progress";
        case MESH_RUNTIME_HEALTH_REASON_BOOTSTRAP_RECONNECT_PENDING:
            return "mesh is connected but bootstrap recovery is still pending";
        case MESH_RUNTIME_HEALTH_REASON_AWAITING_PEERS:
            return "node is listening and waiting for peers";
        case MESH_RUNTIME_HEALTH_REASON_STARTING:
            return "mesh is starting and has not finished initial connect attempts";
        case MESH_RUNTIME_HEALTH_REASON_NO_CONNECTED_PATH:
            return "no connected direct or relay path is currently available";
        case MESH_RUNTIME_HEALTH_REASON_BOOTSTRAP_UNREACHABLE:
            return "bootstrap recovery is failing and no path is available";
        case MESH_RUNTIME_HEALTH_REASON_NONE:
        default:
            return "health state has no summary";
    }
}

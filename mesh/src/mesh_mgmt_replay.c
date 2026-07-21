#include "mesh_mgmt_replay.h"

#include "mesh_mgmt_crypto.h"

#include <stdlib.h>
#include <string.h>

#define MESH_MGMT_SERIAL_HALF_RANGE (UINT64_C(1) << 63)

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
    uint8_t aggregate = 0;
    size_t index = 0;

    for (index = 0; index < length; index++) aggregate |= bytes[index];
    return aggregate == 0u;
}

static int sequence_is_newer(uint64_t candidate, uint64_t current) {
    const uint64_t distance = candidate - current;
    return distance != 0u && distance < MESH_MGMT_SERIAL_HALF_RANGE;
}

static uint64_t bounded_expiry(uint64_t now_ms,
                               uint64_t frame_expiry_ms,
                               uint64_t ttl_ms) {
    uint64_t ttl_expiry = UINT64_MAX;

    if (now_ms <= UINT64_MAX - ttl_ms) ttl_expiry = now_ms + ttl_ms;
    return frame_expiry_ms < ttl_expiry ? frame_expiry_ms : ttl_expiry;
}

mesh_mgmt_replay_result_t mesh_mgmt_replay_init_v1(
    mesh_mgmt_replay_gate_v1_t *gate,
    const mesh_mgmt_replay_config_v1_t *config) {
    mesh_mgmt_replay_entry_v1_t *entries = NULL;

    if (!gate || !config) return MESH_MGMT_REPLAY_INVALID_ARG;
    memset(gate, 0, sizeof(*gate));
    if (config->capacity == 0u ||
        config->capacity > MESH_MGMT_REPLAY_CACHE_MAX ||
        config->ttl_ms == 0u ||
        config->ttl_ms > MESH_MGMT_REPLAY_TTL_MAX_MS) {
        return MESH_MGMT_REPLAY_INVALID_SCHEMA;
    }
    entries = (mesh_mgmt_replay_entry_v1_t *)calloc(
        config->capacity, sizeof(*entries));
    if (!entries) return MESH_MGMT_REPLAY_RESOURCE_EXHAUSTED;
    gate->config = *config;
    gate->entries = entries;
    return MESH_MGMT_REPLAY_OK;
}

void mesh_mgmt_replay_destroy_v1(mesh_mgmt_replay_gate_v1_t *gate) {
    if (!gate) return;
    free(gate->entries);
    memset(gate, 0, sizeof(*gate));
}

mesh_mgmt_replay_result_t mesh_mgmt_replay_bind_v1(
    mesh_mgmt_replay_gate_v1_t *gate,
    const mesh_mgmt_replay_binding_v1_t *binding) {
    if (!gate || !binding || !gate->entries)
        return MESH_MGMT_REPLAY_INVALID_ARG;
    if (bytes_are_zero(binding->principal_key,
                       sizeof(binding->principal_key)) ||
        bytes_are_zero(binding->session_id, sizeof(binding->session_id))) {
        return MESH_MGMT_REPLAY_INVALID_SCHEMA;
    }
    memset(gate->entries, 0,
           gate->config.capacity * sizeof(*gate->entries));
    gate->binding = *binding;
    gate->last_sequence = 0u;
    gate->has_sequence = 0u;
    gate->bound = 1u;
    gate->generation++;
    return MESH_MGMT_REPLAY_OK;
}

mesh_mgmt_replay_result_t mesh_mgmt_replay_prepare_v1(
    const mesh_mgmt_replay_gate_v1_t *gate,
    const mesh_mgmt_header_v1_t *header,
    uint64_t now_ms,
    mesh_mgmt_replay_preparation_v1_t *out_preparation) {
    size_t available_slot = SIZE_MAX;
    size_t index = 0;

    if (!gate || !header || !out_preparation || !gate->entries)
        return MESH_MGMT_REPLAY_INVALID_ARG;
    memset(out_preparation, 0, sizeof(*out_preparation));
    if (!gate->bound) return MESH_MGMT_REPLAY_BINDING_MISMATCH;
    if (bytes_are_zero(header->message_id, sizeof(header->message_id)) ||
        bytes_are_zero(header->session_id, sizeof(header->session_id))) {
        return MESH_MGMT_REPLAY_INVALID_SCHEMA;
    }
    if (header->issued_at_ms > now_ms || header->expires_at_ms <= now_ms)
        return MESH_MGMT_REPLAY_EXPIRED;
    if (!mesh_mgmt_crypto_equal_32(header->origin_principal_key,
                                   gate->binding.principal_key) ||
        header->principal_epoch != gate->binding.principal_epoch ||
        header->incarnation != gate->binding.incarnation ||
        !mesh_mgmt_crypto_equal_16(header->session_id,
                                   gate->binding.session_id)) {
        return MESH_MGMT_REPLAY_BINDING_MISMATCH;
    }
    if (gate->has_sequence &&
        !sequence_is_newer(header->origin_sequence, gate->last_sequence)) {
        return MESH_MGMT_REPLAY_REPLAYED;
    }
    for (index = 0; index < gate->config.capacity; index++) {
        const mesh_mgmt_replay_entry_v1_t *entry = &gate->entries[index];
        if (!entry->occupied || entry->expires_at_ms <= now_ms) {
            if (available_slot == SIZE_MAX) available_slot = index;
            continue;
        }
        if (mesh_mgmt_crypto_equal_16(entry->message_id,
                                      header->message_id)) {
            return MESH_MGMT_REPLAY_REPLAYED;
        }
    }
    if (available_slot == SIZE_MAX)
        return MESH_MGMT_REPLAY_RESOURCE_EXHAUSTED;

    out_preparation->generation = gate->generation;
    out_preparation->sequence = header->origin_sequence;
    out_preparation->cache_expires_at_ms = bounded_expiry(
        now_ms, header->expires_at_ms, gate->config.ttl_ms);
    out_preparation->cache_slot = available_slot;
    memcpy(out_preparation->message_id, header->message_id,
           sizeof(out_preparation->message_id));
    out_preparation->prepared = 1u;
    return MESH_MGMT_REPLAY_OK;
}

mesh_mgmt_replay_result_t mesh_mgmt_replay_commit_v1(
    mesh_mgmt_replay_gate_v1_t *gate,
    const mesh_mgmt_replay_preparation_v1_t *preparation) {
    mesh_mgmt_replay_entry_v1_t *entry = NULL;

    if (!gate || !preparation || !gate->entries || !preparation->prepared)
        return MESH_MGMT_REPLAY_INVALID_ARG;
    if (!gate->bound || preparation->generation != gate->generation ||
        preparation->cache_slot >= gate->config.capacity) {
        return MESH_MGMT_REPLAY_STALE_PREPARATION;
    }
    if (gate->has_sequence &&
        !sequence_is_newer(preparation->sequence, gate->last_sequence)) {
        return MESH_MGMT_REPLAY_STALE_PREPARATION;
    }
    entry = &gate->entries[preparation->cache_slot];
    memcpy(entry->message_id, preparation->message_id,
           sizeof(entry->message_id));
    entry->expires_at_ms = preparation->cache_expires_at_ms;
    entry->occupied = 1u;
    gate->last_sequence = preparation->sequence;
    gate->has_sequence = 1u;
    gate->generation++;
    return MESH_MGMT_REPLAY_OK;
}

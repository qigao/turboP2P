#include "mesh_control_controller_identity.h"

#include "mesh_mgmt_crypto.h"

#include <stdlib.h>
#include <string.h>

static int zero_bytes(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  for (index = 0u; index < size; ++index) aggregate |= bytes[index];
  return aggregate == 0u;
}

static mesh_control_controller_identity_entry_v1_t *find_entry(
    mesh_control_controller_identity_registry_v1_t *registry,
    const uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE]) {
  size_t index;
  for (index = 0u; index < registry->count; ++index)
    if (mesh_mgmt_crypto_equal_32(registry->entries[index].node_id, node_id))
      return &registry->entries[index];
  return NULL;
}

static int entry_valid(
    const mesh_control_controller_identity_entry_v1_t *entry) {
  return entry && !zero_bytes(entry->node_id, sizeof(entry->node_id)) &&
         !zero_bytes(entry->management_public_key,
                     sizeof(entry->management_public_key)) &&
         entry->certificate && entry->certificate->initialized &&
         entry->certificate->role == MESH_CERTIFICATE_ROLE_CLIENT_V1 &&
         entry->identity_policy_generation != 0u &&
         entry->identity_policy_generation ==
             entry->certificate->policy_generation;
}

mesh_control_result_t mesh_control_controller_identity_registry_init_v1(
    mesh_control_controller_identity_registry_v1_t *registry,
    size_t capacity, mesh_control_controller_identity_now_fn now_ms,
    void *now_context) {
  if (!registry || registry->initialized || capacity == 0u ||
      capacity > MESH_CONTROL_CONTROLLER_IDENTITY_MAX_V1 || !now_ms)
    return MESH_CONTROL_INVALID_ARG;
  memset(registry, 0, sizeof(*registry));
  registry->entries = (mesh_control_controller_identity_entry_v1_t *)calloc(
      capacity, sizeof(*registry->entries));
  if (!registry->entries) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  registry->capacity = capacity;
  registry->now_ms = now_ms;
  registry->now_context = now_context;
  registry->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_identity_registry_put_v1(
    mesh_control_controller_identity_registry_v1_t *registry,
    const mesh_control_controller_identity_entry_v1_t *entry) {
  mesh_control_controller_identity_entry_v1_t *existing;
  if (!registry || !registry->initialized || !entry_valid(entry))
    return MESH_CONTROL_INVALID_ARG;
  existing = find_entry(registry, entry->node_id);
  if (existing) {
    if (entry->identity_policy_generation <=
        existing->identity_policy_generation)
      return MESH_CONTROL_STALE_EPOCH;
    *existing = *entry;
    return MESH_CONTROL_OK;
  }
  if (registry->count == registry->capacity)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  registry->entries[registry->count++] = *entry;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_identity_authorize_v1(
    void *context,
    const uint8_t claimed_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t actual_tls_certificate_sha256[MESH_CONTROL_DIGEST_SIZE],
    mesh_control_agent_sync_hello_policy_v1_t *out_policy) {
  mesh_control_controller_identity_registry_v1_t *registry =
      (mesh_control_controller_identity_registry_v1_t *)context;
  mesh_control_controller_identity_entry_v1_t *entry;
  uint64_t now_ms;
  uint64_t certificate_generation = 0u;
  uint64_t minimum_serial;
  uint64_t maximum_serial;
  mesh_control_result_t current_result;
  if (!registry || !registry->initialized || !claimed_node_id ||
      !actual_tls_certificate_sha256 || !out_policy)
    return MESH_CONTROL_INVALID_ARG;
  entry = find_entry(registry, claimed_node_id);
  now_ms = registry->now_ms(registry->now_context);
  if (!entry || now_ms == 0u || !entry_valid(entry))
    return MESH_CONTROL_UNAUTHORIZED;
  current_result = mesh_certificate_lifecycle_authorize_v1(
      entry->certificate, actual_tls_certificate_sha256,
      entry->certificate->current.serial, now_ms, &certificate_generation);
  if (current_result != MESH_CONTROL_OK &&
      (!entry->certificate->next.configured ||
       mesh_certificate_lifecycle_authorize_v1(
           entry->certificate, actual_tls_certificate_sha256,
           entry->certificate->next.serial, now_ms,
           &certificate_generation) != MESH_CONTROL_OK))
    return MESH_CONTROL_UNAUTHORIZED;
  if (certificate_generation != entry->identity_policy_generation)
    return MESH_CONTROL_UNAUTHORIZED;
  minimum_serial = entry->certificate->current.serial;
  maximum_serial = entry->certificate->current.serial;
  if (entry->certificate->next.configured) {
    if (entry->certificate->next.serial < minimum_serial)
      minimum_serial = entry->certificate->next.serial;
    if (entry->certificate->next.serial > maximum_serial)
      maximum_serial = entry->certificate->next.serial;
  }
  memset(out_policy, 0, sizeof(*out_policy));
  memcpy(out_policy->expected_node_id, entry->node_id,
         sizeof(out_policy->expected_node_id));
  memcpy(out_policy->expected_management_public_key,
         entry->management_public_key,
         sizeof(out_policy->expected_management_public_key));
  out_policy->minimum_certificate_serial = minimum_serial;
  out_policy->maximum_certificate_serial = maximum_serial;
  out_policy->identity_policy_generation =
      entry->identity_policy_generation;
  return MESH_CONTROL_OK;
}

void mesh_control_controller_identity_registry_destroy_v1(
    mesh_control_controller_identity_registry_v1_t *registry) {
  if (!registry) return;
  free(registry->entries);
  memset(registry, 0, sizeof(*registry));
}

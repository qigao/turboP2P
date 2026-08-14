#include "mesh_network_reconciler.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

enum {
  MESH_NETWORK_RECONCILER_UNINITIALIZED = 0,
  MESH_NETWORK_RECONCILER_OPEN = 1,
  MESH_NETWORK_RECONCILER_CLOSING = 2,
  MESH_NETWORK_RECONCILER_CLOSED = 3
};

static mesh_control_result_t map_mesh_result(int result) {
  switch (result) {
    case MESH_OK: return MESH_CONTROL_OK;
    case MESH_ERR_INVALID_ARG: return MESH_CONTROL_INVALID_ARG;
    case MESH_ERR_NO_MEMORY:
    case MESH_ERR_RESOURCE_EXHAUSTED: return MESH_CONTROL_RESOURCE_EXHAUSTED;
    case MESH_ERR_NOT_FOUND: return MESH_CONTROL_EMPTY;
    case MESH_ERR_ALREADY_EXISTS:
    case MESH_ERR_CONFLICT: return MESH_CONTROL_CONFLICT;
    case MESH_ERR_STALE_EPOCH: return MESH_CONTROL_STALE_EPOCH;
    case MESH_ERR_UNAUTHORIZED: return MESH_CONTROL_UNAUTHORIZED;
    case MESH_ERR_UNSUPPORTED: return MESH_CONTROL_UNSUPPORTED;
    case MESH_ERR_UNKNOWN_COMMIT: return MESH_CONTROL_UNKNOWN_COMMIT;
    case MESH_ERR_CLOSED: return MESH_CONTROL_CLOSED;
    default: return MESH_CONTROL_INVALID_STATE;
  }
}

mesh_control_result_t mesh_network_resource_id_v1(
    const uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE],
    const uint8_t network_uid[MESH_CONTROL_ID_SIZE],
    uint8_t out_resource_id[MESH_CONTROL_DIGEST_SIZE]) {
  static const uint8_t domain[] = "mesh-network/v1";
  uint8_t input[(sizeof(domain) - 1u) + MESH_CONTROL_DIGEST_SIZE +
                MESH_CONTROL_ID_SIZE];
  if (!mesh_id || !network_uid || !out_resource_id)
    return MESH_CONTROL_INVALID_ARG;
  memcpy(input, domain, sizeof(domain) - 1u);
  memcpy(input + sizeof(domain) - 1u, mesh_id, MESH_CONTROL_DIGEST_SIZE);
  memcpy(input + sizeof(domain) - 1u + MESH_CONTROL_DIGEST_SIZE,
         network_uid, MESH_CONTROL_ID_SIZE);
  if (turbo_crypto_sha256(input, sizeof(input), out_resource_id) !=
      TURBO_CRYPTO_OK) {
    memset(input, 0, sizeof(input));
    return MESH_CONTROL_INVALID_STATE;
  }
  memset(input, 0, sizeof(input));
  return MESH_CONTROL_OK;
}

static int resource_id_matches(
    const mesh_control_network_document_v1_t *document,
    const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE]) {
  uint8_t expected[MESH_CONTROL_DIGEST_SIZE];
  int matches = 0;
  if (mesh_network_resource_id_v1(document->mesh_id, document->network_uid,
                                  expected) == MESH_CONTROL_OK)
    matches = turbo_crypto_verify(expected, resource_id, sizeof(expected)) ==
              TURBO_CRYPTO_OK;
  memset(expected, 0, sizeof(expected));
  return matches;
}

static size_t find_record(const mesh_network_reconciler_v1_t *reconciler,
                          const uint8_t resource_id[32]) {
  size_t index;
  for (index = 0u; index < reconciler->count; ++index) {
    if (turbo_crypto_verify(reconciler->records[index].resource_id,
                            resource_id, 32u) == TURBO_CRYPTO_OK)
      return index;
  }
  return SIZE_MAX;
}

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  if (!bytes) return 1;
  for (index = 0u; index < size; ++index) aggregate |= bytes[index];
  return aggregate == 0u;
}

mesh_control_result_t mesh_network_reconciler_init_v1(
    mesh_network_reconciler_v1_t *reconciler, mesh_fabric_t *fabric,
    size_t capacity) {
  if (!reconciler || !fabric || capacity == 0u ||
      capacity > MESH_NETWORK_HARD_LIMIT || reconciler->records ||
      reconciler->lifecycle != MESH_NETWORK_RECONCILER_UNINITIALIZED)
    return MESH_CONTROL_INVALID_ARG;
  memset(reconciler, 0, sizeof(*reconciler));
  reconciler->records = (mesh_network_reconciler_record_v1_t *)calloc(
      capacity, sizeof(*reconciler->records));
  if (!reconciler->records) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  reconciler->fabric = fabric;
  reconciler->capacity = capacity;
  reconciler->lifecycle = MESH_NETWORK_RECONCILER_OPEN;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_network_reconciler_submit_v1(
    mesh_network_reconciler_v1_t *reconciler,
    const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE],
    mesh_control_desired_action_v1_t action,
    uint64_t precondition_generation,
    const uint8_t *document, size_t document_size,
    uint64_t drain_timeout_ms, uint64_t *out_generation) {
  size_t index;
  int mesh_result;
  if (!reconciler) return MESH_CONTROL_INVALID_ARG;
  if (reconciler->lifecycle != MESH_NETWORK_RECONCILER_OPEN)
    return MESH_CONTROL_CLOSED;
  if (!resource_id || !out_generation ||
      (action != MESH_CONTROL_DESIRED_APPLY &&
       action != MESH_CONTROL_DESIRED_DELETE))
    return MESH_CONTROL_INVALID_ARG;
  *out_generation = 0u;
  index = find_record(reconciler, resource_id);
  if (action == MESH_CONTROL_DESIRED_DELETE) {
    mesh_network_reconciler_record_v1_t *record;
    if (document || document_size != 0u || drain_timeout_ms == 0u)
      return MESH_CONTROL_INVALID_ARG;
    if (index == SIZE_MAX) return MESH_CONTROL_EMPTY;
    record = &reconciler->records[index];
    *out_generation = record->generation;
    if (precondition_generation != record->generation)
      return MESH_CONTROL_STALE_EPOCH;
    mesh_result = mesh_fabric_detach_network_v2(
        reconciler->fabric, &record->network_uid, drain_timeout_ms);
    if (mesh_result != MESH_OK) return map_mesh_result(mesh_result);
    if (index + 1u < reconciler->count)
      memmove(&reconciler->records[index], &reconciler->records[index + 1u],
              (reconciler->count - index - 1u) * sizeof(*record));
    reconciler->count--;
    memset(&reconciler->records[reconciler->count], 0,
           sizeof(*record));
    return MESH_CONTROL_OK;
  }
  {
    mesh_control_network_document_v1_t decoded;
    mesh_network_membership_ticket_v1_t ticket;
    mesh_network_spec_v2_t spec;
    mesh_network_route_v2_t routes[MESH_CONTROL_NETWORK_MAX_ROUTES_V1];
    mesh_network_t *network = NULL;
    uint8_t document_digest[MESH_CONTROL_DIGEST_SIZE];
    uint64_t applied_generation = 0u;
    size_t route_index;
    if (!document || document_size == 0u || drain_timeout_ms != 0u ||
        turbo_crypto_sha256(document, document_size, document_digest) !=
            TURBO_CRYPTO_OK ||
        mesh_control_network_document_decode_v1(document, document_size,
                                                &decoded) != MESH_CONTROL_OK ||
        !resource_id_matches(&decoded, resource_id) ||
        mesh_network_membership_ticket_decode_v1(
            decoded.membership_ticket,
            MESH_CONTROL_NETWORK_TICKET_SIZE_V1, &ticket) != MESH_OK)
      return MESH_CONTROL_INVALID_ARG;
    if (decoded.lifecycle != MESH_CONTROL_NETWORK_ACTIVE_V1)
      return MESH_CONTROL_UNSUPPORTED;
    if (!bytes_zero(decoded.dns_digest, sizeof(decoded.dns_digest)))
      return MESH_CONTROL_UNSUPPORTED;
    memset(routes, 0, sizeof(routes));
    for (route_index = 0u; route_index < decoded.route_count; ++route_index) {
      mesh_control_network_route_v1_t decoded_route;
      if (mesh_control_network_route_decode_v1(
              decoded.route_entries +
                  route_index * MESH_CONTROL_NETWORK_ROUTE_SIZE_V1,
              &decoded_route) != MESH_CONTROL_OK)
        return MESH_CONTROL_INVALID_ARG;
      routes[route_index].destination_network =
          decoded_route.destination_network;
      routes[route_index].prefix_length = decoded_route.prefix_length;
      routes[route_index].kind = decoded_route.kind;
      routes[route_index].metric = decoded_route.metric;
      memcpy(routes[route_index].next_hop_node_id,
             decoded_route.next_hop_node_id, MESH_NETWORK_IDENTITY_SIZE);
    }
    memset(&spec, 0, sizeof(spec));
    spec.struct_size = sizeof(spec);
    memcpy(spec.network_uid.bytes, decoded.network_uid,
           MESH_NETWORK_UID_SIZE);
    spec.name = decoded.name;
    spec.generation = decoded.generation;
    spec.policy_epoch = decoded.policy_epoch;
    spec.route_epoch = decoded.route_epoch;
    spec.mtu = decoded.mtu;
    spec.lifecycle = MESH_NETWORK_ACTIVE;
    spec.attach_mode =
        decoded.attach_mode == MESH_CONTROL_NETWORK_USERSPACE_V1
            ? MESH_NETWORK_ATTACH_USERSPACE
            : decoded.attach_mode == MESH_CONTROL_NETWORK_OS_SHARED_V1
                  ? MESH_NETWORK_ATTACH_OS_SHARED
                  : MESH_NETWORK_ATTACH_OS_ISOLATED;
    spec.local_membership = ticket;
    spec.authorized_peer_node_ids = decoded.authorized_peer_node_ids;
    spec.authorized_peer_count = decoded.authorized_peer_count;
    spec.routes = decoded.route_count == 0u ? NULL : routes;
    spec.route_count = decoded.route_count;
    if (index == SIZE_MAX) {
      if (precondition_generation != 0u)
        return MESH_CONTROL_STALE_EPOCH;
      if (reconciler->count >= reconciler->capacity)
        return MESH_CONTROL_RESOURCE_EXHAUSTED;
      mesh_result = mesh_fabric_attach_network_v2(reconciler->fabric, &spec,
                                                  &network);
      if (mesh_result != MESH_OK) return map_mesh_result(mesh_result);
      index = reconciler->count++;
      memcpy(reconciler->records[index].resource_id, resource_id,
             MESH_CONTROL_DIGEST_SIZE);
      memcpy(reconciler->records[index].network_uid.bytes,
             decoded.network_uid, MESH_CONTROL_ID_SIZE);
      reconciler->records[index].network = network;
      reconciler->records[index].generation = decoded.generation;
      memcpy(reconciler->records[index].document_digest, document_digest,
             sizeof(document_digest));
      *out_generation = decoded.generation;
      memset(document_digest, 0, sizeof(document_digest));
      return MESH_CONTROL_OK;
    }
    *out_generation = reconciler->records[index].generation;
    mesh_result = mesh_network_apply_snapshot_v2(
        reconciler->records[index].network, precondition_generation, &spec,
        &applied_generation);
    if (mesh_result != MESH_OK) return map_mesh_result(mesh_result);
    reconciler->records[index].generation = applied_generation;
    memcpy(reconciler->records[index].document_digest, document_digest,
           sizeof(document_digest));
    *out_generation = applied_generation;
    memset(document_digest, 0, sizeof(document_digest));
    return MESH_CONTROL_OK;
  }
}

mesh_control_result_t mesh_network_reconciler_close_v1(
    mesh_network_reconciler_v1_t *reconciler, uint64_t drain_timeout_ms) {
  if (!reconciler || drain_timeout_ms == 0u)
    return MESH_CONTROL_INVALID_ARG;
  if (reconciler->lifecycle == MESH_NETWORK_RECONCILER_CLOSED)
    return MESH_CONTROL_OK;
  if (reconciler->lifecycle != MESH_NETWORK_RECONCILER_OPEN &&
      reconciler->lifecycle != MESH_NETWORK_RECONCILER_CLOSING)
    return MESH_CONTROL_INVALID_STATE;
  reconciler->lifecycle = MESH_NETWORK_RECONCILER_CLOSING;
  while (reconciler->count != 0u) {
    mesh_network_reconciler_record_v1_t *record =
        &reconciler->records[reconciler->count - 1u];
    int detach_result = mesh_fabric_detach_network_v2(
        reconciler->fabric, &record->network_uid, drain_timeout_ms);
    if (detach_result != MESH_OK) return map_mesh_result(detach_result);
    memset(record, 0, sizeof(*record));
    reconciler->count--;
  }
  reconciler->lifecycle = MESH_NETWORK_RECONCILER_CLOSED;
  return MESH_CONTROL_OK;
}

void mesh_network_reconciler_destroy_v1(
    mesh_network_reconciler_v1_t *reconciler) {
  if (!reconciler) return;
  if (reconciler->lifecycle != MESH_NETWORK_RECONCILER_CLOSED) return;
  free(reconciler->records);
  memset(reconciler, 0, sizeof(*reconciler));
}

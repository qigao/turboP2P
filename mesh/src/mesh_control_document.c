#include "mesh_control_document.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_wire.h"

#include <string.h>

static const uint8_t MESH_CONTROL_INTENT_MAGIC_V1[4] = {'T', 'C', 'I', '1'};
static const uint8_t MESH_CONTROL_FUNCTION_MAGIC_V1[4] = {'T', 'C', 'F', '1'};
static const uint8_t MESH_CONTROL_NETWORK_MAGIC_V1[4] = {'T', 'C', 'N', '1'};

static int mesh_control_bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  if (!bytes) return 1;
  for (index = 0u; index < size; ++index) aggregate |= bytes[index];
  return aggregate == 0u;
}

static int mesh_control_network_name_valid(const char *name, size_t *out_size) {
  size_t size;
  size_t index;
  if (!name) return 0;
  size = strnlen(name, MESH_CONTROL_NETWORK_NAME_CAPACITY_V1);
  if (size == 0u || size >= MESH_CONTROL_NETWORK_NAME_CAPACITY_V1) return 0;
  for (index = 0u; index < size; ++index) {
    unsigned char ch = (unsigned char)name[index];
    if (ch < 0x20u || ch == 0x7fu || ch == '/' || ch == '\\') return 0;
  }
  if (out_size) *out_size = size;
  return 1;
}

static int mesh_control_network_peers_valid(const uint8_t *peers,
                                            size_t peer_count) {
  size_t index;
  if (peer_count > MESH_CONTROL_NETWORK_MAX_PEERS_V1 ||
      (peer_count != 0u && !peers)) return 0;
  for (index = 0u; index < peer_count; ++index) {
    const uint8_t *current = peers + index * MESH_CONTROL_NODE_ID_SIZE;
    if (mesh_control_bytes_zero(current, MESH_CONTROL_NODE_ID_SIZE)) return 0;
    if (index != 0u &&
        memcmp(peers + (index - 1u) * MESH_CONTROL_NODE_ID_SIZE,
               current, MESH_CONTROL_NODE_ID_SIZE) >= 0) return 0;
  }
  return 1;
}

static uint32_t mesh_control_network_route_required_role(uint8_t kind) {
  return kind == MESH_CONTROL_NETWORK_ROUTE_SUBNET_V1
             ? 1u << 1
             : kind == MESH_CONTROL_NETWORK_ROUTE_EXIT_V1 ? 1u << 2 : 0u;
}

static int mesh_control_network_route_valid(
    const mesh_control_network_route_v1_t *route) {
  uint32_t mask;
  if (!route || route->prefix_length > 32u ||
      mesh_control_network_route_required_role(route->kind) == 0u ||
      mesh_control_bytes_zero(route->next_hop_node_id,
                              MESH_CONTROL_NODE_ID_SIZE))
    return 0;
  mask = route->prefix_length == 0u
             ? 0u
             : UINT32_MAX << (32u - route->prefix_length);
  return route->destination_network == (route->destination_network & mask) &&
         (route->kind != MESH_CONTROL_NETWORK_ROUTE_EXIT_V1 ||
          (route->prefix_length == 0u &&
           route->destination_network == 0u)) &&
         (route->kind != MESH_CONTROL_NETWORK_ROUTE_SUBNET_V1 ||
          route->prefix_length != 0u);
}

static int mesh_control_network_route_compare(
    const mesh_control_network_route_v1_t *left,
    const mesh_control_network_route_v1_t *right) {
  int node_order;
  if (left->destination_network != right->destination_network)
    return left->destination_network < right->destination_network ? -1 : 1;
  if (left->prefix_length != right->prefix_length)
    return left->prefix_length > right->prefix_length ? -1 : 1;
  if (left->metric != right->metric)
    return left->metric < right->metric ? -1 : 1;
  node_order = memcmp(left->next_hop_node_id, right->next_hop_node_id,
                      MESH_CONTROL_NODE_ID_SIZE);
  if (node_order != 0) return node_order;
  return (int)left->kind - (int)right->kind;
}

mesh_control_result_t mesh_control_network_route_encode_v1(
    const mesh_control_network_route_v1_t *route,
    uint8_t output[MESH_CONTROL_NETWORK_ROUTE_SIZE_V1]) {
  if (!mesh_control_network_route_valid(route) || !output)
    return MESH_CONTROL_INVALID_ARG;
  mesh_mgmt_wire_write_u32(output, route->destination_network);
  output[4u] = route->prefix_length;
  output[5u] = route->kind;
  mesh_mgmt_wire_write_u16(output + 6u, route->metric);
  memcpy(output + 8u, route->next_hop_node_id,
         MESH_CONTROL_NODE_ID_SIZE);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_network_route_decode_v1(
    const uint8_t input[MESH_CONTROL_NETWORK_ROUTE_SIZE_V1],
    mesh_control_network_route_v1_t *out_route) {
  if (!input || !out_route) return MESH_CONTROL_INVALID_ARG;
  memset(out_route, 0, sizeof(*out_route));
  out_route->destination_network = mesh_mgmt_wire_read_u32(input);
  out_route->prefix_length = input[4u];
  out_route->kind = input[5u];
  out_route->metric = mesh_mgmt_wire_read_u16(input + 6u);
  memcpy(out_route->next_hop_node_id, input + 8u,
         MESH_CONTROL_NODE_ID_SIZE);
  if (!mesh_control_network_route_valid(out_route)) {
    memset(out_route, 0, sizeof(*out_route));
    return MESH_CONTROL_INVALID_ARG;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_network_routes_digest_v1(
    const uint8_t *route_entries, size_t route_count,
    uint8_t out_digest[MESH_CONTROL_DIGEST_SIZE]) {
  if (!out_digest || route_count > MESH_CONTROL_NETWORK_MAX_ROUTES_V1 ||
      (route_count != 0u && !route_entries))
    return MESH_CONTROL_INVALID_ARG;
  if (route_count == 0u) {
    memset(out_digest, 0, MESH_CONTROL_DIGEST_SIZE);
    return MESH_CONTROL_OK;
  }
  return mesh_mgmt_blake2b_256(
             route_entries,
             route_count * MESH_CONTROL_NETWORK_ROUTE_SIZE_V1,
             out_digest) == MESH_MGMT_CRYPTO_OK
             ? MESH_CONTROL_OK
             : MESH_CONTROL_INVALID_STATE;
}

static int mesh_control_network_route_next_hop_allowed(
    const mesh_control_network_document_v1_t *document,
    const mesh_control_network_route_v1_t *route) {
  uint32_t required_role =
      mesh_control_network_route_required_role(route->kind);
  uint32_t local_roles;
  size_t peer_index;
  if (memcmp(route->next_hop_node_id, document->managed_node_id,
             MESH_CONTROL_NODE_ID_SIZE) == 0) {
    local_roles = mesh_mgmt_wire_read_u32(document->membership_ticket + 176u);
    return (local_roles & required_role) != 0u;
  }
  for (peer_index = 0u; peer_index < document->authorized_peer_count;
       ++peer_index) {
    if (memcmp(route->next_hop_node_id,
               document->authorized_peer_node_ids +
                   peer_index * MESH_CONTROL_NODE_ID_SIZE,
               MESH_CONTROL_NODE_ID_SIZE) == 0)
      return 1;
  }
  return 0;
}

static int mesh_control_network_routes_valid(
    const mesh_control_network_document_v1_t *document) {
  mesh_control_network_route_v1_t previous;
  mesh_control_network_route_v1_t current;
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE];
  size_t index;
  if (!document ||
      document->route_count > MESH_CONTROL_NETWORK_MAX_ROUTES_V1 ||
      (document->route_count != 0u && !document->route_entries))
    return 0;
  if (document->route_count == 0u)
    return mesh_control_bytes_zero(document->route_digest,
                                   MESH_CONTROL_DIGEST_SIZE);
  if (mesh_control_bytes_zero(document->route_digest,
                              MESH_CONTROL_DIGEST_SIZE) ||
      mesh_control_network_routes_digest_v1(
          document->route_entries, document->route_count, digest) !=
          MESH_CONTROL_OK ||
      !mesh_mgmt_crypto_equal_32(document->route_digest, digest))
    return 0;
  memset(&previous, 0, sizeof(previous));
  for (index = 0u; index < document->route_count; ++index) {
    if (mesh_control_network_route_decode_v1(
            document->route_entries +
                index * MESH_CONTROL_NETWORK_ROUTE_SIZE_V1,
            &current) != MESH_CONTROL_OK ||
        !mesh_control_network_route_next_hop_allowed(document, &current) ||
        (index != 0u &&
         mesh_control_network_route_compare(&previous, &current) >= 0))
      return 0;
    previous = current;
  }
  return 1;
}

static int mesh_control_network_document_valid(
    const mesh_control_network_document_v1_t *document, size_t *name_size) {
  const uint8_t *ticket;
  if (!document || document->schema_version != MESH_CONTROL_SCHEMA_V1 ||
      document->reserved != 0u || document->flags != 0u ||
      document->lifecycle < MESH_CONTROL_NETWORK_ACTIVE_V1 ||
      document->lifecycle > MESH_CONTROL_NETWORK_TOMBSTONED_V1 ||
      document->attach_mode < MESH_CONTROL_NETWORK_USERSPACE_V1 ||
      document->attach_mode > MESH_CONTROL_NETWORK_OS_ISOLATED_V1 ||
      mesh_control_bytes_zero(document->network_uid, MESH_CONTROL_ID_SIZE) ||
      mesh_control_bytes_zero(document->mesh_id, MESH_CONTROL_DIGEST_SIZE) ||
      mesh_control_bytes_zero(document->managed_node_id,
                              MESH_CONTROL_NODE_ID_SIZE) ||
      document->generation == 0u || document->policy_epoch == 0u ||
      document->route_epoch == 0u || document->key_epoch == 0u ||
      document->ipv4_address == 0u || document->ipv4_prefix > 32u ||
      document->mtu < 576u || document->mtu > 9000u ||
      !mesh_control_network_name_valid(document->name, name_size) ||
      mesh_control_bytes_zero(document->policy_digest,
                              MESH_CONTROL_DIGEST_SIZE) ||
      mesh_control_bytes_zero(document->address_pool_digest,
                              MESH_CONTROL_DIGEST_SIZE) ||
      !mesh_control_network_peers_valid(document->authorized_peer_node_ids,
                                        document->authorized_peer_count) ||
      !mesh_control_network_routes_valid(document))
    return 0;
  ticket = document->membership_ticket;
  return memcmp(ticket, "MTK1", 4u) == 0 &&
         mesh_mgmt_wire_read_u16(ticket + 4u) == 1u &&
         mesh_mgmt_wire_read_u16(ticket + 6u) ==
             MESH_CONTROL_NETWORK_TICKET_SIZE_V1 &&
         memcmp(ticket + 8u, document->mesh_id, MESH_CONTROL_DIGEST_SIZE) == 0 &&
         memcmp(ticket + 40u, document->network_uid, MESH_CONTROL_ID_SIZE) == 0 &&
         memcmp(ticket + 72u, document->managed_node_id,
                MESH_CONTROL_NODE_ID_SIZE) == 0 &&
         mesh_mgmt_wire_read_u64(ticket + 136u) == document->generation &&
         mesh_mgmt_wire_read_u64(ticket + 152u) == document->key_epoch &&
         mesh_mgmt_wire_read_u64(ticket + 160u) == document->policy_epoch &&
         mesh_mgmt_wire_read_u32(ticket + 168u) == document->ipv4_address &&
         ticket[172u] == document->ipv4_prefix &&
         !mesh_control_bytes_zero(ticket + 236u, 64u);
}

mesh_control_result_t mesh_control_intent_encode_v1(
    mesh_control_desired_action_v1_t action, const uint8_t *document,
    size_t document_size, uint8_t *output, size_t output_capacity,
    size_t *out_size) {
  size_t required_size;
  if (out_size == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = 0u;
  if ((action != MESH_CONTROL_DESIRED_APPLY &&
       action != MESH_CONTROL_DESIRED_DELETE) ||
      (document_size != 0u && document == NULL) ||
      document_size > MESH_CONTROL_MMP_BODY_MAX_V1 -
                          MESH_CONTROL_INTENT_HEADER_SIZE_V1) {
    return MESH_CONTROL_INVALID_ARG;
  }
  required_size = MESH_CONTROL_INTENT_HEADER_SIZE_V1 + document_size;
  *out_size = required_size;
  if (output == NULL || output_capacity < required_size)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memcpy(output, MESH_CONTROL_INTENT_MAGIC_V1,
         sizeof(MESH_CONTROL_INTENT_MAGIC_V1));
  mesh_mgmt_wire_write_u16(output + MESH_CONTROL_INTENT_MAGIC_SIZE_V1,
                           MESH_CONTROL_SCHEMA_V1);
  mesh_mgmt_wire_write_u16(
      output + MESH_CONTROL_INTENT_MAGIC_SIZE_V1 + sizeof(uint16_t),
      (uint16_t)action);
  if (document_size != 0u)
    memcpy(output + MESH_CONTROL_INTENT_HEADER_SIZE_V1, document,
           document_size);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_intent_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_control_intent_view_v1_t *out_intent) {
  uint16_t action;
  if (out_intent == NULL)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_intent, 0, sizeof(*out_intent));
  if (payload == NULL || payload_size < MESH_CONTROL_INTENT_HEADER_SIZE_V1 ||
      payload_size > MESH_CONTROL_MMP_BODY_MAX_V1 ||
      memcmp(payload, MESH_CONTROL_INTENT_MAGIC_V1,
             sizeof(MESH_CONTROL_INTENT_MAGIC_V1)) != 0 ||
      mesh_mgmt_wire_read_u16(payload + MESH_CONTROL_INTENT_MAGIC_SIZE_V1) !=
          MESH_CONTROL_SCHEMA_V1) {
    return MESH_CONTROL_INVALID_ARG;
  }
  action = mesh_mgmt_wire_read_u16(
      payload + MESH_CONTROL_INTENT_MAGIC_SIZE_V1 + sizeof(uint16_t));
  if (action != MESH_CONTROL_DESIRED_APPLY &&
      action != MESH_CONTROL_DESIRED_DELETE)
    return MESH_CONTROL_INVALID_ARG;
  out_intent->action = (mesh_control_desired_action_v1_t)action;
  out_intent->document_size =
      payload_size - MESH_CONTROL_INTENT_HEADER_SIZE_V1;
  out_intent->document = out_intent->document_size == 0u
                             ? NULL
                             : payload + MESH_CONTROL_INTENT_HEADER_SIZE_V1;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_function_document_encode_v1(
    const mesh_control_function_spec_v1_t *spec, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  if (out_size == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = 0u;
  if (mesh_control_function_spec_validate_v1(spec) != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1;
  if (output == NULL || output_capacity < MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memcpy(output, MESH_CONTROL_FUNCTION_MAGIC_V1,
         sizeof(MESH_CONTROL_FUNCTION_MAGIC_V1));
  mesh_mgmt_wire_write_u16(output + 4u, spec->schema_version);
  mesh_mgmt_wire_write_u16(output + 6u, spec->runtime);
  mesh_mgmt_wire_write_u16(output + 8u, spec->desired_state);
  mesh_mgmt_wire_write_u16(output + 10u, 0u);
  mesh_mgmt_wire_write_u32(output + 12u, spec->flags);
  memcpy(output + 16u, spec->function_id, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 48u, spec->provider_id, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 80u, spec->artifact_digest, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 112u, spec->config_digest, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 144u, spec->network_policy_digest,
         MESH_CONTROL_DIGEST_SIZE);
  mesh_mgmt_wire_write_u64(output + 176u, spec->generation);
  mesh_mgmt_wire_write_u64(output + 184u, spec->required_capabilities);
  mesh_mgmt_wire_write_u64(output + 192u, spec->limits.memory_bytes);
  mesh_mgmt_wire_write_u64(output + 200u, spec->limits.cpu_time_ms);
  mesh_mgmt_wire_write_u64(output + 208u, spec->limits.input_bytes);
  mesh_mgmt_wire_write_u64(output + 216u, spec->limits.output_bytes);
  mesh_mgmt_wire_write_u32(output + 224u, spec->limits.concurrency);
  mesh_mgmt_wire_write_u32(output + 228u, spec->limits.host_calls);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_function_document_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_control_function_spec_v1_t *out_spec) {
  if (input == NULL || out_spec == NULL ||
      input_size != MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_spec, 0, sizeof(*out_spec));
  if (memcmp(input, MESH_CONTROL_FUNCTION_MAGIC_V1,
             sizeof(MESH_CONTROL_FUNCTION_MAGIC_V1)) != 0 ||
      mesh_mgmt_wire_read_u16(input + 10u) != 0u)
    return MESH_CONTROL_INVALID_ARG;
  out_spec->schema_version = mesh_mgmt_wire_read_u16(input + 4u);
  out_spec->runtime = mesh_mgmt_wire_read_u16(input + 6u);
  out_spec->desired_state = mesh_mgmt_wire_read_u16(input + 8u);
  out_spec->flags = mesh_mgmt_wire_read_u32(input + 12u);
  memcpy(out_spec->function_id, input + 16u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_spec->provider_id, input + 48u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_spec->artifact_digest, input + 80u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_spec->config_digest, input + 112u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_spec->network_policy_digest, input + 144u,
         MESH_CONTROL_DIGEST_SIZE);
  out_spec->generation = mesh_mgmt_wire_read_u64(input + 176u);
  out_spec->required_capabilities = mesh_mgmt_wire_read_u64(input + 184u);
  out_spec->limits.memory_bytes = mesh_mgmt_wire_read_u64(input + 192u);
  out_spec->limits.cpu_time_ms = mesh_mgmt_wire_read_u64(input + 200u);
  out_spec->limits.input_bytes = mesh_mgmt_wire_read_u64(input + 208u);
  out_spec->limits.output_bytes = mesh_mgmt_wire_read_u64(input + 216u);
  out_spec->limits.concurrency = mesh_mgmt_wire_read_u32(input + 224u);
  out_spec->limits.host_calls = mesh_mgmt_wire_read_u32(input + 228u);
  if (mesh_control_function_spec_validate_v1(out_spec) != MESH_CONTROL_OK) {
    memset(out_spec, 0, sizeof(*out_spec));
    return MESH_CONTROL_INVALID_ARG;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_network_document_encode_v1(
    const mesh_control_network_document_v1_t *document, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  size_t name_size = 0u;
  size_t peer_bytes;
  size_t route_bytes;
  size_t required_size;
  if (!out_size) return MESH_CONTROL_INVALID_ARG;
  *out_size = 0u;
  if (!mesh_control_network_document_valid(document, &name_size) ||
      document->authorized_peer_count >
          (SIZE_MAX - MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1) /
              MESH_CONTROL_NODE_ID_SIZE ||
      document->route_count >
          (SIZE_MAX - MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1) /
              MESH_CONTROL_NETWORK_ROUTE_SIZE_V1)
    return MESH_CONTROL_INVALID_ARG;
  peer_bytes = document->authorized_peer_count * MESH_CONTROL_NODE_ID_SIZE;
  route_bytes = document->route_count * MESH_CONTROL_NETWORK_ROUTE_SIZE_V1;
  if (peer_bytes > SIZE_MAX - MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 ||
      route_bytes >
          SIZE_MAX - MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 - peer_bytes)
    return MESH_CONTROL_INVALID_ARG;
  required_size = MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 + peer_bytes +
                  route_bytes;
  *out_size = required_size;
  if (!output || output_capacity < required_size)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memset(output, 0, required_size);
  memcpy(output, MESH_CONTROL_NETWORK_MAGIC_V1, 4u);
  mesh_mgmt_wire_write_u16(output + 4u, document->schema_version);
  mesh_mgmt_wire_write_u16(output + 6u, document->lifecycle);
  mesh_mgmt_wire_write_u16(output + 8u, document->attach_mode);
  mesh_mgmt_wire_write_u16(output + 10u, (uint16_t)document->route_count);
  mesh_mgmt_wire_write_u32(output + 12u, document->flags);
  memcpy(output + 16u, document->network_uid, MESH_CONTROL_ID_SIZE);
  memcpy(output + 32u, document->mesh_id, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 64u, document->managed_node_id, MESH_CONTROL_NODE_ID_SIZE);
  mesh_mgmt_wire_write_u64(output + 96u, document->generation);
  mesh_mgmt_wire_write_u64(output + 104u, document->policy_epoch);
  mesh_mgmt_wire_write_u64(output + 112u, document->route_epoch);
  mesh_mgmt_wire_write_u64(output + 120u, document->key_epoch);
  mesh_mgmt_wire_write_u32(output + 128u, document->ipv4_address);
  output[132u] = document->ipv4_prefix;
  mesh_mgmt_wire_write_u16(output + 134u, document->mtu);
  mesh_mgmt_wire_write_u16(output + 136u,
                           (uint16_t)document->authorized_peer_count);
  mesh_mgmt_wire_write_u16(output + 138u, (uint16_t)name_size);
  memcpy(output + 140u, document->policy_digest, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 172u, document->address_pool_digest,
         MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 204u, document->route_digest, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 236u, document->dns_digest, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 268u, document->membership_ticket,
         MESH_CONTROL_NETWORK_TICKET_SIZE_V1);
  memcpy(output + 568u, document->name, name_size);
  if (document->authorized_peer_count != 0u)
    memcpy(output + MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1,
           document->authorized_peer_node_ids,
           peer_bytes);
  if (document->route_count != 0u)
    memcpy(output + MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 + peer_bytes,
           document->route_entries, route_bytes);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_network_document_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_control_network_document_v1_t *out_document) {
  size_t peer_count;
  size_t route_count;
  size_t name_size;
  size_t peer_bytes;
  size_t route_bytes;
  size_t required_size;
  if (!input || !out_document ||
      input_size < MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 ||
      input_size > MESH_CONTROL_NETWORK_DOCUMENT_MAX_SIZE_V1)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_document, 0, sizeof(*out_document));
  if (memcmp(input, MESH_CONTROL_NETWORK_MAGIC_V1, 4u) != 0 ||
      input[133u] != 0u)
    return MESH_CONTROL_INVALID_ARG;
  route_count = mesh_mgmt_wire_read_u16(input + 10u);
  peer_count = mesh_mgmt_wire_read_u16(input + 136u);
  name_size = mesh_mgmt_wire_read_u16(input + 138u);
  if (peer_count > MESH_CONTROL_NETWORK_MAX_PEERS_V1 ||
      route_count > MESH_CONTROL_NETWORK_MAX_ROUTES_V1 ||
      name_size == 0u || name_size >= MESH_CONTROL_NETWORK_NAME_CAPACITY_V1 ||
      peer_count >
          (SIZE_MAX - MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1) /
              MESH_CONTROL_NODE_ID_SIZE ||
      route_count >
          (SIZE_MAX - MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1) /
              MESH_CONTROL_NETWORK_ROUTE_SIZE_V1)
    return MESH_CONTROL_INVALID_ARG;
  peer_bytes = peer_count * MESH_CONTROL_NODE_ID_SIZE;
  route_bytes = route_count * MESH_CONTROL_NETWORK_ROUTE_SIZE_V1;
  if (route_bytes >
      SIZE_MAX - MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 - peer_bytes)
    return MESH_CONTROL_INVALID_ARG;
  required_size = MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 + peer_bytes +
                  route_bytes;
  if (required_size != input_size) return MESH_CONTROL_INVALID_ARG;
  for (size_t index = 568u + name_size;
       index < MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1; ++index) {
    if (input[index] != 0u) return MESH_CONTROL_INVALID_ARG;
  }
  out_document->schema_version = mesh_mgmt_wire_read_u16(input + 4u);
  out_document->lifecycle = mesh_mgmt_wire_read_u16(input + 6u);
  out_document->attach_mode = mesh_mgmt_wire_read_u16(input + 8u);
  out_document->flags = mesh_mgmt_wire_read_u32(input + 12u);
  memcpy(out_document->network_uid, input + 16u, MESH_CONTROL_ID_SIZE);
  memcpy(out_document->mesh_id, input + 32u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_document->managed_node_id, input + 64u,
         MESH_CONTROL_NODE_ID_SIZE);
  out_document->generation = mesh_mgmt_wire_read_u64(input + 96u);
  out_document->policy_epoch = mesh_mgmt_wire_read_u64(input + 104u);
  out_document->route_epoch = mesh_mgmt_wire_read_u64(input + 112u);
  out_document->key_epoch = mesh_mgmt_wire_read_u64(input + 120u);
  out_document->ipv4_address = mesh_mgmt_wire_read_u32(input + 128u);
  out_document->ipv4_prefix = input[132u];
  out_document->mtu = mesh_mgmt_wire_read_u16(input + 134u);
  memcpy(out_document->policy_digest, input + 140u,
         MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_document->address_pool_digest, input + 172u,
         MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_document->route_digest, input + 204u,
         MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_document->dns_digest, input + 236u,
         MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_document->membership_ticket, input + 268u,
         MESH_CONTROL_NETWORK_TICKET_SIZE_V1);
  memcpy(out_document->name, input + 568u, name_size);
  out_document->name[name_size] = '\0';
  out_document->authorized_peer_count = peer_count;
  out_document->authorized_peer_node_ids =
      peer_count == 0u ? NULL
                       : input + MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1;
  out_document->route_count = route_count;
  out_document->route_entries =
      route_count == 0u
          ? NULL
          : input + MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 + peer_bytes;
  if (!mesh_control_network_document_valid(out_document, NULL)) {
    memset(out_document, 0, sizeof(*out_document));
    return MESH_CONTROL_INVALID_ARG;
  }
  return MESH_CONTROL_OK;
}

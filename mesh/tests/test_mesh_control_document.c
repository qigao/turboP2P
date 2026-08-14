#include "mesh_control_document.h"
#include "tinytest.h"

#include <string.h>

static void make_spec(mesh_control_function_spec_v1_t *spec,
                      mesh_control_function_runtime_v1_t runtime) {
  memset(spec, 0, sizeof(*spec));
  spec->schema_version = MESH_CONTROL_SCHEMA_V1;
  spec->runtime = runtime;
  spec->desired_state = MESH_CONTROL_FUNCTION_RUNNING;
  spec->flags = MESH_CONTROL_FUNCTION_FLAG_PRESTAGED;
  if (runtime == MESH_CONTROL_FUNCTION_NATIVE)
    spec->flags |= MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;
  spec->function_id[0] = 1u;
  spec->provider_id[0] = 2u;
  spec->artifact_digest[0] = 3u;
  spec->config_digest[0] = 4u;
  spec->network_policy_digest[0] = 5u;
  spec->generation = 6u;
  spec->required_capabilities = 7u;
  spec->limits.memory_bytes = 8u;
  spec->limits.cpu_time_ms = 9u;
  spec->limits.input_bytes = 10u;
  spec->limits.output_bytes = 11u;
  spec->limits.concurrency = 12u;
  spec->limits.host_calls = 13u;
}

static void test_function_document_round_trips(void) {
  mesh_control_function_spec_v1_t spec;
  mesh_control_function_spec_v1_t decoded;
  mesh_control_intent_view_v1_t intent;
  uint8_t document[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  uint8_t payload[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1 +
                  MESH_CONTROL_INTENT_HEADER_SIZE_V1];
  size_t document_size = 0u;
  size_t payload_size = 0u;

  make_spec(&spec, MESH_CONTROL_FUNCTION_NATIVE);
  check_int_eq(mesh_control_function_document_encode_v1(
                   &spec, document, sizeof(document), &document_size),
               MESH_CONTROL_OK);
  check_int_eq(document_size, MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1);
  check_int_eq(mesh_control_function_document_decode_v1(
                   document, document_size, &decoded),
               MESH_CONTROL_OK);
  check_mem_eq(&decoded, &spec, sizeof(spec));
  check_int_eq(mesh_control_intent_encode_v1(
                   MESH_CONTROL_DESIRED_APPLY, document, document_size,
                   payload, sizeof(payload), &payload_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_intent_decode_v1(
                   payload, payload_size, &intent),
               MESH_CONTROL_OK);
  check_int_eq(intent.action, MESH_CONTROL_DESIRED_APPLY);
  check_int_eq(intent.document_size, document_size);
  check_mem_eq(intent.document, document, document_size);
}

static void test_function_document_rejects_tamper_and_short_buffers(void) {
  mesh_control_function_spec_v1_t spec;
  mesh_control_function_spec_v1_t decoded;
  mesh_control_intent_view_v1_t intent;
  uint8_t document[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  uint8_t payload[MESH_CONTROL_INTENT_HEADER_SIZE_V1];
  size_t required_size = 0u;

  make_spec(&spec, MESH_CONTROL_FUNCTION_NATIVE);
  check_int_eq(mesh_control_function_document_encode_v1(
                   &spec, document, sizeof(document) - 1u, &required_size),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(required_size, MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1);
  check_int_eq(mesh_control_function_document_encode_v1(
                   &spec, document, sizeof(document), &required_size),
               MESH_CONTROL_OK);
  document[10] = 1u;
  check_int_eq(mesh_control_function_document_decode_v1(
                   document, sizeof(document), &decoded),
               MESH_CONTROL_INVALID_ARG);
  check_int_eq(mesh_control_function_document_decode_v1(
                   document, sizeof(document) - 1u, &decoded),
               MESH_CONTROL_INVALID_ARG);
  check_int_eq(mesh_control_intent_encode_v1(
                   MESH_CONTROL_DESIRED_DELETE, NULL, 0u, payload,
                   sizeof(payload), &required_size),
               MESH_CONTROL_OK);
  payload[4] = 0u;
  payload[5] = 2u;
  check_int_eq(mesh_control_intent_decode_v1(
                   payload, sizeof(payload), &intent),
               MESH_CONTROL_INVALID_ARG);
}

static void make_network_document(
    mesh_control_network_document_v1_t *document,
    uint8_t peers[2u * MESH_CONTROL_NODE_ID_SIZE],
    uint8_t route_entry[MESH_CONTROL_NETWORK_ROUTE_SIZE_V1]) {
  mesh_control_network_route_v1_t route;
  memset(document, 0, sizeof(*document));
  memset(peers, 0, 2u * MESH_CONTROL_NODE_ID_SIZE);
  document->schema_version = MESH_CONTROL_SCHEMA_V1;
  document->lifecycle = MESH_CONTROL_NETWORK_ACTIVE_V1;
  document->attach_mode = MESH_CONTROL_NETWORK_USERSPACE_V1;
  document->network_uid[0] = 1u;
  document->mesh_id[0] = 2u;
  document->managed_node_id[0] = 3u;
  document->generation = 4u;
  document->policy_epoch = 5u;
  document->route_epoch = 6u;
  document->key_epoch = 7u;
  document->ipv4_address = 0x0a640001u;
  document->ipv4_prefix = 24u;
  document->mtu = 1280u;
  memcpy(document->name, "production", sizeof("production"));
  document->policy_digest[0] = 8u;
  document->address_pool_digest[0] = 9u;
  document->dns_digest[0] = 11u;
  memcpy(document->membership_ticket, "MTK1", 4u);
  document->membership_ticket[5] = 1u;
  document->membership_ticket[6] = 1u;
  document->membership_ticket[7] = 44u;
  memcpy(document->membership_ticket + 8u, document->mesh_id,
         MESH_CONTROL_DIGEST_SIZE);
  memcpy(document->membership_ticket + 40u, document->network_uid,
         MESH_CONTROL_ID_SIZE);
  memcpy(document->membership_ticket + 72u, document->managed_node_id,
         MESH_CONTROL_NODE_ID_SIZE);
  document->membership_ticket[143] = 4u;
  document->membership_ticket[159] = 7u;
  document->membership_ticket[167] = 5u;
  document->membership_ticket[168] = 10u;
  document->membership_ticket[169] = 100u;
  document->membership_ticket[171] = 1u;
  document->membership_ticket[172] = 24u;
  document->membership_ticket[236] = 1u;
  peers[0] = 0x10u;
  peers[MESH_CONTROL_NODE_ID_SIZE] = 0x20u;
  document->authorized_peer_node_ids = peers;
  document->authorized_peer_count = 2u;
  memset(&route, 0, sizeof(route));
  route.destination_network = 0xcb007100u;
  route.prefix_length = 24u;
  route.kind = MESH_CONTROL_NETWORK_ROUTE_SUBNET_V1;
  route.metric = 10u;
  memcpy(route.next_hop_node_id, peers + MESH_CONTROL_NODE_ID_SIZE,
         MESH_CONTROL_NODE_ID_SIZE);
  check_int_eq(MESH_CONTROL_OK, mesh_control_network_route_encode_v1(
                                      &route, route_entry));
  document->route_entries = route_entry;
  document->route_count = 1u;
  check_int_eq(MESH_CONTROL_OK, mesh_control_network_routes_digest_v1(
                                      route_entry, 1u,
                                      document->route_digest));
}

static void test_network_document_round_trips_and_rejects_tamper(void) {
  mesh_control_network_document_v1_t document;
  mesh_control_network_document_v1_t decoded;
  mesh_control_network_route_v1_t decoded_route;
  uint8_t peers[2u * MESH_CONTROL_NODE_ID_SIZE];
  uint8_t route_entry[MESH_CONTROL_NETWORK_ROUTE_SIZE_V1];
  uint8_t wire[MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 + sizeof(peers) +
               sizeof(route_entry)];
  size_t wire_size = 0u;

  make_network_document(&document, peers, route_entry);
  check_int_eq(mesh_control_network_document_encode_v1(
                   &document, wire, sizeof(wire), &wire_size),
               MESH_CONTROL_OK);
  check_uint_eq(sizeof(wire), wire_size);
  check_int_eq(mesh_control_network_document_decode_v1(
                   wire, wire_size, &decoded),
               MESH_CONTROL_OK);
  check_str_eq("production", decoded.name);
  check_uint_eq(2u, decoded.authorized_peer_count);
  check_mem_eq(peers, decoded.authorized_peer_node_ids, sizeof(peers));
  check_uint_eq(1u, decoded.route_count);
  check_int_eq(MESH_CONTROL_OK, mesh_control_network_route_decode_v1(
                                      decoded.route_entries,
                                      &decoded_route));
  check_uint_eq(0xcb007100u, decoded_route.destination_network);
  check_mem_eq(peers + MESH_CONTROL_NODE_ID_SIZE,
               decoded_route.next_hop_node_id, MESH_CONTROL_NODE_ID_SIZE);

  wire[632u] = 0x30u; /* break canonical sorted peer order */
  check_int_eq(mesh_control_network_document_decode_v1(
                   wire, wire_size, &decoded),
               MESH_CONTROL_INVALID_ARG);
  make_network_document(&document, peers, route_entry);
  check_int_eq(mesh_control_network_document_encode_v1(
                   &document, wire, sizeof(wire), &wire_size),
               MESH_CONTROL_OK);
  wire[268u + 160u] ^= 1u; /* ticket no longer binds policy epoch */
  check_int_eq(mesh_control_network_document_decode_v1(
                   wire, wire_size, &decoded),
               MESH_CONTROL_INVALID_ARG);
  make_network_document(&document, peers, route_entry);
  check_int_eq(mesh_control_network_document_encode_v1(
                   &document, wire, sizeof(wire), &wire_size),
               MESH_CONTROL_OK);
  wire[268u + 152u] ^= 1u; /* ticket no longer binds node key epoch */
  check_int_eq(mesh_control_network_document_decode_v1(
                   wire, wire_size, &decoded),
               MESH_CONTROL_INVALID_ARG);
  make_network_document(&document, peers, route_entry);
  check_int_eq(mesh_control_network_document_encode_v1(
                   &document, wire, sizeof(wire), &wire_size),
               MESH_CONTROL_OK);
  wire[MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 + sizeof(peers)] ^= 1u;
  check_int_eq(mesh_control_network_document_decode_v1(
                   wire, wire_size, &decoded),
               MESH_CONTROL_INVALID_ARG);
}

spec("mesh control canonical desired documents") {
  describe("function assignment schema") {
    it("round trips an exact typed function intent") {
      test_function_document_round_trips();
    }
    it("rejects short buffers and noncanonical fields") {
      test_function_document_rejects_tamper_and_short_buffers();
    }
  }
  describe("Network snapshot schema") {
    it("round trips canonical scoped state and rejects inconsistent fields") {
      test_network_document_round_trips_and_rejects_tamper();
    }
  }
}

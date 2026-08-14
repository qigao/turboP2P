#include "mesh_network_reconciler.h"
#include "mesh_node_ipc_network_executor.h"

#include <p2p.h>
#include <tinytest.h>
#include <turbo_crypto.h>

#include <string.h>
#include <time.h>

static const uint8_t TEST_ISSUER_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t TEST_ISSUER_PUBLIC_KEY[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

typedef struct {
  uint8_t wire[MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 +
               MESH_CONTROL_NETWORK_ROUTE_SIZE_V1];
  size_t wire_size;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
} test_network_intent_t;

static void test_hex(const uint8_t bytes[32], char output[65]) {
  static const char digits[] = "0123456789abcdef";
  size_t index;
  for (index = 0u; index < 32u; ++index) {
    output[index * 2u] = digits[bytes[index] >> 4u];
    output[index * 2u + 1u] = digits[bytes[index] & 0x0fu];
  }
  output[64] = '\0';
}

static void make_network_intent(
    test_network_intent_t *intent, const uint8_t mesh_id[32],
    const uint8_t node_id[32], const mesh_network_issuer_v1_t *issuer,
    uint8_t uid_marker, uint64_t generation, uint16_t lifecycle,
    const char *name) {
  mesh_control_network_document_v1_t document;
  mesh_network_membership_ticket_v1_t ticket;
  mesh_network_uid_t uid;
  mesh_control_network_route_v1_t route;
  uint8_t route_entry[MESH_CONTROL_NETWORK_ROUTE_SIZE_V1];
  uint64_t now = (uint64_t)time(NULL);
  size_t ticket_size = 0u;

  memset(intent, 0, sizeof(*intent));
  memset(&document, 0, sizeof(document));
  memset(&ticket, 0, sizeof(ticket));
  memset(&uid, uid_marker, sizeof(uid));
  memcpy(ticket.mesh_id, mesh_id, sizeof(ticket.mesh_id));
  ticket.network_uid = uid;
  memset(ticket.membership_id, uid_marker + 1u,
         sizeof(ticket.membership_id));
  memcpy(ticket.managed_node_id, node_id, sizeof(ticket.managed_node_id));
  check_int_eq(MESH_OK, mesh_network_public_key_digest_v1(
                                node_id, ticket.node_public_key_digest));
  ticket.network_generation = generation;
  ticket.membership_generation = generation;
  ticket.node_key_epoch = generation;
  ticket.policy_epoch = generation;
  ticket.ipv4_address = 0x0a640001u + uid_marker;
  ticket.ipv4_prefix = 24u;
  ticket.roles = MESH_NETWORK_ROLE_MEMBER | MESH_NETWORK_ROLE_SUBNET_ROUTER;
  ticket.issued_at_unix_s = now - 1u;
  ticket.not_before_unix_s = now - 1u;
  ticket.not_after_unix_s = now + 3600u;
  memcpy(ticket.issuer_key_id, issuer->key_id,
         sizeof(ticket.issuer_key_id));
  check_int_eq(MESH_OK, mesh_network_membership_ticket_sign_v1(
                                &ticket, TEST_ISSUER_PRIVATE_KEY));

  document.schema_version = MESH_CONTROL_SCHEMA_V1;
  document.lifecycle = lifecycle;
  document.attach_mode = MESH_CONTROL_NETWORK_USERSPACE_V1;
  memcpy(document.network_uid, uid.bytes, sizeof(document.network_uid));
  memcpy(document.mesh_id, mesh_id, sizeof(document.mesh_id));
  memcpy(document.managed_node_id, node_id, sizeof(document.managed_node_id));
  document.generation = generation;
  document.policy_epoch = generation;
  document.route_epoch = generation;
  document.key_epoch = generation;
  document.ipv4_address = ticket.ipv4_address;
  document.ipv4_prefix = ticket.ipv4_prefix;
  document.mtu = 1280u;
  memcpy(document.name, name, strlen(name) + 1u);
  memset(document.policy_digest, 0x31, sizeof(document.policy_digest));
  memset(document.address_pool_digest, 0x32,
         sizeof(document.address_pool_digest));
  memset(&route, 0, sizeof(route));
  route.destination_network = 0xcb007100u;
  route.prefix_length = 24u;
  route.kind = MESH_CONTROL_NETWORK_ROUTE_SUBNET_V1;
  route.metric = 10u;
  memcpy(route.next_hop_node_id, node_id, MESH_CONTROL_NODE_ID_SIZE);
  check_int_eq(MESH_CONTROL_OK, mesh_control_network_route_encode_v1(
                                      &route, route_entry));
  document.route_entries = route_entry;
  document.route_count = 1u;
  check_int_eq(MESH_CONTROL_OK, mesh_control_network_routes_digest_v1(
                                      route_entry, 1u,
                                      document.route_digest));
  check_int_eq(MESH_OK, mesh_network_membership_ticket_encode_v1(
                                &ticket, document.membership_ticket,
                                sizeof(document.membership_ticket),
                                &ticket_size));
  check_uint_eq(MESH_CONTROL_NETWORK_TICKET_SIZE_V1, ticket_size);
  check_int_eq(MESH_CONTROL_OK, mesh_control_network_document_encode_v1(
                                       &document, intent->wire,
                                       sizeof(intent->wire),
                                       &intent->wire_size));
  check_int_eq(MESH_CONTROL_OK,
               mesh_network_resource_id_v1(mesh_id, document.network_uid,
                                           intent->resource_id));
}

static void test_reconciles_fenced_network_lifecycle(void) {
  static const char network_id[] = "network-reconciler-test";
  uint8_t node_private[32];
  uint8_t node_public[32];
  uint8_t mesh_id[32];
  char node_public_hex[65];
  const char *allowed_nodes[1];
  mesh_network_issuer_v1_t issuer;
  mesh_fabric_config_v2_t fabric_config;
  mesh_fabric_t *fabric = NULL;
  mesh_network_reconciler_v1_t reconciler;
  mesh_node_ipc_network_executor_v1_t ipc_executor;
  test_network_intent_t generation_one;
  test_network_intent_t generation_two;
  test_network_intent_t draining;
  test_network_intent_t second_network;
  mesh_fabric_status_v2_t status;
  mesh_network_status_v2_t network_status;
  uint64_t result_generation = 0u;
  mesh_node_ipc_command_v1_t ipc_command;
  mesh_node_ipc_execution_output_v1_t ipc_execution;

  memset(node_private, 0x44, sizeof(node_private));
  memset(&reconciler, 0, sizeof(reconciler));
  memset(&ipc_executor, 0, sizeof(ipc_executor));
  check_int_eq(P2P_OK,
               p2p_public_key_from_private_key(node_private, node_public));
  test_hex(node_public, node_public_hex);
  allowed_nodes[0] = node_public_hex;
  check_int_eq(TURBO_CRYPTO_OK,
               turbo_crypto_sha256(network_id, strlen(network_id), mesh_id));
  memset(&issuer, 0, sizeof(issuer));
  memset(issuer.key_id, 0x61, sizeof(issuer.key_id));
  memcpy(issuer.public_key, TEST_ISSUER_PUBLIC_KEY,
         sizeof(issuer.public_key));

  mesh_fabric_config_init_v2(&fabric_config);
  fabric_config.underlay.virtual_ip = "10.91.0.1";
  fabric_config.underlay.virtual_prefix = 24u;
  fabric_config.underlay.listen_port = 24991;
  fabric_config.underlay.network_id = network_id;
  fabric_config.underlay.identity_private_key = node_private;
  fabric_config.underlay.identity_private_key_size = sizeof(node_private);
  fabric_config.underlay.peer_allow_node_ids = allowed_nodes;
  fabric_config.underlay.peer_allow_node_id_count = 1u;
  fabric_config.trusted_issuers = &issuer;
  fabric_config.trusted_issuer_count = 1u;
  check_int_eq(MESH_OK, mesh_fabric_create_v2(&fabric_config, &fabric));
  check_int_eq(MESH_CONTROL_OK,
               mesh_network_reconciler_init_v1(&reconciler, fabric, 1u));
  check_int_eq(mesh_network_reconciler_init_v1(&reconciler, fabric, 1u),
               MESH_CONTROL_INVALID_ARG);
  check_int_eq(MESH_CONTROL_OK, mesh_node_ipc_network_executor_init_v1(
                                      &ipc_executor, &reconciler, mesh_id,
                                      100u));

  make_network_intent(&generation_one, mesh_id, node_public, &issuer, 0x11u,
                      1u, MESH_CONTROL_NETWORK_ACTIVE_V1, "production");
  memset(&ipc_command, 0, sizeof(ipc_command));
  ipc_command.action = MESH_CONTROL_DESIRED_APPLY;
  ipc_command.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  memcpy(ipc_command.mesh_id, mesh_id, sizeof(ipc_command.mesh_id));
  memcpy(ipc_command.resource_id, generation_one.resource_id,
         sizeof(ipc_command.resource_id));
  ipc_command.document = generation_one.wire;
  ipc_command.document_size = generation_one.wire_size;
  check_int_eq(TURBO_CRYPTO_OK,
               turbo_crypto_sha256(ipc_command.document,
                                   ipc_command.document_size,
                                   ipc_command.document_digest));
  check_int_eq(MESH_CONTROL_OK, mesh_node_ipc_network_execute_v1(
                                      &ipc_executor, &ipc_command, 1u,
                                      &ipc_execution));
  check_uint_eq(1u, ipc_execution.applied_epoch);
  check_mem_eq(ipc_execution.observed_digest, ipc_command.document_digest,
               sizeof(ipc_execution.observed_digest));
  memset(&ipc_execution, 0, sizeof(ipc_execution));
  check_int_eq(MESH_CONTROL_OK, mesh_node_ipc_network_execute_v1(
                                      &ipc_executor, &ipc_command, 1u,
                                      &ipc_execution));
  check_uint_eq(1u, ipc_execution.applied_epoch);
  memset(&network_status, 0, sizeof(network_status));
  network_status.struct_size = sizeof(network_status);
  check_int_eq(MESH_OK, mesh_network_get_status_v2(
                                reconciler.records[0].network,
                                &network_status));
  check_uint_eq(1u, network_status.route_count);
  check_uint_eq(1u, network_status.route_epoch);
  check_int_eq(mesh_network_reconciler_submit_v1(
                   &reconciler, generation_one.resource_id,
                   MESH_CONTROL_DESIRED_APPLY, 0u, generation_one.wire,
                   generation_one.wire_size, 0u, &result_generation),
               MESH_CONTROL_STALE_EPOCH);

  make_network_intent(&generation_two, mesh_id, node_public, &issuer, 0x11u,
                      2u, MESH_CONTROL_NETWORK_ACTIVE_V1, "production");
  generation_two.wire[631u] = 1u; /* noncanonical reserved padding */
  check_int_eq(mesh_network_reconciler_submit_v1(
                   &reconciler, generation_two.resource_id,
                   MESH_CONTROL_DESIRED_APPLY, 1u, generation_two.wire,
                   generation_two.wire_size, 0u, &result_generation),
               MESH_CONTROL_INVALID_ARG);
  make_network_intent(&generation_two, mesh_id, node_public, &issuer, 0x11u,
                      2u, MESH_CONTROL_NETWORK_ACTIVE_V1, "production");
  generation_two.wire[536u] ^= 1u; /* signature byte; shape remains valid */
  check_int_eq(mesh_network_reconciler_submit_v1(
                   &reconciler, generation_two.resource_id,
                   MESH_CONTROL_DESIRED_APPLY, 1u, generation_two.wire,
                   generation_two.wire_size, 0u, &result_generation),
               MESH_CONTROL_UNAUTHORIZED);
  make_network_intent(&generation_two, mesh_id, node_public, &issuer, 0x11u,
                      2u, MESH_CONTROL_NETWORK_ACTIVE_V1, "production");
  check_int_eq(MESH_CONTROL_OK, mesh_network_reconciler_submit_v1(
                                      &reconciler, generation_two.resource_id,
                                      MESH_CONTROL_DESIRED_APPLY, 1u,
                                      generation_two.wire,
                                      generation_two.wire_size, 0u,
                                      &result_generation));
  check_uint_eq(2u, result_generation);

  make_network_intent(&draining, mesh_id, node_public, &issuer, 0x11u, 3u,
                      MESH_CONTROL_NETWORK_DRAINING_V1, "production");
  check_int_eq(mesh_network_reconciler_submit_v1(
                   &reconciler, draining.resource_id,
                   MESH_CONTROL_DESIRED_APPLY, 2u, draining.wire,
                   draining.wire_size, 0u, &result_generation),
               MESH_CONTROL_UNSUPPORTED);
  make_network_intent(&draining, mesh_id, node_public, &issuer, 0x11u, 3u,
                      MESH_CONTROL_NETWORK_ACTIVE_V1, "production");
  draining.wire[236u] = 1u; /* DNS snapshot has no V2 executor yet */
  check_int_eq(mesh_network_reconciler_submit_v1(
                   &reconciler, draining.resource_id,
                   MESH_CONTROL_DESIRED_APPLY, 2u, draining.wire,
                   draining.wire_size, 0u, &result_generation),
               MESH_CONTROL_UNSUPPORTED);

  make_network_intent(&second_network, mesh_id, node_public, &issuer, 0x22u,
                      1u, MESH_CONTROL_NETWORK_ACTIVE_V1, "backup");
  check_int_eq(mesh_network_reconciler_submit_v1(
                   &reconciler, second_network.resource_id,
                   MESH_CONTROL_DESIRED_APPLY, 0u, second_network.wire,
                   second_network.wire_size, 0u, &result_generation),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_network_reconciler_submit_v1(
                   &reconciler, generation_two.resource_id,
                   MESH_CONTROL_DESIRED_DELETE, 1u, NULL, 0u, 100u,
                   &result_generation),
               MESH_CONTROL_STALE_EPOCH);
  check_int_eq(MESH_CONTROL_OK, mesh_network_reconciler_submit_v1(
                                      &reconciler,
                                      generation_two.resource_id,
                                      MESH_CONTROL_DESIRED_DELETE, 2u, NULL,
                                      0u, 100u, &result_generation));
  check_uint_eq(2u, result_generation);

  check_int_eq(MESH_CONTROL_OK, mesh_network_reconciler_submit_v1(
                                      &reconciler,
                                      second_network.resource_id,
                                      MESH_CONTROL_DESIRED_APPLY, 0u,
                                      second_network.wire,
                                      second_network.wire_size, 0u,
                                      &result_generation));
  memset(&status, 0, sizeof(status));
  status.struct_size = sizeof(status);
  check_int_eq(MESH_OK, mesh_fabric_get_status_v2(fabric, &status));
  check_uint_eq(1u, status.attached_networks);
  check_int_eq(MESH_CONTROL_OK,
               mesh_network_reconciler_close_v1(&reconciler, 100u));
  check_int_eq(mesh_network_reconciler_submit_v1(
                   &reconciler, second_network.resource_id,
                   MESH_CONTROL_DESIRED_DELETE, 1u, NULL, 0u, 100u,
                   &result_generation),
               MESH_CONTROL_CLOSED);
  mesh_node_ipc_network_executor_destroy_v1(&ipc_executor);
  mesh_network_reconciler_destroy_v1(&reconciler);
  mesh_fabric_destroy_v2(fabric);
}

spec("mesh Network reconciler") {
  describe("bounded desired-state application") {
    it("authenticates, fences, bounds, updates and drains Networks") {
      test_reconciles_fenced_network_lifecycle();
    }
  }
}

#include "mesh_mgmt_execution_disabled_responder.h"

#include <tinytest.h>

#include <string.h>

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static void test_disabled_status_preserves_request_binding(void) {
  mesh_mgmt_execution_shadow_command_v1_t command;
  mesh_mgmt_execution_status_v1_t status;

  memset(&command, 0, sizeof(command));
  fill_bytes(command.request.command_id,
             sizeof(command.request.command_id), 0x11u);
  fill_bytes(command.request.correlation_id,
             sizeof(command.request.correlation_id), 0x21u);
  fill_bytes(command.request.target_node_id,
             sizeof(command.request.target_node_id), 0x31u);
  fill_bytes(command.request_digest, sizeof(command.request_digest), 0x41u);

  check_int_eq(mesh_mgmt_execution_disabled_status_from_command_v1(
                   &command, &status),
               MESH_MGMT_EXECUTION_DISABLED_RESPONDER_OK);
  check_int_eq(status.version, MESH_MGMT_EXECUTION_SCHEMA_V1);
  check_int_eq(status.code, MESH_MGMT_EXECUTION_STATUS_DISABLED);
  check_int_eq(memcmp(status.command_id, command.request.command_id,
                      sizeof(status.command_id)),
               0);
  check_int_eq(memcmp(status.correlation_id,
                      command.request.correlation_id,
                      sizeof(status.correlation_id)),
               0);
  check_int_eq(memcmp(status.request_digest, command.request_digest,
                      sizeof(status.request_digest)),
               0);
  check_int_eq(memcmp(status.responder_node_id,
                      command.request.target_node_id,
                      sizeof(status.responder_node_id)),
               0);
  check_int_eq(mesh_mgmt_execution_command_status_encode_v1(
                   &status, NULL, 0u, &(size_t){0u}),
               MESH_MGMT_EXECUTION_WIRE_RESOURCE_EXHAUSTED);
}

static void test_disabled_status_rejects_missing_ownership(void) {
  mesh_mgmt_execution_shadow_command_v1_t command;
  mesh_mgmt_execution_status_v1_t status;

  memset(&command, 0, sizeof(command));
  memset(&status, 0, sizeof(status));
  check_int_eq(mesh_mgmt_execution_disabled_status_from_command_v1(
                   NULL, &status),
               MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG);
  check_int_eq(mesh_mgmt_execution_disabled_status_from_command_v1(
                   &command, NULL),
               MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG);
}

spec("mesh management execution disabled responder") {
  describe("fail-closed node execution") {
    it("binds STATUS_DISABLED to the verified request") {
      test_disabled_status_preserves_request_binding();
    }
    it("rejects missing command ownership") {
      test_disabled_status_rejects_missing_ownership();
    }
  }
}

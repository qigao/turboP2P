#include "mesh_control_status.h"
#include "tinytest.h"

#include <string.h>

static void make_page(mesh_control_snapshot_page_info_v1_t *info,
                      mesh_control_resource_status_v1_t *resource,
                      mesh_control_operation_v1_t *operation) {
  memset(info, 0, sizeof(*info));
  info->generation = 7u;
  info->event_cursor = 11u;
  info->resource_total = 2u;
  info->operation_total = 1u;
  info->resource_offset = 1u;
  info->resource_count = 1u;
  info->operation_count = 1u;

  memset(resource, 0, sizeof(*resource));
  resource->resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  resource->resource_id[0] = 1u;
  resource->desired_epoch = 3u;
  resource->observed_epoch = 2u;
  resource->desired_presence = MESH_CONTROL_PRESENCE_PRESENT;
  resource->observed_presence = MESH_CONTROL_PRESENCE_ABSENT;
  resource->desired_digest[0] = 2u;

  memset(operation, 0, sizeof(*operation));
  operation->operation_id[0] = 3u;
  operation->request_id[0] = 4u;
  operation->message_id[0] = 5u;
  operation->resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  operation->action = MESH_CONTROL_DESIRED_APPLY;
  operation->resource_id[0] = 1u;
  operation->desired_digest[0] = 2u;
  operation->desired_epoch = 3u;
  operation->created_at_ms = 100u;
  operation->updated_at_ms = 110u;
  operation->state = MESH_CONTROL_OPERATION_RUNNING;
}

static void test_status_page_round_trips(void) {
  mesh_control_snapshot_page_info_v1_t info;
  mesh_control_resource_status_v1_t resource;
  mesh_control_resource_status_v1_t decoded_resource;
  mesh_control_operation_v1_t operation;
  mesh_control_operation_v1_t decoded_operation;
  mesh_control_status_page_view_v1_t page;
  uint8_t output[512];
  size_t output_size = 0u;

  make_page(&info, &resource, &operation);
  check_int_eq(mesh_control_status_page_encode_v1(&info, &resource, &operation, output,
                                                  sizeof(output), &output_size),
               MESH_CONTROL_OK);
  check_int_eq(output_size, MESH_CONTROL_STATUS_HEADER_SIZE_V1 +
                                MESH_CONTROL_STATUS_RESOURCE_RECORD_SIZE_V1 +
                                MESH_CONTROL_STATUS_OPERATION_RECORD_SIZE_V1);
  check_int_eq(mesh_control_status_page_decode_v1(output, output_size, &page), MESH_CONTROL_OK);
  check_int_eq(page.generation, info.generation);
  check_int_eq(page.event_cursor, info.event_cursor);
  check_int_eq(page.resource_offset, 1u);
  check_bits(page.flags, MESH_CONTROL_STATUS_FLAG_RESOURCES_COMPLETE);
  check_bits(page.flags, MESH_CONTROL_STATUS_FLAG_OPERATIONS_COMPLETE);
  check_int_eq(mesh_control_status_resource_at_v1(&page, 0u, &decoded_resource), MESH_CONTROL_OK);
  check_int_eq(mesh_control_status_operation_at_v1(&page, 0u, &decoded_operation), MESH_CONTROL_OK);
  check_mem_eq(&decoded_resource, &resource, sizeof(resource));
  check_mem_eq(&decoded_operation, &operation, sizeof(operation));
}

static void test_status_page_rejects_capacity_and_tamper(void) {
  mesh_control_snapshot_page_info_v1_t info;
  mesh_control_resource_status_v1_t resource;
  mesh_control_operation_v1_t operation;
  mesh_control_status_page_view_v1_t page;
  uint8_t output[512];
  size_t output_size = 0u;

  make_page(&info, &resource, &operation);
  check_int_eq(
      mesh_control_status_page_encode_v1(&info, &resource, &operation, output, 1u, &output_size),
      MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_true(output_size > 1u);
  check_int_eq(mesh_control_status_page_encode_v1(&info, &resource, &operation, output,
                                                  sizeof(output), &output_size),
               MESH_CONTROL_OK);
  output[6] = 0u;
  output[7] = 0u;
  check_int_eq(mesh_control_status_page_decode_v1(output, output_size, &page),
               MESH_CONTROL_INVALID_ARG);
  check_int_eq(mesh_control_status_page_decode_v1(output, output_size - 1u, &page),
               MESH_CONTROL_INVALID_ARG);
}

static void test_event_page_round_trips(void) {
  mesh_control_event_v1_t events[2] = {{0}};
  mesh_control_event_v1_t decoded;
  mesh_control_event_page_view_v1_t page;
  uint8_t output[256];
  size_t output_size = 0u;

  events[0].cursor = 8u;
  events[0].operation_id[0] = 1u;
  events[0].resource_kind = MESH_CONTROL_RESOURCE_SERVICE;
  events[0].operation_state = MESH_CONTROL_OPERATION_ACCEPTED;
  events[0].resource_id[0] = 2u;
  events[0].desired_epoch = 3u;
  events[0].recorded_at_ms = 100u;
  events[1] = events[0];
  events[1].cursor = 9u;
  events[1].operation_state = MESH_CONTROL_OPERATION_RUNNING;
  events[1].recorded_at_ms = 110u;
  check_int_eq(
      mesh_control_event_page_encode_v1(7u, 9u, events, 2u, output, sizeof(output), &output_size),
      MESH_CONTROL_OK);
  check_int_eq(mesh_control_event_page_decode_v1(output, output_size, &page), MESH_CONTROL_OK);
  check_int_eq(page.requested_cursor, 7u);
  check_int_eq(page.next_cursor, 9u);
  check_int_eq(page.event_count, 2u);
  check_int_eq(mesh_control_event_at_v1(&page, 1u, &decoded), MESH_CONTROL_OK);
  check_mem_eq(&decoded, &events[1], sizeof(decoded));
  check_int_eq(
      mesh_control_event_page_encode_v1(7u, 8u, NULL, 0u, output, sizeof(output), &output_size),
      MESH_CONTROL_INVALID_ARG);
  check_int_eq(
      mesh_control_event_page_encode_v1(7u, 10u, events, 2u, output, sizeof(output), &output_size),
      MESH_CONTROL_INVALID_ARG);
  events[1].cursor = 8u;
  check_int_eq(
      mesh_control_event_page_encode_v1(7u, 8u, events, 2u, output, sizeof(output), &output_size),
      MESH_CONTROL_INVALID_ARG);
}

static void test_durable_receipt_round_trips_and_rejects_tamper(void) {
  mesh_control_receipt_v1_t receipt = {0};
  mesh_control_receipt_v1_t decoded;
  uint8_t output[MESH_CONTROL_RECEIPT_SIZE_V1];
  size_t output_size = 0u;

  receipt.flags = MESH_CONTROL_RECEIPT_FLAG_DURABLE_V1;
  receipt.operation.operation_id[0] = 3u;
  receipt.operation.request_id[0] = 4u;
  memcpy(receipt.operation.message_id, receipt.operation.operation_id,
         sizeof(receipt.operation.message_id));
  receipt.operation.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  receipt.operation.action = MESH_CONTROL_DESIRED_APPLY;
  receipt.operation.state = MESH_CONTROL_OPERATION_ACCEPTED;
  receipt.operation.resource_id[0] = 5u;
  receipt.operation.desired_epoch = 6u;
  receipt.durable_through_index = 9u;
  receipt.state_generation = 10u;
  receipt.checkpoint_base_index = 7u;
  check_int_eq(mesh_control_receipt_encode_v1(&receipt, output, sizeof(output), &output_size),
               MESH_CONTROL_OK);
  check_size_eq(output_size, MESH_CONTROL_RECEIPT_SIZE_V1);
  check_int_eq(mesh_control_receipt_decode_v1(output, output_size, &decoded), MESH_CONTROL_OK);
  check_int_eq(decoded.flags, receipt.flags);
  check_mem_eq(decoded.operation.operation_id, receipt.operation.operation_id,
               sizeof(receipt.operation.operation_id));
  check_mem_eq(decoded.operation.request_id, receipt.operation.request_id,
               sizeof(receipt.operation.request_id));
  check_uint_eq(decoded.durable_through_index, 9u);
  check_uint_eq(decoded.state_generation, 10u);
  check_uint_eq(decoded.checkpoint_base_index, 7u);
  output[14] = 1u;
  check_int_eq(mesh_control_receipt_decode_v1(output, output_size, &decoded),
               MESH_CONTROL_INVALID_ARG);
}

spec("mesh control status page codec") {
  describe("canonical bounded snapshot pages") {
    it("round trips resources, operations and resume cursors") { test_status_page_round_trips(); }
    it("rejects insufficient capacity and inconsistent framing") {
      test_status_page_rejects_capacity_and_tamper();
    }
    it("round trips incremental operation events") { test_event_page_round_trips(); }
    it("round trips a canonical queryable durable receipt") {
      test_durable_receipt_round_trips_and_rejects_tamper();
    }
  }
}

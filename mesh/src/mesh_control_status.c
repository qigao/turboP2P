#include "mesh_control_status.h"

#include "mesh_mgmt_wire.h"

#include <limits.h>
#include <string.h>

static const uint8_t MESH_CONTROL_STATUS_MAGIC_V1[4] = {'T', 'C', 'S', '1'};
static const uint8_t MESH_CONTROL_EVENT_MAGIC_V1[4] = {'T', 'C', 'E', '1'};
static const uint8_t MESH_CONTROL_RECEIPT_MAGIC_V1[4] = {'T', 'C', 'R', '1'};

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int size_add(size_t left, size_t right, size_t *out_value) {
  if (out_value == NULL || left > SIZE_MAX - right)
    return 0;
  *out_value = left + right;
  return 1;
}

static int size_multiply(size_t left, size_t right, size_t *out_value) {
  if (out_value == NULL || (left != 0u && right > SIZE_MAX / left))
    return 0;
  *out_value = left * right;
  return 1;
}

static int info_valid(const mesh_control_snapshot_page_info_v1_t *info) {
  return info != NULL && info->generation != 0u && info->resource_total <= UINT32_MAX &&
         info->operation_total <= UINT32_MAX && info->resource_offset <= info->resource_total &&
         info->operation_offset <= info->operation_total &&
         info->resource_count <= info->resource_total - info->resource_offset &&
         info->operation_count <= info->operation_total - info->operation_offset &&
         info->resource_offset <= UINT32_MAX && info->operation_offset <= UINT32_MAX &&
         info->resource_count <= UINT16_MAX && info->operation_count <= UINT16_MAX;
}

static uint16_t page_flags(const mesh_control_snapshot_page_info_v1_t *info) {
  uint16_t flags = 0u;
  if (info->resource_count == info->resource_total - info->resource_offset)
    flags |= MESH_CONTROL_STATUS_FLAG_RESOURCES_COMPLETE;
  if (info->operation_count == info->operation_total - info->operation_offset)
    flags |= MESH_CONTROL_STATUS_FLAG_OPERATIONS_COMPLETE;
  return flags;
}

static void encode_resource(const mesh_control_resource_status_v1_t *record, uint8_t *output) {
  mesh_mgmt_wire_write_u16(output, record->resource_kind);
  mesh_mgmt_wire_write_u16(output + 2u, record->desired_presence);
  mesh_mgmt_wire_write_u16(output + 4u, record->observed_presence);
  mesh_mgmt_wire_write_u16(output + 6u, 0u);
  memcpy(output + 8u, record->resource_id, MESH_CONTROL_DIGEST_SIZE);
  mesh_mgmt_wire_write_u64(output + 40u, record->desired_epoch);
  mesh_mgmt_wire_write_u64(output + 48u, record->observed_epoch);
  memcpy(output + 56u, record->desired_digest, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 88u, record->observed_digest, MESH_CONTROL_DIGEST_SIZE);
}

static void encode_operation(const mesh_control_operation_v1_t *record, uint8_t *output) {
  memcpy(output, record->operation_id, MESH_CONTROL_ID_SIZE);
  memcpy(output + 16u, record->request_id, MESH_CONTROL_ID_SIZE);
  memcpy(output + 32u, record->message_id, MESH_CONTROL_ID_SIZE);
  mesh_mgmt_wire_write_u16(output + 48u, record->resource_kind);
  mesh_mgmt_wire_write_u16(output + 50u, record->action);
  mesh_mgmt_wire_write_u16(output + 52u, record->state);
  mesh_mgmt_wire_write_u16(output + 54u, 0u);
  memcpy(output + 56u, record->resource_id, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 88u, record->desired_digest, MESH_CONTROL_DIGEST_SIZE);
  mesh_mgmt_wire_write_u64(output + 120u, record->desired_epoch);
  mesh_mgmt_wire_write_u64(output + 128u, record->created_at_ms);
  mesh_mgmt_wire_write_u64(output + 136u, record->updated_at_ms);
}

mesh_control_result_t
mesh_control_status_page_encode_v1(const mesh_control_snapshot_page_info_v1_t *info,
                                   const mesh_control_resource_status_v1_t *resources,
                                   const mesh_control_operation_v1_t *operations, uint8_t *output,
                                   size_t output_capacity, size_t *out_size) {
  size_t resource_bytes;
  size_t operation_bytes;
  size_t required_size;
  size_t offset;
  size_t index;

  if (out_size == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = 0u;
  if (!info_valid(info) || (info->resource_count != 0u && resources == NULL) ||
      (info->operation_count != 0u && operations == NULL) ||
      !size_multiply(info->resource_count, MESH_CONTROL_STATUS_RESOURCE_RECORD_SIZE_V1,
                     &resource_bytes) ||
      !size_multiply(info->operation_count, MESH_CONTROL_STATUS_OPERATION_RECORD_SIZE_V1,
                     &operation_bytes) ||
      !size_add(MESH_CONTROL_STATUS_HEADER_SIZE_V1, resource_bytes, &required_size) ||
      !size_add(required_size, operation_bytes, &required_size) ||
      required_size > MESH_CONTROL_MAX_STATUS_SNAPSHOT_SIZE_V1) {
    return MESH_CONTROL_INVALID_ARG;
  }
  *out_size = required_size;
  if (output == NULL || output_capacity < required_size)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;

  memcpy(output, MESH_CONTROL_STATUS_MAGIC_V1, sizeof(MESH_CONTROL_STATUS_MAGIC_V1));
  mesh_mgmt_wire_write_u16(output + 4u, MESH_CONTROL_SCHEMA_V1);
  mesh_mgmt_wire_write_u16(output + 6u, page_flags(info));
  mesh_mgmt_wire_write_u64(output + 8u, info->generation);
  mesh_mgmt_wire_write_u64(output + 16u, info->event_cursor);
  mesh_mgmt_wire_write_u32(output + 24u, (uint32_t)info->resource_total);
  mesh_mgmt_wire_write_u32(output + 28u, (uint32_t)info->operation_total);
  mesh_mgmt_wire_write_u32(output + 32u, (uint32_t)info->resource_offset);
  mesh_mgmt_wire_write_u32(output + 36u, (uint32_t)info->operation_offset);
  mesh_mgmt_wire_write_u16(output + 40u, (uint16_t)info->resource_count);
  mesh_mgmt_wire_write_u16(output + 42u, (uint16_t)info->operation_count);
  offset = MESH_CONTROL_STATUS_HEADER_SIZE_V1;
  for (index = 0u; index < info->resource_count; ++index) {
    encode_resource(&resources[index], output + offset);
    offset += MESH_CONTROL_STATUS_RESOURCE_RECORD_SIZE_V1;
  }
  for (index = 0u; index < info->operation_count; ++index) {
    encode_operation(&operations[index], output + offset);
    offset += MESH_CONTROL_STATUS_OPERATION_RECORD_SIZE_V1;
  }
  return offset == required_size ? MESH_CONTROL_OK : MESH_CONTROL_INVALID_STATE;
}

mesh_control_result_t
mesh_control_status_page_decode_v1(const uint8_t *input, size_t input_size,
                                   mesh_control_status_page_view_v1_t *out_page) {
  size_t resource_bytes;
  size_t operation_bytes;
  size_t required_size;

  if (input == NULL || out_page == NULL || input_size < MESH_CONTROL_STATUS_HEADER_SIZE_V1 ||
      input_size > MESH_CONTROL_MAX_STATUS_SNAPSHOT_SIZE_V1)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_page, 0, sizeof(*out_page));
  if (memcmp(input, MESH_CONTROL_STATUS_MAGIC_V1, sizeof(MESH_CONTROL_STATUS_MAGIC_V1)) != 0 ||
      mesh_mgmt_wire_read_u16(input + 4u) != MESH_CONTROL_SCHEMA_V1)
    return MESH_CONTROL_INVALID_ARG;
  out_page->flags = mesh_mgmt_wire_read_u16(input + 6u);
  out_page->generation = mesh_mgmt_wire_read_u64(input + 8u);
  out_page->event_cursor = mesh_mgmt_wire_read_u64(input + 16u);
  out_page->resource_total = mesh_mgmt_wire_read_u32(input + 24u);
  out_page->operation_total = mesh_mgmt_wire_read_u32(input + 28u);
  out_page->resource_offset = mesh_mgmt_wire_read_u32(input + 32u);
  out_page->operation_offset = mesh_mgmt_wire_read_u32(input + 36u);
  out_page->resource_count = mesh_mgmt_wire_read_u16(input + 40u);
  out_page->operation_count = mesh_mgmt_wire_read_u16(input + 42u);
  if (out_page->generation == 0u || (out_page->flags & ~MESH_CONTROL_STATUS_FLAGS_KNOWN_V1) != 0u ||
      out_page->resource_offset > out_page->resource_total ||
      out_page->operation_offset > out_page->operation_total ||
      out_page->resource_count > out_page->resource_total - out_page->resource_offset ||
      out_page->operation_count > out_page->operation_total - out_page->operation_offset ||
      ((out_page->flags & MESH_CONTROL_STATUS_FLAG_RESOURCES_COMPLETE) != 0u) !=
          (out_page->resource_count == out_page->resource_total - out_page->resource_offset) ||
      ((out_page->flags & MESH_CONTROL_STATUS_FLAG_OPERATIONS_COMPLETE) != 0u) !=
          (out_page->operation_count == out_page->operation_total - out_page->operation_offset) ||
      !size_multiply(out_page->resource_count, MESH_CONTROL_STATUS_RESOURCE_RECORD_SIZE_V1,
                     &resource_bytes) ||
      !size_multiply(out_page->operation_count, MESH_CONTROL_STATUS_OPERATION_RECORD_SIZE_V1,
                     &operation_bytes) ||
      !size_add(MESH_CONTROL_STATUS_HEADER_SIZE_V1, resource_bytes, &required_size) ||
      !size_add(required_size, operation_bytes, &required_size) || required_size != input_size) {
    memset(out_page, 0, sizeof(*out_page));
    return MESH_CONTROL_INVALID_ARG;
  }
  out_page->resource_records = input + MESH_CONTROL_STATUS_HEADER_SIZE_V1;
  out_page->operation_records = out_page->resource_records + resource_bytes;
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_status_resource_at_v1(const mesh_control_status_page_view_v1_t *page, size_t index,
                                   mesh_control_resource_status_v1_t *out_resource) {
  const uint8_t *input;
  if (page == NULL || out_resource == NULL || index >= page->resource_count ||
      page->resource_records == NULL)
    return MESH_CONTROL_INVALID_ARG;
  input = page->resource_records + index * MESH_CONTROL_STATUS_RESOURCE_RECORD_SIZE_V1;
  memset(out_resource, 0, sizeof(*out_resource));
  out_resource->resource_kind = mesh_mgmt_wire_read_u16(input);
  out_resource->desired_presence = mesh_mgmt_wire_read_u16(input + 2u);
  out_resource->observed_presence = mesh_mgmt_wire_read_u16(input + 4u);
  if (mesh_mgmt_wire_read_u16(input + 6u) != 0u ||
      out_resource->resource_kind < MESH_CONTROL_RESOURCE_NODE ||
      out_resource->resource_kind > MESH_CONTROL_RESOURCE_RELEASE ||
      out_resource->desired_presence < MESH_CONTROL_PRESENCE_ABSENT ||
      out_resource->desired_presence > MESH_CONTROL_PRESENCE_PRESENT ||
      out_resource->observed_presence < MESH_CONTROL_PRESENCE_ABSENT ||
      out_resource->observed_presence > MESH_CONTROL_PRESENCE_PRESENT) {
    memset(out_resource, 0, sizeof(*out_resource));
    return MESH_CONTROL_INVALID_ARG;
  }
  memcpy(out_resource->resource_id, input + 8u, MESH_CONTROL_DIGEST_SIZE);
  out_resource->desired_epoch = mesh_mgmt_wire_read_u64(input + 40u);
  out_resource->observed_epoch = mesh_mgmt_wire_read_u64(input + 48u);
  memcpy(out_resource->desired_digest, input + 56u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_resource->observed_digest, input + 88u, MESH_CONTROL_DIGEST_SIZE);
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_status_operation_at_v1(const mesh_control_status_page_view_v1_t *page, size_t index,
                                    mesh_control_operation_v1_t *out_operation) {
  const uint8_t *input;
  if (page == NULL || out_operation == NULL || index >= page->operation_count ||
      page->operation_records == NULL)
    return MESH_CONTROL_INVALID_ARG;
  input = page->operation_records + index * MESH_CONTROL_STATUS_OPERATION_RECORD_SIZE_V1;
  memset(out_operation, 0, sizeof(*out_operation));
  memcpy(out_operation->operation_id, input, MESH_CONTROL_ID_SIZE);
  memcpy(out_operation->request_id, input + 16u, MESH_CONTROL_ID_SIZE);
  memcpy(out_operation->message_id, input + 32u, MESH_CONTROL_ID_SIZE);
  out_operation->resource_kind = mesh_mgmt_wire_read_u16(input + 48u);
  out_operation->action = mesh_mgmt_wire_read_u16(input + 50u);
  out_operation->state = mesh_mgmt_wire_read_u16(input + 52u);
  if (mesh_mgmt_wire_read_u16(input + 54u) != 0u ||
      out_operation->resource_kind < MESH_CONTROL_RESOURCE_NODE ||
      out_operation->resource_kind > MESH_CONTROL_RESOURCE_RELEASE ||
      out_operation->action < MESH_CONTROL_DESIRED_APPLY ||
      out_operation->action > MESH_CONTROL_DESIRED_DELETE ||
      out_operation->state < MESH_CONTROL_OPERATION_SUBMITTED ||
      out_operation->state > MESH_CONTROL_OPERATION_INTERRUPTED) {
    memset(out_operation, 0, sizeof(*out_operation));
    return MESH_CONTROL_INVALID_ARG;
  }
  memcpy(out_operation->resource_id, input + 56u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(out_operation->desired_digest, input + 88u, MESH_CONTROL_DIGEST_SIZE);
  out_operation->desired_epoch = mesh_mgmt_wire_read_u64(input + 120u);
  out_operation->created_at_ms = mesh_mgmt_wire_read_u64(input + 128u);
  out_operation->updated_at_ms = mesh_mgmt_wire_read_u64(input + 136u);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_event_page_encode_v1(uint64_t requested_cursor,
                                                        uint64_t next_cursor,
                                                        const mesh_control_event_v1_t *events,
                                                        size_t event_count, uint8_t *output,
                                                        size_t output_capacity, size_t *out_size) {
  size_t event_bytes;
  size_t required_size;
  size_t offset;
  size_t index;
  uint64_t previous_cursor = requested_cursor;

  if (out_size == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = 0u;
  if (event_count > UINT16_MAX || (event_count != 0u && events == NULL) ||
      (event_count == 0u && next_cursor != requested_cursor) ||
      (event_count != 0u && next_cursor <= requested_cursor) ||
      !size_multiply(event_count, MESH_CONTROL_EVENT_RECORD_SIZE_V1, &event_bytes) ||
      !size_add(MESH_CONTROL_EVENT_HEADER_SIZE_V1, event_bytes, &required_size) ||
      required_size > MESH_CONTROL_MAX_STATUS_SNAPSHOT_SIZE_V1)
    return MESH_CONTROL_INVALID_ARG;
  for (index = 0u; index < event_count; ++index) {
    if (events[index].cursor <= previous_cursor ||
        events[index].resource_kind < MESH_CONTROL_RESOURCE_NODE ||
        events[index].resource_kind > MESH_CONTROL_RESOURCE_RELEASE ||
        events[index].operation_state < MESH_CONTROL_OPERATION_SUBMITTED ||
        events[index].operation_state > MESH_CONTROL_OPERATION_INTERRUPTED)
      return MESH_CONTROL_INVALID_ARG;
    previous_cursor = events[index].cursor;
  }
  if (event_count != 0u && previous_cursor != next_cursor)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = required_size;
  if (output == NULL || output_capacity < required_size)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memcpy(output, MESH_CONTROL_EVENT_MAGIC_V1, sizeof(MESH_CONTROL_EVENT_MAGIC_V1));
  mesh_mgmt_wire_write_u16(output + 4u, MESH_CONTROL_SCHEMA_V1);
  mesh_mgmt_wire_write_u16(output + 6u, 0u);
  mesh_mgmt_wire_write_u64(output + 8u, requested_cursor);
  mesh_mgmt_wire_write_u64(output + 16u, next_cursor);
  mesh_mgmt_wire_write_u16(output + 24u, (uint16_t)event_count);
  mesh_mgmt_wire_write_u16(output + 26u, 0u);
  offset = MESH_CONTROL_EVENT_HEADER_SIZE_V1;
  for (index = 0u; index < event_count; ++index) {
    const mesh_control_event_v1_t *event = &events[index];
    mesh_mgmt_wire_write_u64(output + offset, event->cursor);
    memcpy(output + offset + 8u, event->operation_id, MESH_CONTROL_ID_SIZE);
    mesh_mgmt_wire_write_u16(output + offset + 24u, event->resource_kind);
    mesh_mgmt_wire_write_u16(output + offset + 26u, event->operation_state);
    memcpy(output + offset + 28u, event->resource_id, MESH_CONTROL_DIGEST_SIZE);
    mesh_mgmt_wire_write_u64(output + offset + 60u, event->desired_epoch);
    mesh_mgmt_wire_write_u64(output + offset + 68u, event->recorded_at_ms);
    offset += MESH_CONTROL_EVENT_RECORD_SIZE_V1;
  }
  return offset == required_size ? MESH_CONTROL_OK : MESH_CONTROL_INVALID_STATE;
}

mesh_control_result_t
mesh_control_event_page_decode_v1(const uint8_t *input, size_t input_size,
                                  mesh_control_event_page_view_v1_t *out_page) {
  size_t event_bytes;
  size_t required_size;
  size_t index;
  uint64_t previous_cursor;
  mesh_control_event_v1_t event;
  if (input == NULL || out_page == NULL || input_size < MESH_CONTROL_EVENT_HEADER_SIZE_V1 ||
      input_size > MESH_CONTROL_MAX_STATUS_SNAPSHOT_SIZE_V1)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_page, 0, sizeof(*out_page));
  if (memcmp(input, MESH_CONTROL_EVENT_MAGIC_V1, sizeof(MESH_CONTROL_EVENT_MAGIC_V1)) != 0 ||
      mesh_mgmt_wire_read_u16(input + 4u) != MESH_CONTROL_SCHEMA_V1 ||
      mesh_mgmt_wire_read_u16(input + 6u) != 0u || mesh_mgmt_wire_read_u16(input + 26u) != 0u)
    return MESH_CONTROL_INVALID_ARG;
  out_page->requested_cursor = mesh_mgmt_wire_read_u64(input + 8u);
  out_page->next_cursor = mesh_mgmt_wire_read_u64(input + 16u);
  out_page->event_count = mesh_mgmt_wire_read_u16(input + 24u);
  if ((out_page->event_count == 0u && out_page->next_cursor != out_page->requested_cursor) ||
      (out_page->event_count != 0u && out_page->next_cursor <= out_page->requested_cursor) ||
      !size_multiply(out_page->event_count, MESH_CONTROL_EVENT_RECORD_SIZE_V1, &event_bytes) ||
      !size_add(MESH_CONTROL_EVENT_HEADER_SIZE_V1, event_bytes, &required_size) ||
      required_size != input_size) {
    memset(out_page, 0, sizeof(*out_page));
    return MESH_CONTROL_INVALID_ARG;
  }
  out_page->event_records = input + MESH_CONTROL_EVENT_HEADER_SIZE_V1;
  previous_cursor = out_page->requested_cursor;
  for (index = 0u; index < out_page->event_count; ++index) {
    if (mesh_control_event_at_v1(out_page, index, &event) != MESH_CONTROL_OK ||
        event.cursor <= previous_cursor) {
      memset(out_page, 0, sizeof(*out_page));
      return MESH_CONTROL_INVALID_ARG;
    }
    previous_cursor = event.cursor;
  }
  if (out_page->event_count != 0u && previous_cursor != out_page->next_cursor) {
    memset(out_page, 0, sizeof(*out_page));
    return MESH_CONTROL_INVALID_ARG;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_event_at_v1(const mesh_control_event_page_view_v1_t *page,
                                               size_t index, mesh_control_event_v1_t *out_event) {
  const uint8_t *input;
  if (page == NULL || out_event == NULL || index >= page->event_count ||
      page->event_records == NULL)
    return MESH_CONTROL_INVALID_ARG;
  input = page->event_records + index * MESH_CONTROL_EVENT_RECORD_SIZE_V1;
  memset(out_event, 0, sizeof(*out_event));
  out_event->cursor = mesh_mgmt_wire_read_u64(input);
  memcpy(out_event->operation_id, input + 8u, MESH_CONTROL_ID_SIZE);
  out_event->resource_kind = mesh_mgmt_wire_read_u16(input + 24u);
  out_event->operation_state = mesh_mgmt_wire_read_u16(input + 26u);
  memcpy(out_event->resource_id, input + 28u, MESH_CONTROL_DIGEST_SIZE);
  out_event->desired_epoch = mesh_mgmt_wire_read_u64(input + 60u);
  out_event->recorded_at_ms = mesh_mgmt_wire_read_u64(input + 68u);
  if (out_event->cursor <= page->requested_cursor || out_event->cursor > page->next_cursor ||
      out_event->resource_kind < MESH_CONTROL_RESOURCE_NODE ||
      out_event->resource_kind > MESH_CONTROL_RESOURCE_RELEASE ||
      out_event->operation_state < MESH_CONTROL_OPERATION_SUBMITTED ||
      out_event->operation_state > MESH_CONTROL_OPERATION_INTERRUPTED) {
    memset(out_event, 0, sizeof(*out_event));
    return MESH_CONTROL_INVALID_ARG;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_receipt_encode_v1(const mesh_control_receipt_v1_t *receipt,
                                                     uint8_t *output, size_t output_capacity,
                                                     size_t *out_size) {
  const mesh_control_operation_v1_t *operation;
  if (!out_size)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = MESH_CONTROL_RECEIPT_SIZE_V1;
  if (!receipt || !output)
    return MESH_CONTROL_INVALID_ARG;
  if (output_capacity < MESH_CONTROL_RECEIPT_SIZE_V1)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  operation = &receipt->operation;
  if (receipt->flags != MESH_CONTROL_RECEIPT_FLAG_DURABLE_V1 ||
      receipt->durable_through_index == 0u || receipt->state_generation == 0u ||
      receipt->checkpoint_base_index > receipt->durable_through_index ||
      operation->state != MESH_CONTROL_OPERATION_ACCEPTED ||
      operation->resource_kind < MESH_CONTROL_RESOURCE_NODE ||
      operation->resource_kind > MESH_CONTROL_RESOURCE_RELEASE ||
      (operation->action != MESH_CONTROL_DESIRED_APPLY &&
       operation->action != MESH_CONTROL_DESIRED_DELETE) ||
      bytes_zero(operation->operation_id, sizeof(operation->operation_id)) ||
      bytes_zero(operation->request_id, sizeof(operation->request_id)) ||
      memcmp(operation->operation_id, operation->message_id, sizeof(operation->operation_id)) !=
          0) {
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(output, 0, MESH_CONTROL_RECEIPT_SIZE_V1);
  memcpy(output, MESH_CONTROL_RECEIPT_MAGIC_V1, sizeof(MESH_CONTROL_RECEIPT_MAGIC_V1));
  mesh_mgmt_wire_write_u16(output + 4u, MESH_CONTROL_SCHEMA_V1);
  mesh_mgmt_wire_write_u16(output + 6u, receipt->flags);
  mesh_mgmt_wire_write_u16(output + 8u, operation->state);
  mesh_mgmt_wire_write_u16(output + 10u, operation->resource_kind);
  mesh_mgmt_wire_write_u16(output + 12u, operation->action);
  memcpy(output + 16u, operation->operation_id, MESH_CONTROL_ID_SIZE);
  memcpy(output + 32u, operation->request_id, MESH_CONTROL_ID_SIZE);
  memcpy(output + 48u, operation->message_id, MESH_CONTROL_ID_SIZE);
  memcpy(output + 64u, operation->resource_id, MESH_CONTROL_DIGEST_SIZE);
  mesh_mgmt_wire_write_u64(output + 96u, operation->desired_epoch);
  mesh_mgmt_wire_write_u64(output + 104u, receipt->durable_through_index);
  mesh_mgmt_wire_write_u64(output + 112u, receipt->state_generation);
  mesh_mgmt_wire_write_u64(output + 120u, receipt->checkpoint_base_index);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_receipt_decode_v1(const uint8_t *input, size_t input_size,
                                                     mesh_control_receipt_v1_t *out_receipt) {
  mesh_control_receipt_v1_t receipt;
  uint8_t canonical[MESH_CONTROL_RECEIPT_SIZE_V1];
  size_t canonical_size = 0u;
  if (!input || !out_receipt || input_size != MESH_CONTROL_RECEIPT_SIZE_V1 ||
      memcmp(input, MESH_CONTROL_RECEIPT_MAGIC_V1, sizeof(MESH_CONTROL_RECEIPT_MAGIC_V1)) != 0 ||
      mesh_mgmt_wire_read_u16(input + 4u) != MESH_CONTROL_SCHEMA_V1 ||
      mesh_mgmt_wire_read_u16(input + 14u) != 0u) {
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(&receipt, 0, sizeof(receipt));
  receipt.flags = mesh_mgmt_wire_read_u16(input + 6u);
  receipt.operation.state = mesh_mgmt_wire_read_u16(input + 8u);
  receipt.operation.resource_kind = mesh_mgmt_wire_read_u16(input + 10u);
  receipt.operation.action = mesh_mgmt_wire_read_u16(input + 12u);
  memcpy(receipt.operation.operation_id, input + 16u, MESH_CONTROL_ID_SIZE);
  memcpy(receipt.operation.request_id, input + 32u, MESH_CONTROL_ID_SIZE);
  memcpy(receipt.operation.message_id, input + 48u, MESH_CONTROL_ID_SIZE);
  memcpy(receipt.operation.resource_id, input + 64u, MESH_CONTROL_DIGEST_SIZE);
  receipt.operation.desired_epoch = mesh_mgmt_wire_read_u64(input + 96u);
  receipt.durable_through_index = mesh_mgmt_wire_read_u64(input + 104u);
  receipt.state_generation = mesh_mgmt_wire_read_u64(input + 112u);
  receipt.checkpoint_base_index = mesh_mgmt_wire_read_u64(input + 120u);
  if (mesh_control_receipt_encode_v1(&receipt, canonical, sizeof(canonical), &canonical_size) !=
          MESH_CONTROL_OK ||
      canonical_size != input_size || memcmp(canonical, input, input_size) != 0) {
    return MESH_CONTROL_INVALID_ARG;
  }
  *out_receipt = receipt;
  return MESH_CONTROL_OK;
}

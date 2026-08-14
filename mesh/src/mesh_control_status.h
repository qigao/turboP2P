#ifndef MESH_CONTROL_STATUS_H
#define MESH_CONTROL_STATUS_H

#include "mesh_control_state.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_STATUS_MIME_V1 "application/vnd.turbo-mesh-status-v1"
#define MESH_CONTROL_EVENT_MIME_V1 "application/vnd.turbo-mesh-events-v1"
#define MESH_CONTROL_RECEIPT_MIME_V1 "application/vnd.turbo-mesh-receipt-v1"
#define MESH_CONTROL_STATUS_HEADER_SIZE_V1 44u
#define MESH_CONTROL_STATUS_RESOURCE_RECORD_SIZE_V1 120u
#define MESH_CONTROL_STATUS_OPERATION_RECORD_SIZE_V1 144u
#define MESH_CONTROL_EVENT_HEADER_SIZE_V1 28u
#define MESH_CONTROL_EVENT_RECORD_SIZE_V1 76u
#define MESH_CONTROL_RECEIPT_SIZE_V1 128u

#define MESH_CONTROL_RECEIPT_FLAG_DURABLE_V1 (1u << 0)

typedef struct {
  uint16_t flags;
  mesh_control_operation_v1_t operation;
  /** WAL/checkpoint fact source contains every mutation through this index. */
  uint64_t durable_through_index;
  uint64_t state_generation;
  uint64_t checkpoint_base_index;
} mesh_control_receipt_v1_t;

typedef enum {
  MESH_CONTROL_STATUS_FLAG_RESOURCES_COMPLETE = 1u << 0,
  MESH_CONTROL_STATUS_FLAG_OPERATIONS_COMPLETE = 1u << 1
} mesh_control_status_flags_v1_t;

#define MESH_CONTROL_STATUS_FLAGS_KNOWN_V1                                                         \
  (MESH_CONTROL_STATUS_FLAG_RESOURCES_COMPLETE | MESH_CONTROL_STATUS_FLAG_OPERATIONS_COMPLETE)

typedef struct {
  uint16_t flags;
  uint64_t generation;
  uint64_t event_cursor;
  uint32_t resource_total;
  uint32_t operation_total;
  uint32_t resource_offset;
  uint32_t resource_count;
  uint32_t operation_offset;
  uint32_t operation_count;
  const uint8_t *resource_records;
  const uint8_t *operation_records;
} mesh_control_status_page_view_v1_t;

typedef struct {
  uint64_t requested_cursor;
  uint64_t next_cursor;
  uint16_t event_count;
  const uint8_t *event_records;
} mesh_control_event_page_view_v1_t;

/**
 * Encodes one canonical, bounded status page. Input records are borrowed for
 * the call. out_size receives the required size even when capacity is too
 * small; no bytes are written on RESOURCE_EXHAUSTED.
 */
mesh_control_result_t
mesh_control_status_page_encode_v1(const mesh_control_snapshot_page_info_v1_t *info,
                                   const mesh_control_resource_status_v1_t *resources,
                                   const mesh_control_operation_v1_t *operations, uint8_t *output,
                                   size_t output_capacity, size_t *out_size);

/** Decodes a page and returns borrowed canonical record spans. */
mesh_control_result_t
mesh_control_status_page_decode_v1(const uint8_t *input, size_t input_size,
                                   mesh_control_status_page_view_v1_t *out_page);

mesh_control_result_t
mesh_control_status_resource_at_v1(const mesh_control_status_page_view_v1_t *page, size_t index,
                                   mesh_control_resource_status_v1_t *out_resource);

mesh_control_result_t
mesh_control_status_operation_at_v1(const mesh_control_status_page_view_v1_t *page, size_t index,
                                    mesh_control_operation_v1_t *out_operation);

mesh_control_result_t mesh_control_event_page_encode_v1(uint64_t requested_cursor,
                                                        uint64_t next_cursor,
                                                        const mesh_control_event_v1_t *events,
                                                        size_t event_count, uint8_t *output,
                                                        size_t output_capacity, size_t *out_size);

mesh_control_result_t
mesh_control_event_page_decode_v1(const uint8_t *input, size_t input_size,
                                  mesh_control_event_page_view_v1_t *out_page);

mesh_control_result_t mesh_control_event_at_v1(const mesh_control_event_page_view_v1_t *page,
                                               size_t index, mesh_control_event_v1_t *out_event);

mesh_control_result_t mesh_control_receipt_encode_v1(const mesh_control_receipt_v1_t *receipt,
                                                     uint8_t *output, size_t output_capacity,
                                                     size_t *out_size);

mesh_control_result_t mesh_control_receipt_decode_v1(const uint8_t *input, size_t input_size,
                                                     mesh_control_receipt_v1_t *out_receipt);

#ifdef __cplusplus
}
#endif

#endif

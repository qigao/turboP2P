#ifndef MESH_CONTROL_NETWORK_PROVIDER_H
#define MESH_CONTROL_NETWORK_PROVIDER_H

#include "mesh_control_state.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  mesh_control_operation_v1_t operation;
  uint64_t precondition_epoch;
  const uint8_t *document;
  size_t document_size;
} mesh_control_network_provider_request_v1_t;

typedef enum {
  MESH_CONTROL_NETWORK_PROVIDER_COMPLETED = 1,
  MESH_CONTROL_NETWORK_PROVIDER_FAILED = 2
} mesh_control_network_provider_completion_state_v1_t;

typedef struct {
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint16_t state;
} mesh_control_network_provider_completion_v1_t;

typedef struct {
  mesh_control_result_t (*try_start)(
      void *context,
      const mesh_control_network_provider_request_v1_t *request);
  mesh_control_result_t (*try_peek_completion)(
      void *context, mesh_control_network_provider_completion_v1_t *completion);
  mesh_control_result_t (*ack_completion)(
      void *context,
      const uint8_t operation_id[MESH_CONTROL_ID_SIZE]);
  void (*close)(void *context);
  int (*is_drained)(void *context);
} mesh_control_network_provider_ops_v1_t;

/**
 * Transport-neutral, single-owner Network mutation provider. The agent copies
 * this descriptor; context remains caller-owned. try_start must copy all
 * request data before returning and may retain only bounded internal state.
 */
typedef struct {
  mesh_control_network_provider_ops_v1_t ops;
  void *context;
} mesh_control_network_provider_v1_t;

#ifdef __cplusplus
}
#endif

#endif

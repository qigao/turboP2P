#include "mesh_node_ipc_network_executor.h"

#include <turbo_crypto.h>

#include <string.h>

static int bytes_equal(const uint8_t *left, const uint8_t *right,
                       size_t size) {
  return turbo_crypto_verify(left, right, size) == TURBO_CRYPTO_OK;
}

static const mesh_network_reconciler_record_v1_t *find_record(
    const mesh_network_reconciler_v1_t *reconciler,
    const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE]) {
  size_t index;
  if (!reconciler || !resource_id)
    return NULL;
  for (index = 0u; index < reconciler->count; ++index) {
    if (bytes_equal(reconciler->records[index].resource_id, resource_id,
                    MESH_CONTROL_DIGEST_SIZE))
      return &reconciler->records[index];
  }
  return NULL;
}

mesh_control_result_t mesh_node_ipc_network_executor_init_v1(
    mesh_node_ipc_network_executor_v1_t *executor,
    mesh_network_reconciler_v1_t *reconciler,
    const uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE],
    uint64_t delete_drain_timeout_ms) {
  static const uint8_t zeros[MESH_CONTROL_DIGEST_SIZE] = {0u};
  if (!executor || executor->initialized != 0u || !reconciler || !mesh_id ||
      delete_drain_timeout_ms == 0u ||
      bytes_equal(mesh_id, zeros, sizeof(zeros)))
    return MESH_CONTROL_INVALID_ARG;
  memset(executor, 0, sizeof(*executor));
  executor->reconciler = reconciler;
  memcpy(executor->mesh_id, mesh_id, sizeof(executor->mesh_id));
  executor->delete_drain_timeout_ms = delete_drain_timeout_ms;
  executor->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_network_execute_v1(
    void *context, const mesh_node_ipc_command_v1_t *command,
    uint64_t desired_epoch,
    mesh_node_ipc_execution_output_v1_t *out_execution) {
  mesh_node_ipc_network_executor_v1_t *executor =
      (mesh_node_ipc_network_executor_v1_t *)context;
  mesh_control_network_document_v1_t document;
  uint8_t document_digest[MESH_CONTROL_DIGEST_SIZE];
  uint64_t runtime_generation = 0u;
  mesh_control_result_t result;

  if (!executor || executor->initialized == 0u || !command ||
      !out_execution || desired_epoch == 0u)
    return MESH_CONTROL_INVALID_ARG;
  if (command->resource_kind != MESH_CONTROL_RESOURCE_NETWORK)
    return MESH_CONTROL_UNSUPPORTED;
  if (!bytes_equal(command->mesh_id, executor->mesh_id,
                   sizeof(executor->mesh_id)))
    return MESH_CONTROL_UNAUTHORIZED;

  memset(out_execution, 0, sizeof(*out_execution));
  if (command->action == MESH_CONTROL_DESIRED_APPLY) {
    const mesh_network_reconciler_record_v1_t *record;
    if (!command->document || command->document_size == 0u ||
        turbo_crypto_sha256(command->document, command->document_size,
                            document_digest) != TURBO_CRYPTO_OK ||
        !bytes_equal(document_digest, command->document_digest,
                     sizeof(document_digest)) ||
        mesh_control_network_document_decode_v1(
            command->document, command->document_size, &document) !=
            MESH_CONTROL_OK ||
        !bytes_equal(document.mesh_id, executor->mesh_id,
                     sizeof(executor->mesh_id)) ||
        document.generation != desired_epoch) {
      memset(document_digest, 0, sizeof(document_digest));
      return MESH_CONTROL_CONFLICT;
    }
    record = find_record(executor->reconciler, command->resource_id);
    if (record && record->generation == desired_epoch &&
        bytes_equal(record->document_digest, command->document_digest,
                    sizeof(record->document_digest))) {
      out_execution->applied_epoch = desired_epoch;
      memcpy(out_execution->observed_digest, command->document_digest,
             sizeof(out_execution->observed_digest));
      memset(document_digest, 0, sizeof(document_digest));
      return MESH_CONTROL_OK;
    }
    result = mesh_network_reconciler_submit_v1(
        executor->reconciler, command->resource_id,
        MESH_CONTROL_DESIRED_APPLY, command->precondition_epoch,
        command->document, command->document_size, 0u, &runtime_generation);
    if (result == MESH_CONTROL_OK) {
      if (runtime_generation != document.generation) {
        memset(document_digest, 0, sizeof(document_digest));
        return MESH_CONTROL_UNKNOWN_COMMIT;
      }
      out_execution->applied_epoch = desired_epoch;
      memcpy(out_execution->observed_digest, command->document_digest,
             sizeof(out_execution->observed_digest));
    }
    memset(document_digest, 0, sizeof(document_digest));
    return result;
  }

  if (command->action != MESH_CONTROL_DESIRED_DELETE || command->document ||
      command->document_size != 0u)
    return MESH_CONTROL_INVALID_ARG;
  result = mesh_network_reconciler_submit_v1(
      executor->reconciler, command->resource_id,
      MESH_CONTROL_DESIRED_DELETE, command->precondition_epoch, NULL, 0u,
      executor->delete_drain_timeout_ms, &runtime_generation);
  if (result == MESH_CONTROL_OK) {
    if (runtime_generation != command->precondition_epoch)
      return MESH_CONTROL_UNKNOWN_COMMIT;
    out_execution->applied_epoch = desired_epoch;
  }
  return result;
}

void mesh_node_ipc_network_executor_destroy_v1(
    mesh_node_ipc_network_executor_v1_t *executor) {
  if (!executor)
    return;
  memset(executor, 0, sizeof(*executor));
}

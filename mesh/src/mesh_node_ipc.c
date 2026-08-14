#include "mesh_node_ipc.h"

#include "mesh_mgmt_wire.h"

#include <turbo_crypto.h>

#include <string.h>

static const uint8_t MESH_NODE_IPC_MAGIC_V1[4] = {'M', 'N', 'I', 'P'};
static const uint8_t MESH_NODE_IPC_COMMAND_MAGIC_V1[4] = {'M', 'N', 'C', 'M'};
static const uint8_t MESH_NODE_IPC_RESULT_MAGIC_V1[4] = {'M', 'N', 'R', 'S'};

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int kind_valid(uint16_t kind) {
  return kind >= MESH_NODE_IPC_HELLO_V1 &&
         kind <= MESH_NODE_IPC_DRAINED_V1;
}

static int kind_requires_operation(uint16_t kind) {
  return kind == MESH_NODE_IPC_COMMAND_V1 ||
         kind == MESH_NODE_IPC_ACCEPTED_V1 ||
         kind == MESH_NODE_IPC_RESULT_V1 ||
         kind == MESH_NODE_IPC_ACK_RESULT_V1 ||
         kind == MESH_NODE_IPC_CANCEL_V1;
}

static int kind_allows_operation(uint16_t kind) {
  return kind_requires_operation(kind) || kind == MESH_NODE_IPC_QUERY_V1 ||
         kind == MESH_NODE_IPC_STATUS_V1;
}

static int kind_requires_epoch(uint16_t kind) {
  return kind == MESH_NODE_IPC_COMMAND_V1 ||
         kind == MESH_NODE_IPC_ACCEPTED_V1 ||
         kind == MESH_NODE_IPC_RESULT_V1 ||
         kind == MESH_NODE_IPC_CANCEL_V1;
}

static int kind_allows_epoch(uint16_t kind) {
  return kind_requires_epoch(kind) || kind == MESH_NODE_IPC_QUERY_V1 ||
         kind == MESH_NODE_IPC_STATUS_V1;
}

static int envelope_valid(const mesh_node_ipc_envelope_v1_t *envelope) {
  if (!envelope || envelope->minor != 0u || !kind_valid(envelope->kind) ||
      envelope->flags != 0u || bytes_zero(envelope->request_id,
                                          sizeof(envelope->request_id)) ||
      bytes_zero(envelope->sender_incarnation,
                 sizeof(envelope->sender_incarnation)) ||
      envelope->sequence == 0u ||
      envelope->body_size >
          MESH_NODE_IPC_MAX_FRAME_SIZE_V1 - MESH_NODE_IPC_HEADER_SIZE_V1 ||
      (envelope->body_size != 0u && !envelope->body))
    return 0;
  if ((kind_requires_operation(envelope->kind) &&
       bytes_zero(envelope->operation_id, sizeof(envelope->operation_id))) ||
      (!kind_allows_operation(envelope->kind) &&
       !bytes_zero(envelope->operation_id, sizeof(envelope->operation_id))))
    return 0;
  if ((kind_requires_epoch(envelope->kind) && envelope->desired_epoch == 0u) ||
      (!kind_allows_epoch(envelope->kind) && envelope->desired_epoch != 0u))
    return 0;
  switch (envelope->kind) {
    case MESH_NODE_IPC_COMMAND_V1:
      return envelope->body_size >= MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1;
    case MESH_NODE_IPC_ACCEPTED_V1:
    case MESH_NODE_IPC_ACK_RESULT_V1:
    case MESH_NODE_IPC_CANCEL_V1:
    case MESH_NODE_IPC_DRAIN_V1:
    case MESH_NODE_IPC_DRAINED_V1:
      return envelope->body_size == 0u;
    case MESH_NODE_IPC_RESULT_V1:
      return envelope->body_size == MESH_NODE_IPC_RESULT_SIZE_V1;
    default:
      break;
  }
  return 1;
}

static int message_digest(const uint8_t *header, const uint8_t *body,
                          size_t body_size, uint8_t out_digest[32]) {
  static const uint8_t zeros[32] = {0u};
  turbo_crypto_sha256_ctx_t hash;
  if (turbo_crypto_sha256_init(&hash) != TURBO_CRYPTO_OK ||
      turbo_crypto_sha256_update(&hash, header, 88u) != TURBO_CRYPTO_OK ||
      turbo_crypto_sha256_update(&hash, zeros, sizeof(zeros)) !=
          TURBO_CRYPTO_OK ||
      turbo_crypto_sha256_update(&hash, header + 120u, 8u) !=
          TURBO_CRYPTO_OK ||
      (body_size != 0u &&
       turbo_crypto_sha256_update(&hash, body, body_size) !=
           TURBO_CRYPTO_OK) ||
      turbo_crypto_sha256_final(&hash, out_digest) != TURBO_CRYPTO_OK)
    return 0;
  return 1;
}

mesh_control_result_t mesh_node_ipc_envelope_encode_v1(
    const mesh_node_ipc_envelope_v1_t *envelope, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  size_t total_size;
  uint8_t digest[32];
  if (out_size)
    *out_size = 0u;
  if (!output || !out_size || !envelope_valid(envelope))
    return MESH_CONTROL_INVALID_ARG;
  total_size = MESH_NODE_IPC_HEADER_SIZE_V1 + envelope->body_size;
  if (output_capacity < total_size)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memset(output, 0, total_size);
  memcpy(output, MESH_NODE_IPC_MAGIC_V1, sizeof(MESH_NODE_IPC_MAGIC_V1));
  mesh_mgmt_wire_write_u16(output + 4u, 1u);
  mesh_mgmt_wire_write_u16(output + 6u, envelope->minor);
  mesh_mgmt_wire_write_u16(output + 8u, envelope->kind);
  mesh_mgmt_wire_write_u16(output + 10u, envelope->flags);
  mesh_mgmt_wire_write_u16(output + 12u, MESH_NODE_IPC_HEADER_SIZE_V1);
  mesh_mgmt_wire_write_u32(output + 16u, (uint32_t)envelope->body_size);
  memcpy(output + 24u, envelope->request_id,
         sizeof(envelope->request_id));
  memcpy(output + 40u, envelope->operation_id,
         sizeof(envelope->operation_id));
  memcpy(output + 56u, envelope->sender_incarnation,
         sizeof(envelope->sender_incarnation));
  mesh_mgmt_wire_write_u64(output + 72u, envelope->sequence);
  mesh_mgmt_wire_write_u64(output + 80u, envelope->desired_epoch);
  if (envelope->body_size != 0u)
    memcpy(output + MESH_NODE_IPC_HEADER_SIZE_V1, envelope->body,
           envelope->body_size);
  if (!message_digest(output, output + MESH_NODE_IPC_HEADER_SIZE_V1,
                      envelope->body_size, digest)) {
    memset(output, 0, total_size);
    return MESH_CONTROL_INVALID_STATE;
  }
  memcpy(output + 88u, digest, sizeof(digest));
  memset(digest, 0, sizeof(digest));
  *out_size = total_size;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_envelope_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_node_ipc_envelope_v1_t *out_envelope) {
  mesh_node_ipc_envelope_v1_t decoded;
  uint8_t digest[32];
  size_t body_size;
  if (out_envelope)
    memset(out_envelope, 0, sizeof(*out_envelope));
  if (!input || !out_envelope || input_size < MESH_NODE_IPC_HEADER_SIZE_V1 ||
      memcmp(input, MESH_NODE_IPC_MAGIC_V1, sizeof(MESH_NODE_IPC_MAGIC_V1)) !=
          0 ||
      mesh_mgmt_wire_read_u16(input + 4u) != 1u ||
      mesh_mgmt_wire_read_u16(input + 12u) != MESH_NODE_IPC_HEADER_SIZE_V1 ||
      mesh_mgmt_wire_read_u16(input + 14u) != 0u ||
      mesh_mgmt_wire_read_u32(input + 20u) != 0u ||
      mesh_mgmt_wire_read_u64(input + 120u) != 0u)
    return MESH_CONTROL_INVALID_ARG;
  body_size = mesh_mgmt_wire_read_u32(input + 16u);
  if (body_size >
          MESH_NODE_IPC_MAX_FRAME_SIZE_V1 - MESH_NODE_IPC_HEADER_SIZE_V1 ||
      input_size != MESH_NODE_IPC_HEADER_SIZE_V1 + body_size ||
      !message_digest(input, input + MESH_NODE_IPC_HEADER_SIZE_V1, body_size,
                      digest) ||
      turbo_crypto_verify(digest, input + 88u, sizeof(digest)) !=
          TURBO_CRYPTO_OK) {
    memset(digest, 0, sizeof(digest));
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(&decoded, 0, sizeof(decoded));
  decoded.minor = mesh_mgmt_wire_read_u16(input + 6u);
  decoded.kind = mesh_mgmt_wire_read_u16(input + 8u);
  decoded.flags = mesh_mgmt_wire_read_u16(input + 10u);
  memcpy(decoded.request_id, input + 24u, sizeof(decoded.request_id));
  memcpy(decoded.operation_id, input + 40u, sizeof(decoded.operation_id));
  memcpy(decoded.sender_incarnation, input + 56u,
         sizeof(decoded.sender_incarnation));
  decoded.sequence = mesh_mgmt_wire_read_u64(input + 72u);
  decoded.desired_epoch = mesh_mgmt_wire_read_u64(input + 80u);
  decoded.body =
      body_size == 0u ? NULL : input + MESH_NODE_IPC_HEADER_SIZE_V1;
  decoded.body_size = body_size;
  memset(digest, 0, sizeof(digest));
  if (!envelope_valid(&decoded)) {
    memset(out_envelope, 0, sizeof(*out_envelope));
    return MESH_CONTROL_INVALID_ARG;
  }
  *out_envelope = decoded;
  return MESH_CONTROL_OK;
}

static int command_valid(const mesh_node_ipc_command_v1_t *command) {
  if (!command ||
      (command->action != MESH_CONTROL_DESIRED_APPLY &&
       command->action != MESH_CONTROL_DESIRED_DELETE) ||
      command->resource_kind == MESH_CONTROL_RESOURCE_NONE ||
      command->resource_kind > MESH_CONTROL_RESOURCE_RELEASE ||
      bytes_zero(command->mesh_id, sizeof(command->mesh_id)) ||
      bytes_zero(command->resource_id, sizeof(command->resource_id)) ||
      bytes_zero(command->provider_id, sizeof(command->provider_id)) ||
      command->document_size > MESH_NODE_IPC_MAX_FRAME_SIZE_V1 -
                                   MESH_NODE_IPC_HEADER_SIZE_V1 -
                                   MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1)
    return 0;
  if (command->action == MESH_CONTROL_DESIRED_APPLY)
    return command->document && command->document_size != 0u &&
           !bytes_zero(command->document_digest,
                       sizeof(command->document_digest));
  return !command->document && command->document_size == 0u &&
         bytes_zero(command->document_digest,
                    sizeof(command->document_digest));
}

mesh_control_result_t mesh_node_ipc_command_encode_v1(
    const mesh_node_ipc_command_v1_t *command, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  uint8_t digest[32];
  size_t total_size;
  if (out_size)
    *out_size = 0u;
  if (!output || !out_size || !command_valid(command))
    return MESH_CONTROL_INVALID_ARG;
  total_size = MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1 + command->document_size;
  if (output_capacity < total_size)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (command->document_size != 0u &&
      (turbo_crypto_sha256(command->document, command->document_size, digest) !=
           TURBO_CRYPTO_OK ||
       turbo_crypto_verify(digest, command->document_digest,
                           sizeof(digest)) != TURBO_CRYPTO_OK)) {
    memset(digest, 0, sizeof(digest));
    return MESH_CONTROL_CONFLICT;
  }
  memset(output, 0, total_size);
  memcpy(output, MESH_NODE_IPC_COMMAND_MAGIC_V1,
         sizeof(MESH_NODE_IPC_COMMAND_MAGIC_V1));
  mesh_mgmt_wire_write_u16(output + 4u, 1u);
  mesh_mgmt_wire_write_u16(output + 6u, command->action);
  mesh_mgmt_wire_write_u16(output + 8u, command->resource_kind);
  mesh_mgmt_wire_write_u64(output + 12u, command->precondition_epoch);
  memcpy(output + 20u, command->mesh_id, sizeof(command->mesh_id));
  memcpy(output + 52u, command->resource_id, sizeof(command->resource_id));
  memcpy(output + 84u, command->provider_id, sizeof(command->provider_id));
  memcpy(output + 116u, command->document_digest,
         sizeof(command->document_digest));
  mesh_mgmt_wire_write_u32(output + 148u, (uint32_t)command->document_size);
  if (command->document_size != 0u)
    memcpy(output + MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1, command->document,
           command->document_size);
  memset(digest, 0, sizeof(digest));
  *out_size = total_size;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_command_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_node_ipc_command_v1_t *out_command) {
  mesh_node_ipc_command_v1_t decoded;
  uint8_t digest[32];
  size_t document_size;
  if (out_command)
    memset(out_command, 0, sizeof(*out_command));
  if (!input || !out_command || input_size < MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1 ||
      memcmp(input, MESH_NODE_IPC_COMMAND_MAGIC_V1,
             sizeof(MESH_NODE_IPC_COMMAND_MAGIC_V1)) != 0 ||
      mesh_mgmt_wire_read_u16(input + 4u) != 1u ||
      mesh_mgmt_wire_read_u16(input + 10u) != 0u ||
      mesh_mgmt_wire_read_u32(input + 152u) != 0u)
    return MESH_CONTROL_INVALID_ARG;
  document_size = mesh_mgmt_wire_read_u32(input + 148u);
  if (document_size > MESH_NODE_IPC_MAX_FRAME_SIZE_V1 -
                          MESH_NODE_IPC_HEADER_SIZE_V1 -
                          MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1 ||
      input_size != MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1 + document_size)
    return MESH_CONTROL_INVALID_ARG;
  memset(&decoded, 0, sizeof(decoded));
  decoded.action = mesh_mgmt_wire_read_u16(input + 6u);
  decoded.resource_kind = mesh_mgmt_wire_read_u16(input + 8u);
  decoded.precondition_epoch = mesh_mgmt_wire_read_u64(input + 12u);
  memcpy(decoded.mesh_id, input + 20u, sizeof(decoded.mesh_id));
  memcpy(decoded.resource_id, input + 52u, sizeof(decoded.resource_id));
  memcpy(decoded.provider_id, input + 84u, sizeof(decoded.provider_id));
  memcpy(decoded.document_digest, input + 116u,
         sizeof(decoded.document_digest));
  decoded.document = document_size == 0u
                         ? NULL
                         : input + MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1;
  decoded.document_size = document_size;
  if (!command_valid(&decoded)) {
    memset(out_command, 0, sizeof(*out_command));
    return MESH_CONTROL_INVALID_ARG;
  }
  if (document_size != 0u &&
      (turbo_crypto_sha256(decoded.document, document_size, digest) !=
           TURBO_CRYPTO_OK ||
       turbo_crypto_verify(digest, decoded.document_digest,
                           sizeof(digest)) != TURBO_CRYPTO_OK)) {
    memset(digest, 0, sizeof(digest));
    memset(out_command, 0, sizeof(*out_command));
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(digest, 0, sizeof(digest));
  *out_command = decoded;
  return MESH_CONTROL_OK;
}

static int result_valid(const mesh_node_ipc_result_v1_t *result) {
  if (!result ||
      (result->outcome != MESH_NODE_IPC_OUTCOME_SUCCEEDED_V1 &&
       result->outcome != MESH_NODE_IPC_OUTCOME_FAILED_V1) ||
      result->stable_error > MESH_NODE_IPC_ERROR_TIMEOUT_V1 ||
      result->failure_stage > MESH_NODE_IPC_STAGE_RESULT_V1 ||
      result->resource_kind == MESH_CONTROL_RESOURCE_NONE ||
      result->resource_kind > MESH_CONTROL_RESOURCE_RELEASE ||
      (result->action != MESH_CONTROL_DESIRED_APPLY &&
       result->action != MESH_CONTROL_DESIRED_DELETE) ||
      bytes_zero(result->resource_id, sizeof(result->resource_id)))
    return 0;
  if (result->outcome == MESH_NODE_IPC_OUTCOME_SUCCEEDED_V1)
    return result->stable_error == MESH_NODE_IPC_ERROR_NONE_V1 &&
           result->failure_stage == MESH_NODE_IPC_STAGE_NONE_V1 &&
           result->applied_epoch != 0u &&
           ((result->action == MESH_CONTROL_DESIRED_APPLY) ==
            !bytes_zero(result->observed_digest,
                        sizeof(result->observed_digest)));
  return result->stable_error != MESH_NODE_IPC_ERROR_NONE_V1 &&
         result->failure_stage != MESH_NODE_IPC_STAGE_NONE_V1 &&
         result->applied_epoch == 0u &&
         bytes_zero(result->observed_digest,
                    sizeof(result->observed_digest));
}

mesh_control_result_t mesh_node_ipc_result_encode_v1(
    const mesh_node_ipc_result_v1_t *result,
    uint8_t output[MESH_NODE_IPC_RESULT_SIZE_V1]) {
  if (!output || !result_valid(result))
    return MESH_CONTROL_INVALID_ARG;
  memset(output, 0, MESH_NODE_IPC_RESULT_SIZE_V1);
  memcpy(output, MESH_NODE_IPC_RESULT_MAGIC_V1,
         sizeof(MESH_NODE_IPC_RESULT_MAGIC_V1));
  mesh_mgmt_wire_write_u16(output + 4u, 1u);
  mesh_mgmt_wire_write_u16(output + 6u, result->outcome);
  mesh_mgmt_wire_write_u16(output + 8u, result->stable_error);
  mesh_mgmt_wire_write_u16(output + 10u, result->failure_stage);
  mesh_mgmt_wire_write_u16(output + 12u, result->resource_kind);
  mesh_mgmt_wire_write_u16(output + 14u, result->action);
  mesh_mgmt_wire_write_u64(output + 16u, result->applied_epoch);
  memcpy(output + 24u, result->resource_id, sizeof(result->resource_id));
  memcpy(output + 56u, result->observed_digest,
         sizeof(result->observed_digest));
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_result_decode_v1(
    const uint8_t input[MESH_NODE_IPC_RESULT_SIZE_V1], size_t input_size,
    mesh_node_ipc_result_v1_t *out_result) {
  mesh_node_ipc_result_v1_t decoded;
  if (out_result)
    memset(out_result, 0, sizeof(*out_result));
  if (!input || !out_result || input_size != MESH_NODE_IPC_RESULT_SIZE_V1 ||
      memcmp(input, MESH_NODE_IPC_RESULT_MAGIC_V1,
             sizeof(MESH_NODE_IPC_RESULT_MAGIC_V1)) != 0 ||
      mesh_mgmt_wire_read_u16(input + 4u) != 1u ||
      mesh_mgmt_wire_read_u64(input + 88u) != 0u)
    return MESH_CONTROL_INVALID_ARG;
  memset(&decoded, 0, sizeof(decoded));
  decoded.outcome = mesh_mgmt_wire_read_u16(input + 6u);
  decoded.stable_error = mesh_mgmt_wire_read_u16(input + 8u);
  decoded.failure_stage = mesh_mgmt_wire_read_u16(input + 10u);
  decoded.resource_kind = mesh_mgmt_wire_read_u16(input + 12u);
  decoded.action = mesh_mgmt_wire_read_u16(input + 14u);
  decoded.applied_epoch = mesh_mgmt_wire_read_u64(input + 16u);
  memcpy(decoded.resource_id, input + 24u, sizeof(decoded.resource_id));
  memcpy(decoded.observed_digest, input + 56u,
         sizeof(decoded.observed_digest));
  if (!result_valid(&decoded)) {
    memset(out_result, 0, sizeof(*out_result));
    return MESH_CONTROL_INVALID_ARG;
  }
  *out_result = decoded;
  return MESH_CONTROL_OK;
}

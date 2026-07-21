#include "mesh_mgmt_peer_signer.h"

#include "mesh_mgmt_crypto.h"

#include <platform.h>

#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  size_t index;
  uint8_t combined = 0u;

  for (index = 0u; index < length; index++)
    combined |= bytes[index];
  return combined == 0u;
}

static uint64_t signer_now_ms(mesh_mgmt_peer_signer_v1_t *signer) {
  return signer->now_ms ? signer->now_ms(signer->callback_context) : turbo_realtime_ms();
}

static int signer_random_bytes(mesh_mgmt_peer_signer_v1_t *signer, uint8_t *output,
                               size_t output_len) {
  return signer->random_bytes ? signer->random_bytes(signer->callback_context, output, output_len)
                              : turbo_secure_random(output, output_len);
}

static mesh_mgmt_peer_signer_result_t signer_require_ready(mesh_mgmt_peer_signer_v1_t *signer,
                                                           const uint8_t **out_frame,
                                                           size_t *out_frame_len) {
  if (out_frame)
    *out_frame = NULL;
  if (out_frame_len)
    *out_frame_len = 0u;
  if (!signer || !out_frame || !out_frame_len)
    return MESH_MGMT_PEER_SIGNER_INVALID_ARG;
  if (signer->state != MESH_MGMT_PEER_SIGNER_READY || signer->in_build)
    return MESH_MGMT_PEER_SIGNER_INVALID_STATE;
  return MESH_MGMT_PEER_SIGNER_OK;
}

static int local_identity_matches(const mesh_mgmt_peer_signer_config_v1_t *config,
                                  const mesh_mgmt_certificate_v1_t *certificate,
                                  const uint8_t management_key[32], const uint8_t issuer_hash[32]) {
  return certificate->principal_type == MESH_MGMT_PRINCIPAL_NODE &&
         config->hello.principal_type == certificate->principal_type &&
         mesh_mgmt_crypto_equal_32(management_key, certificate->management_key) &&
         mesh_mgmt_crypto_equal_32(management_key, config->hello.management_key) &&
         mesh_mgmt_crypto_equal_32(config->local_transport_peer_id,
                                   certificate->transport_peer_id) &&
         mesh_mgmt_crypto_equal_32(config->hello.managed_node_id, certificate->managed_node_id) &&
         mesh_mgmt_crypto_equal_32(config->expected_mesh_id_hash, certificate->mesh_id_hash) &&
         mesh_mgmt_crypto_equal_32(issuer_hash, config->hello.issuer_chain_hash) &&
         certificate->principal_epoch != 0u && certificate->serial != 0u;
}

mesh_mgmt_peer_signer_result_t
mesh_mgmt_peer_signer_init_v1(mesh_mgmt_peer_signer_v1_t *signer,
                              const mesh_mgmt_peer_signer_config_v1_t *config) {
  mesh_mgmt_certificate_v1_t certificate;
  mesh_mgmt_identity_result_t identity_result;
  mesh_mgmt_session_result_t session_result;
  uint8_t management_key[32];
  uint8_t issuer_hash[32];
  uint8_t hello_payload[MESH_MGMT_HELLO_V1_MAX_SIZE];
  size_t hello_payload_len = 0u;
  uint64_t now_ms;

  if (!signer || !config)
    return MESH_MGMT_PEER_SIGNER_INVALID_ARG;
  if (signer->state != MESH_MGMT_PEER_SIGNER_UNINITIALIZED || signer->in_build)
    return MESH_MGMT_PEER_SIGNER_INVALID_STATE;
  if (bytes_are_zero(config->private_key, sizeof(config->private_key)) ||
      bytes_are_zero(config->trusted_issuer_key, sizeof(config->trusted_issuer_key)) ||
      bytes_are_zero(config->expected_mesh_id_hash, sizeof(config->expected_mesh_id_hash)) ||
      bytes_are_zero(config->local_transport_peer_id, sizeof(config->local_transport_peer_id)) ||
      bytes_are_zero(config->session_id, sizeof(config->session_id)) || config->incarnation == 0u ||
      config->first_sequence == 0u || config->frame_ttl_ms == 0u ||
      config->frame_ttl_ms > MESH_MGMT_PEER_SIGNER_FRAME_TTL_MAX_MS)
    return MESH_MGMT_PEER_SIGNER_INVALID_ARG;

  memset(&certificate, 0, sizeof(certificate));
  memset(management_key, 0, sizeof(management_key));
  memset(issuer_hash, 0, sizeof(issuer_hash));
  memset(hello_payload, 0, sizeof(hello_payload));
  session_result = mesh_mgmt_hello_encode_v1(&config->hello, hello_payload, sizeof(hello_payload),
                                             &hello_payload_len);
  if (session_result != MESH_MGMT_SESSION_OK) {
    mesh_mgmt_crypto_wipe(hello_payload, sizeof(hello_payload));
    return MESH_MGMT_PEER_SIGNER_ENCODE_FAILED;
  }
  if (mesh_mgmt_ed25519_public_from_private(config->private_key, management_key) !=
          MESH_MGMT_CRYPTO_OK ||
      mesh_mgmt_blake2b_256(config->trusted_issuer_key, sizeof(config->trusted_issuer_key),
                            issuer_hash) != MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_crypto_wipe(management_key, sizeof(management_key));
    mesh_mgmt_crypto_wipe(issuer_hash, sizeof(issuer_hash));
    mesh_mgmt_crypto_wipe(hello_payload, sizeof(hello_payload));
    return MESH_MGMT_PEER_SIGNER_IDENTITY_FAILED;
  }
  signer->in_build = 1u;
  now_ms = config->now_ms ? config->now_ms(config->callback_context) : turbo_realtime_ms();
  signer->in_build = 0u;
  identity_result = mesh_mgmt_certificate_verify_v1(
      config->hello.certificate, sizeof(config->hello.certificate), config->trusted_issuer_key,
      config->expected_mesh_id_hash, now_ms, &certificate);
  if (identity_result != MESH_MGMT_IDENTITY_OK ||
      !local_identity_matches(config, &certificate, management_key, issuer_hash)) {
    mesh_mgmt_crypto_wipe(&certificate, sizeof(certificate));
    mesh_mgmt_crypto_wipe(management_key, sizeof(management_key));
    mesh_mgmt_crypto_wipe(issuer_hash, sizeof(issuer_hash));
    mesh_mgmt_crypto_wipe(hello_payload, sizeof(hello_payload));
    return MESH_MGMT_PEER_SIGNER_IDENTITY_FAILED;
  }

  memset(signer, 0, sizeof(*signer));
  memcpy(signer->private_key, config->private_key, sizeof(signer->private_key));
  memcpy(signer->mesh_id_hash, config->expected_mesh_id_hash, sizeof(signer->mesh_id_hash));
  memcpy(signer->origin_node_id, certificate.managed_node_id, sizeof(signer->origin_node_id));
  memcpy(signer->session_id, config->session_id, sizeof(signer->session_id));
  signer->hello = config->hello;
  signer->principal_epoch = certificate.principal_epoch;
  signer->incarnation = config->incarnation;
  signer->certificate_serial = certificate.serial;
  signer->next_sequence = config->first_sequence;
  signer->frame_ttl_ms = config->frame_ttl_ms;
  signer->now_ms = config->now_ms;
  signer->random_bytes = config->random_bytes;
  signer->callback_context = config->callback_context;
  signer->state = MESH_MGMT_PEER_SIGNER_READY;
  signer->last_error = MESH_MGMT_PEER_SIGNER_OK;
  signer->last_identity_result = MESH_MGMT_IDENTITY_OK;
  signer->last_session_result = MESH_MGMT_SESSION_OK;
  signer->last_envelope_result = MESH_MGMT_ENVELOPE_OK;

  mesh_mgmt_crypto_wipe(&certificate, sizeof(certificate));
  mesh_mgmt_crypto_wipe(management_key, sizeof(management_key));
  mesh_mgmt_crypto_wipe(issuer_hash, sizeof(issuer_hash));
  mesh_mgmt_crypto_wipe(hello_payload, sizeof(hello_payload));
  return MESH_MGMT_PEER_SIGNER_OK;
}

void mesh_mgmt_peer_signer_destroy_v1(mesh_mgmt_peer_signer_v1_t *signer) {
  if (!signer || signer->in_build)
    return;
  mesh_mgmt_crypto_wipe(signer, sizeof(*signer));
}

static mesh_mgmt_peer_signer_result_t
signer_build_frame(mesh_mgmt_peer_signer_v1_t *signer, uint8_t kind, const uint8_t *payload,
                   size_t payload_len, const uint8_t **out_frame, size_t *out_frame_len) {
  mesh_mgmt_sign_input_v1_t input;
  mesh_mgmt_envelope_result_t envelope_result;
  uint64_t now_ms;
  int random_result;

  memset(&input, 0, sizeof(input));
  signer->in_build = 1u;
  now_ms = signer_now_ms(signer);
  if (now_ms > UINT64_MAX - signer->frame_ttl_ms) {
    signer->in_build = 0u;
    signer->last_error = MESH_MGMT_PEER_SIGNER_INVALID_STATE;
    return signer->last_error;
  }
  random_result =
      signer_random_bytes(signer, input.header.message_id, sizeof(input.header.message_id));
  signer->last_random_result = random_result;
  if (random_result != 0 ||
      bytes_are_zero(input.header.message_id, sizeof(input.header.message_id))) {
    signer->in_build = 0u;
    signer->last_error = MESH_MGMT_PEER_SIGNER_RANDOM_FAILED;
    return signer->last_error;
  }
  input.minor = MESH_MGMT_MINOR_V1;
  input.kind = kind;
  input.private_key = signer->private_key;
  input.payload = payload;
  input.payload_len = payload_len;
  memcpy(input.header.mesh_id_hash, signer->mesh_id_hash, sizeof(input.header.mesh_id_hash));
  memcpy(input.header.origin_node_id, signer->origin_node_id, sizeof(input.header.origin_node_id));
  input.header.principal_epoch = signer->principal_epoch;
  input.header.incarnation = signer->incarnation;
  memcpy(input.header.session_id, signer->session_id, sizeof(input.header.session_id));
  input.header.origin_sequence = signer->next_sequence;
  input.header.issued_at_ms = now_ms;
  input.header.expires_at_ms = now_ms + signer->frame_ttl_ms;
  input.header.certificate_serial = signer->certificate_serial;

  signer->frame_len = 0u;
  envelope_result =
      mesh_mgmt_envelope_sign_v1(&input, signer->frame, sizeof(signer->frame), &signer->frame_len);
  signer->last_envelope_result = envelope_result;
  signer->in_build = 0u;
  if (envelope_result != MESH_MGMT_ENVELOPE_OK) {
    signer->last_error = MESH_MGMT_PEER_SIGNER_SIGN_FAILED;
    return signer->last_error;
  }
  signer->next_sequence++;
  *out_frame = signer->frame;
  *out_frame_len = signer->frame_len;
  signer->last_error = MESH_MGMT_PEER_SIGNER_OK;
  return MESH_MGMT_PEER_SIGNER_OK;
}

int mesh_mgmt_peer_signer_build_hello_v1(void *context, const uint8_t **out_frame,
                                         size_t *out_frame_len) {
  mesh_mgmt_peer_signer_v1_t *signer = (mesh_mgmt_peer_signer_v1_t *)context;
  mesh_mgmt_peer_signer_result_t result = signer_require_ready(signer, out_frame, out_frame_len);
  uint8_t payload[MESH_MGMT_HELLO_V1_MAX_SIZE];
  size_t payload_len = 0u;

  if (result != MESH_MGMT_PEER_SIGNER_OK)
    return result;
  if (signer->hello_built)
    return MESH_MGMT_PEER_SIGNER_INVALID_STATE;
  memset(payload, 0, sizeof(payload));
  signer->last_session_result =
      mesh_mgmt_hello_encode_v1(&signer->hello, payload, sizeof(payload), &payload_len);
  if (signer->last_session_result != MESH_MGMT_SESSION_OK) {
    mesh_mgmt_crypto_wipe(payload, sizeof(payload));
    signer->last_error = MESH_MGMT_PEER_SIGNER_ENCODE_FAILED;
    return signer->last_error;
  }
  result = signer_build_frame(signer, MESH_MGMT_KIND_HELLO, payload, payload_len, out_frame,
                              out_frame_len);
  mesh_mgmt_crypto_wipe(payload, sizeof(payload));
  if (result == MESH_MGMT_PEER_SIGNER_OK)
    signer->hello_built = 1u;
  return result;
}

int mesh_mgmt_peer_signer_build_ack_v1(void *context, const mesh_mgmt_hello_ack_v1_t *ack,
                                       const uint8_t **out_frame, size_t *out_frame_len) {
  mesh_mgmt_peer_signer_v1_t *signer = (mesh_mgmt_peer_signer_v1_t *)context;
  mesh_mgmt_peer_signer_result_t result = signer_require_ready(signer, out_frame, out_frame_len);
  uint8_t payload[MESH_MGMT_HELLO_ACK_V1_SIZE];
  size_t payload_len = 0u;

  if (result != MESH_MGMT_PEER_SIGNER_OK)
    return result;
  if (!ack)
    return MESH_MGMT_PEER_SIGNER_INVALID_ARG;
  if (!signer->hello_built || signer->ack_built)
    return MESH_MGMT_PEER_SIGNER_INVALID_STATE;
  memset(payload, 0, sizeof(payload));
  signer->last_session_result =
      mesh_mgmt_hello_ack_encode_v1(ack, payload, sizeof(payload), &payload_len);
  if (signer->last_session_result != MESH_MGMT_SESSION_OK) {
    mesh_mgmt_crypto_wipe(payload, sizeof(payload));
    signer->last_error = MESH_MGMT_PEER_SIGNER_ENCODE_FAILED;
    return signer->last_error;
  }
  result = signer_build_frame(signer, MESH_MGMT_KIND_HELLO_ACK, payload, payload_len, out_frame,
                              out_frame_len);
  mesh_mgmt_crypto_wipe(payload, sizeof(payload));
  if (result == MESH_MGMT_PEER_SIGNER_OK)
    signer->ack_built = 1u;
  return result;
}

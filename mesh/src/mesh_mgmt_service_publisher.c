#include "mesh_mgmt_service_publisher.h"

#include <platform.h>

#include <limits.h>
#include <string.h>

static uint64_t publisher_now_ms(mesh_mgmt_service_publisher_v1_t *publisher) {
  return publisher->signer.now_ms ? publisher->signer.now_ms(publisher->signer.callback_context)
                                  : turbo_realtime_ms();
}

static int publisher_random(mesh_mgmt_service_publisher_v1_t *publisher, uint8_t *output,
                            size_t output_len) {
  return publisher->signer.random_bytes
             ? publisher->signer.random_bytes(publisher->signer.callback_context, output,
                                              output_len)
             : turbo_secure_random(output, output_len);
}

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  size_t index;
  uint8_t combined = 0u;

  for (index = 0u; index < length; index++)
    combined |= bytes[index];
  return combined == 0u;
}

static size_t bounded_dns_length(const char *dns_name) {
  size_t length;

  for (length = 0u; length <= MESH_MGMT_SERVICE_DNS_NAME_MAX && dns_name[length] != '\0';
       length++) {
  }
  return length;
}

static mesh_mgmt_service_publisher_result_t
publisher_finish(mesh_mgmt_service_publisher_v1_t *publisher,
                 mesh_mgmt_service_publisher_result_t result) {
  publisher->in_api = 0u;
  publisher->last_error = result;
  return result;
}

mesh_mgmt_service_publisher_result_t
mesh_mgmt_service_publisher_init_v1(mesh_mgmt_service_publisher_v1_t *publisher, p2p_node_t *node,
                                    const mesh_mgmt_peer_signer_config_v1_t *signer_config,
                                    uint64_t first_record_epoch) {
  mesh_mgmt_peer_signer_v1_t signer;
  mesh_mgmt_certificate_v1_t certificate;
  uint8_t local_transport_peer_id[P2P_KEY_SIZE];
  uint64_t now_ms;

  if (!publisher || !node || !signer_config || first_record_epoch == 0u)
    return MESH_MGMT_SERVICE_PUBLISHER_INVALID_ARG;
  if (publisher->state != MESH_MGMT_SERVICE_PUBLISHER_UNINITIALIZED || publisher->node ||
      publisher->signer.state != MESH_MGMT_PEER_SIGNER_UNINITIALIZED || publisher->in_api)
    return MESH_MGMT_SERVICE_PUBLISHER_INVALID_STATE;

  memset(&signer, 0, sizeof(signer));
  memset(&certificate, 0, sizeof(certificate));
  memset(local_transport_peer_id, 0, sizeof(local_transport_peer_id));
  if (p2p_node_get_public_key(node, local_transport_peer_id) != P2P_OK ||
      !mesh_mgmt_crypto_equal_32(local_transport_peer_id, signer_config->local_transport_peer_id)) {
    mesh_mgmt_crypto_wipe(local_transport_peer_id, sizeof(local_transport_peer_id));
    return MESH_MGMT_SERVICE_PUBLISHER_IDENTITY_FAILED;
  }
  mesh_mgmt_crypto_wipe(local_transport_peer_id, sizeof(local_transport_peer_id));
  if (mesh_mgmt_peer_signer_init_v1(&signer, signer_config) != MESH_MGMT_PEER_SIGNER_OK) {
    mesh_mgmt_crypto_wipe(&signer, sizeof(signer));
    return MESH_MGMT_SERVICE_PUBLISHER_IDENTITY_FAILED;
  }

  now_ms = signer.now_ms ? signer.now_ms(signer.callback_context) : turbo_realtime_ms();
  if (mesh_mgmt_certificate_verify_v1(
          signer_config->hello.certificate, sizeof(signer_config->hello.certificate),
          signer_config->trusted_issuer_key, signer_config->expected_mesh_id_hash, now_ms,
          &certificate) != MESH_MGMT_IDENTITY_OK ||
      now_ms > UINT64_MAX - signer.frame_ttl_ms ||
      certificate.expires_at_ms < now_ms + signer.frame_ttl_ms) {
    mesh_mgmt_peer_signer_destroy_v1(&signer);
    mesh_mgmt_crypto_wipe(&certificate, sizeof(certificate));
    return MESH_MGMT_SERVICE_PUBLISHER_IDENTITY_FAILED;
  }

  memset(publisher, 0, sizeof(*publisher));
  publisher->node = node;
  publisher->signer = signer;
  publisher->certificate_expires_at_ms = certificate.expires_at_ms;
  publisher->next_record_epoch = first_record_epoch;
  publisher->state = MESH_MGMT_SERVICE_PUBLISHER_READY;
  publisher->last_error = MESH_MGMT_SERVICE_PUBLISHER_OK;
  publisher->last_record_result = MESH_MGMT_SERVICE_RECORD_OK;
  publisher->last_envelope_result = MESH_MGMT_ENVELOPE_OK;
  publisher->last_p2p_result = P2P_OK;
  mesh_mgmt_crypto_wipe(&signer, sizeof(signer));
  mesh_mgmt_crypto_wipe(&certificate, sizeof(certificate));
  return MESH_MGMT_SERVICE_PUBLISHER_OK;
}

mesh_mgmt_service_publisher_result_t mesh_mgmt_service_publisher_set_epoch_allocator_v1(
    mesh_mgmt_service_publisher_v1_t *publisher,
    mesh_mgmt_record_epoch_allocate_fn allocate_record_epoch,
    void *record_epoch_context) {
  if (!publisher || !allocate_record_epoch)
    return MESH_MGMT_SERVICE_PUBLISHER_INVALID_ARG;
  if (publisher->state != MESH_MGMT_SERVICE_PUBLISHER_READY || publisher->in_api)
    return MESH_MGMT_SERVICE_PUBLISHER_INVALID_STATE;
  publisher->allocate_record_epoch = allocate_record_epoch;
  publisher->record_epoch_context = record_epoch_context;
  return MESH_MGMT_SERVICE_PUBLISHER_OK;
}

mesh_mgmt_service_publisher_result_t
mesh_mgmt_service_publisher_publish_cached_v1(mesh_mgmt_service_publisher_v1_t *publisher,
                                              const mesh_mgmt_service_publish_v1_t *service,
                                              uint64_t *out_record_epoch) {
  mesh_mgmt_service_announcement_v1_t announcement;
  mesh_mgmt_sign_input_v1_t sign_input;
  uint8_t payload[MESH_MGMT_SERVICE_RECORD_V1_MAX_SIZE];
  uint8_t frame[MESH_MGMT_SERVICE_FRAME_V1_MAX];
  char key[MESH_MGMT_SERVICE_DHT_KEY_V1_SIZE];
  size_t dns_length;
  size_t payload_len = 0u;
  size_t frame_len = 0u;
  size_t key_len = 0u;
  uint64_t now_ms;
  uint64_t record_epoch;

  if (!out_record_epoch)
    return MESH_MGMT_SERVICE_PUBLISHER_INVALID_ARG;
  *out_record_epoch = 0u;
  if (!publisher || !service || !service->dns_name)
    return MESH_MGMT_SERVICE_PUBLISHER_INVALID_ARG;
  if (publisher->state != MESH_MGMT_SERVICE_PUBLISHER_READY || publisher->in_api ||
      !publisher->node || publisher->signer.state != MESH_MGMT_PEER_SIGNER_READY)
    return MESH_MGMT_SERVICE_PUBLISHER_INVALID_STATE;
  if (publisher->sequence_exhausted || publisher->next_record_epoch == 0u)
    return MESH_MGMT_SERVICE_PUBLISHER_RESOURCE_EXHAUSTED;

  dns_length = bounded_dns_length(service->dns_name);
  if (dns_length > MESH_MGMT_SERVICE_DNS_NAME_MAX)
    return MESH_MGMT_SERVICE_PUBLISHER_ENCODE_FAILED;

  publisher->in_api = 1u;
  now_ms = publisher_now_ms(publisher);
  if (now_ms > UINT64_MAX - publisher->signer.frame_ttl_ms ||
      publisher->certificate_expires_at_ms < now_ms + publisher->signer.frame_ttl_ms)
    return publisher_finish(publisher, MESH_MGMT_SERVICE_PUBLISHER_IDENTITY_FAILED);

  record_epoch = publisher->next_record_epoch;
  if (publisher->allocate_record_epoch) {
    if (publisher->allocate_record_epoch(publisher->record_epoch_context, &record_epoch) != 0 ||
        record_epoch < publisher->next_record_epoch) {
      return publisher_finish(publisher, MESH_MGMT_SERVICE_PUBLISHER_EPOCH_FAILED);
    }
    if (record_epoch == UINT64_MAX)
      publisher->sequence_exhausted = 1u;
    else
      publisher->next_record_epoch = record_epoch + 1u;
  }
  memset(&announcement, 0, sizeof(announcement));
  memcpy(announcement.owner_node_id, publisher->signer.origin_node_id,
         sizeof(announcement.owner_node_id));
  announcement.service_type = MESH_MGMT_SERVICE_RPC;
  announcement.address_family = (mesh_mgmt_service_address_family_t)service->address_family;
  memcpy(announcement.virtual_address, service->virtual_address,
         sizeof(announcement.virtual_address));
  memcpy(announcement.dns_name, service->dns_name, dns_length + 1u);
  announcement.port = service->port;
  announcement.record_epoch = record_epoch;
  announcement.expires_at_ms = now_ms + publisher->signer.frame_ttl_ms;

  memset(payload, 0, sizeof(payload));
  publisher->last_record_result =
      mesh_mgmt_service_record_encode_v1(&announcement, payload, sizeof(payload), &payload_len);
  if (publisher->last_record_result != MESH_MGMT_SERVICE_RECORD_OK) {
    mesh_mgmt_crypto_wipe(payload, sizeof(payload));
    return publisher_finish(publisher, MESH_MGMT_SERVICE_PUBLISHER_ENCODE_FAILED);
  }

  memset(&sign_input, 0, sizeof(sign_input));
  sign_input.minor = MESH_MGMT_MINOR_V1;
  sign_input.kind = MESH_MGMT_KIND_MEMBERSHIP_DELTA;
  sign_input.private_key = publisher->signer.private_key;
  sign_input.payload = payload;
  sign_input.payload_len = payload_len;
  memcpy(sign_input.header.mesh_id_hash, publisher->signer.mesh_id_hash,
         sizeof(sign_input.header.mesh_id_hash));
  memcpy(sign_input.header.origin_node_id, publisher->signer.origin_node_id,
         sizeof(sign_input.header.origin_node_id));
  sign_input.header.principal_epoch = publisher->signer.principal_epoch;
  sign_input.header.incarnation = publisher->signer.incarnation;
  memcpy(sign_input.header.session_id, publisher->signer.session_id,
         sizeof(sign_input.header.session_id));
  sign_input.header.origin_sequence = record_epoch;
  sign_input.header.issued_at_ms = now_ms;
  sign_input.header.expires_at_ms = announcement.expires_at_ms;
  sign_input.header.certificate_serial = publisher->signer.certificate_serial;
  publisher->last_random_result = publisher_random(publisher, sign_input.header.message_id,
                                                   sizeof(sign_input.header.message_id));
  if (publisher->last_random_result != 0 ||
      bytes_are_zero(sign_input.header.message_id, sizeof(sign_input.header.message_id))) {
    mesh_mgmt_crypto_wipe(&sign_input, sizeof(sign_input));
    mesh_mgmt_crypto_wipe(payload, sizeof(payload));
    return publisher_finish(publisher, MESH_MGMT_SERVICE_PUBLISHER_RANDOM_FAILED);
  }

  memset(frame, 0, sizeof(frame));
  publisher->last_envelope_result =
      mesh_mgmt_envelope_sign_v1(&sign_input, frame, sizeof(frame), &frame_len);
  mesh_mgmt_crypto_wipe(&sign_input, sizeof(sign_input));
  mesh_mgmt_crypto_wipe(payload, sizeof(payload));
  if (publisher->last_envelope_result != MESH_MGMT_ENVELOPE_OK) {
    mesh_mgmt_crypto_wipe(frame, sizeof(frame));
    return publisher_finish(publisher, MESH_MGMT_SERVICE_PUBLISHER_SIGN_FAILED);
  }

  publisher->last_record_result = mesh_mgmt_service_dht_key_build_v1(
      publisher->signer.mesh_id_hash, publisher->signer.origin_node_id, key, sizeof(key), &key_len);
  if (publisher->last_record_result != MESH_MGMT_SERVICE_RECORD_OK ||
      key_len != MESH_MGMT_SERVICE_DHT_KEY_V1_LENGTH) {
    mesh_mgmt_crypto_wipe(frame, sizeof(frame));
    return publisher_finish(publisher, MESH_MGMT_SERVICE_PUBLISHER_ENCODE_FAILED);
  }
  publisher->last_p2p_result = p2p_dht_put_cached(publisher->node, key, frame, frame_len);
  mesh_mgmt_crypto_wipe(frame, sizeof(frame));
  if (publisher->last_p2p_result != P2P_OK)
    return publisher_finish(publisher, MESH_MGMT_SERVICE_PUBLISHER_P2P_FAILED);

  *out_record_epoch = record_epoch;
  if (!publisher->allocate_record_epoch) {
    if (record_epoch == UINT64_MAX)
      publisher->sequence_exhausted = 1u;
    else
      publisher->next_record_epoch = record_epoch + 1u;
  }
  return publisher_finish(publisher, MESH_MGMT_SERVICE_PUBLISHER_OK);
}

void mesh_mgmt_service_publisher_destroy_v1(mesh_mgmt_service_publisher_v1_t *publisher) {
  if (!publisher || publisher->in_api)
    return;
  mesh_mgmt_peer_signer_destroy_v1(&publisher->signer);
  mesh_mgmt_crypto_wipe(publisher, sizeof(*publisher));
}

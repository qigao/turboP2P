#ifndef MESH_MGMT_TEST_IDENTITY_H
#define MESH_MGMT_TEST_IDENTITY_H

/* Shared deterministic signed identity fixture for legacy and CNet sessions. */
#include "mesh_mgmt_p2p_peer.h"
#include "mesh_mgmt_crypto.h"
#include <string.h>
#define TEST_NOW_MS 100000u

typedef struct {
  uint8_t next_message_byte;
  int random_result;
  size_t event_count;
  int last_event_type;
} runtime_callbacks_t;

static uint64_t runtime_now_ms(void *context) {
  (void)context;
  return TEST_NOW_MS;
}

static int runtime_random_bytes(void *context, uint8_t *output, size_t output_len) {
  runtime_callbacks_t *callbacks = (runtime_callbacks_t *)context;
  size_t index;

  if (callbacks->random_result != 0)
    return callbacks->random_result;
  for (index = 0u; index < output_len; index++)
    output[index] = (uint8_t)(callbacks->next_message_byte + index);
  callbacks->next_message_byte = (uint8_t)(callbacks->next_message_byte + 0x20u);
  return 0;
}

static int runtime_event(void *context, const mesh_mgmt_dispatch_event_v1_t *event) {
  runtime_callbacks_t *callbacks = (runtime_callbacks_t *)context;

  if (!callbacks || !event)
    return -1;
  callbacks->event_count++;
  callbacks->last_event_type = event->type;
  return 0;
}

static int prepare_runtime_config(mesh_mgmt_p2p_peer_config_v1_t *config, p2p_node_t *node,
                                  p2p_peer_t *peer, const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                  const uint8_t management_private_key[32], uint8_t node_byte,
                                  uint8_t connection_byte, uint8_t session_byte, uint64_t serial,
                                  runtime_callbacks_t *callbacks) {
  static const uint8_t ISSUER_PRIVATE_KEY[32] = {
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
      0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
      0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
  };
  mesh_mgmt_certificate_claims_v1_t claims;
  uint8_t issuer_public_key[32];
  uint8_t management_public_key[32];
  uint8_t mesh_id_hash[32];
  uint8_t issuer_hash[32];
  size_t certificate_len = 0u;

  memset(config, 0, sizeof(*config));
  memset(&claims, 0, sizeof(claims));
  memset(mesh_id_hash, 0x42, sizeof(mesh_id_hash));
  if (mesh_mgmt_ed25519_public_from_private(ISSUER_PRIVATE_KEY, issuer_public_key) !=
          MESH_MGMT_CRYPTO_OK ||
      mesh_mgmt_ed25519_public_from_private(management_private_key, management_public_key) !=
          MESH_MGMT_CRYPTO_OK ||
      mesh_mgmt_blake2b_256(issuer_public_key, sizeof(issuer_public_key), issuer_hash) !=
          MESH_MGMT_CRYPTO_OK) {
    return -1;
  }

  claims.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(claims.management_key, management_public_key, sizeof(claims.management_key));
  memcpy(claims.transport_peer_id, transport_peer_id, sizeof(claims.transport_peer_id));
  memset(claims.managed_node_id, node_byte, sizeof(claims.managed_node_id));
  memcpy(claims.mesh_id_hash, mesh_id_hash, sizeof(claims.mesh_id_hash));
  claims.roles = MESH_MGMT_ROLE_OPERATOR;
  claims.not_before_ms = TEST_NOW_MS - 1000u;
  claims.expires_at_ms = TEST_NOW_MS + 60000u;
  claims.serial = serial;
  claims.principal_epoch = 1u;

  config->node = node;
  config->peer = peer;
  memcpy(config->signer.private_key, management_private_key, sizeof(config->signer.private_key));
  memcpy(config->signer.trusted_issuer_key, issuer_public_key,
         sizeof(config->signer.trusted_issuer_key));
  memcpy(config->signer.expected_mesh_id_hash, mesh_id_hash,
         sizeof(config->signer.expected_mesh_id_hash));
  memcpy(config->signer.local_transport_peer_id, transport_peer_id,
         sizeof(config->signer.local_transport_peer_id));
  config->signer.hello.major = MESH_MGMT_MAJOR_V1;
  config->signer.hello.min_minor = MESH_MGMT_MINOR_V1;
  config->signer.hello.max_minor = MESH_MGMT_MINOR_V1;
  config->signer.hello.features = MESH_MGMT_FEATURE_MEMBERSHIP;
  config->signer.hello.platform = MESH_MGMT_PLATFORM_OTHER;
  memcpy(config->signer.hello.build_version, "p2p-test", 8u);
  config->signer.hello.build_version_len = 8u;
  if (mesh_mgmt_certificate_issue_v1(&claims, ISSUER_PRIVATE_KEY, config->signer.hello.certificate,
                                     sizeof(config->signer.hello.certificate),
                                     &certificate_len) != MESH_MGMT_IDENTITY_OK ||
      certificate_len != sizeof(config->signer.hello.certificate)) {
    return -1;
  }
  memcpy(config->signer.hello.issuer_chain_hash, issuer_hash,
         sizeof(config->signer.hello.issuer_chain_hash));
  config->signer.hello.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(config->signer.hello.management_key, management_public_key,
         sizeof(config->signer.hello.management_key));
  memcpy(config->signer.hello.managed_node_id, claims.managed_node_id,
         sizeof(config->signer.hello.managed_node_id));
  memset(config->signer.hello.connection_id, connection_byte,
         sizeof(config->signer.hello.connection_id));
  config->signer.hello.max_frame = MESH_MGMT_SESSION_MIN_FRAME;
  config->signer.hello.max_digest_entries = 8u;
  config->signer.hello.max_delta_batch = 4u;
  memset(config->signer.session_id, session_byte, sizeof(config->signer.session_id));
  config->signer.incarnation = 1u;
  config->signer.first_sequence = 1u;
  config->signer.frame_ttl_ms = 1000u;
  config->signer.now_ms = runtime_now_ms;
  config->signer.random_bytes = runtime_random_bytes;
  config->signer.callback_context = callbacks;

  memcpy(config->dispatch.session.expected_mesh_id_hash, mesh_id_hash,
         sizeof(config->dispatch.session.expected_mesh_id_hash));
  memcpy(config->dispatch.session.trusted_issuer_key, issuer_public_key,
         sizeof(config->dispatch.session.trusted_issuer_key));
  config->dispatch.session.min_minor = MESH_MGMT_MINOR_V1;
  config->dispatch.session.max_minor = MESH_MGMT_MINOR_V1;
  config->dispatch.session.features = MESH_MGMT_FEATURE_MEMBERSHIP;
  memcpy(config->dispatch.session.connection_id, config->signer.hello.connection_id,
         sizeof(config->dispatch.session.connection_id));
  config->dispatch.session.max_frame = MESH_MGMT_SESSION_MIN_FRAME;
  config->dispatch.session.max_digest_entries = 8u;
  config->dispatch.session.max_delta_batch = 4u;
  config->dispatch.replay.capacity = 8u;
  config->dispatch.replay.ttl_ms = 2000u;
  config->on_event = runtime_event;
  config->event_context = callbacks;
  return 0;
}


#endif

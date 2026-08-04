#include "m3_chunk_mesh.h"

#include "mesh_mgmt_crypto.h"

#include <turbo_thread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FRAME_HEADER_SIZE 40u
#define FRAME_CLAIMS_OFFSET FRAME_HEADER_SIZE
#define FRAME_SIGNATURE_OFFSET (FRAME_HEADER_SIZE + M3_CHUNK_MESH_CLAIMS_SIZE)
#define FRAME_CHANNEL_KEY_OFFSET \
  (FRAME_HEADER_SIZE + M3_CHUNK_MESH_CLAIMS_SIZE + M3_CHUNK_MESH_SIGNATURE_SIZE)
#define FRAME_SIGNER_KEY_OFFSET \
  (FRAME_CHANNEL_KEY_OFFSET + M3_CHUNK_MESH_CHANNEL_KEY_SIZE)
#define FRAME_PAYLOAD_OFFSET \
  (FRAME_SIGNER_KEY_OFFSET + M3_CHUNK_MESH_SIGNER_KEY_SIZE)

#define CLAIM_TENANT_OFFSET 0u
#define CLAIM_ALGORITHM_OFFSET 32u
#define CLAIM_RESERVED_OFFSET 33u
#define CLAIM_SIZE_OFFSET 40u
#define CLAIM_DIGEST_OFFSET 48u
#define CLAIM_OPERATION_OFFSET 80u
#define CLAIM_OP_RESERVED_OFFSET 81u
#define CLAIM_RANGE_OFFSET_OFFSET 88u
#define CLAIM_RANGE_LENGTH_OFFSET 96u
#define CLAIM_AUDIENCE_OFFSET 104u
#define CLAIM_REQUEST_ID_OFFSET 136u
#define CLAIM_ISSUED_AT_OFFSET 152u
#define CLAIM_EXPIRES_AT_OFFSET 160u

static const uint8_t FRAME_MAGIC[8] = {
    'M', '3', 'C', 'H', 'N', 'K', '1', 0,
};

static void write_u16(uint8_t out[2], uint16_t value) {
  out[0] = (uint8_t)(value >> 8u);
  out[1] = (uint8_t)value;
}

static uint16_t read_u16(const uint8_t in[2]) {
  return (uint16_t)(((uint16_t)in[0] << 8u) | (uint16_t)in[1]);
}

static void write_u32(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t)(value >> 24u);
  out[1] = (uint8_t)(value >> 16u);
  out[2] = (uint8_t)(value >> 8u);
  out[3] = (uint8_t)value;
}

static uint32_t read_u32(const uint8_t in[4]) {
  return ((uint32_t)in[0] << 24u) | ((uint32_t)in[1] << 16u) |
         ((uint32_t)in[2] << 8u) | (uint32_t)in[3];
}

static void write_u64(uint8_t out[8], uint64_t value) {
  for (size_t i = 0u; i < 8u; i++)
    out[i] = (uint8_t)(value >> (56u - i * 8u));
}

static uint64_t read_u64(const uint8_t in[8]) {
  uint64_t value = 0u;

  for (size_t i = 0u; i < 8u; i++)
    value = (value << 8u) | in[i];
  return value;
}

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0u; i < size; i++)
    aggregate |= bytes[i];
  return aggregate == 0u;
}

m3_chunk_mesh_result_t m3_chunk_mesh_claims_encode_v1(
    const m3_chunk_capability_claims_v1_t *claims,
    uint8_t out[M3_CHUNK_MESH_CLAIMS_SIZE]) {
  if (!claims || !out)
    return M3_CHUNK_MESH_INVALID_ARG;
  memset(out, 0, M3_CHUNK_MESH_CLAIMS_SIZE);
  memcpy(out + CLAIM_TENANT_OFFSET, claims->tenant_id,
         sizeof(claims->tenant_id));
  out[CLAIM_ALGORITHM_OFFSET] = claims->cid.hash_algorithm;
  write_u64(out + CLAIM_SIZE_OFFSET, claims->cid.size);
  memcpy(out + CLAIM_DIGEST_OFFSET, claims->cid.digest,
         sizeof(claims->cid.digest));
  out[CLAIM_OPERATION_OFFSET] = (uint8_t)claims->operation;
  write_u64(out + CLAIM_RANGE_OFFSET_OFFSET, claims->range_offset);
  write_u64(out + CLAIM_RANGE_LENGTH_OFFSET, claims->range_length);
  memcpy(out + CLAIM_AUDIENCE_OFFSET, claims->audience_node_id,
         sizeof(claims->audience_node_id));
  memcpy(out + CLAIM_REQUEST_ID_OFFSET, claims->request_id.bytes,
         sizeof(claims->request_id.bytes));
  write_u64(out + CLAIM_ISSUED_AT_OFFSET, claims->issued_at_ms);
  write_u64(out + CLAIM_EXPIRES_AT_OFFSET, claims->expires_at_ms);
  return M3_CHUNK_MESH_OK;
}

m3_chunk_mesh_result_t m3_chunk_mesh_claims_decode_v1(
    const uint8_t bytes[M3_CHUNK_MESH_CLAIMS_SIZE],
    m3_chunk_capability_claims_v1_t *out_claims) {
  m3_chunk_capability_claims_v1_t claims = {0};

  if (!bytes || !out_claims)
    return M3_CHUNK_MESH_INVALID_ARG;
  if (!bytes_are_zero(bytes + CLAIM_RESERVED_OFFSET, 7u) ||
      !bytes_are_zero(bytes + CLAIM_OP_RESERVED_OFFSET, 7u)) {
    return M3_CHUNK_MESH_CORRUPT;
  }
  memcpy(claims.tenant_id, bytes + CLAIM_TENANT_OFFSET,
         sizeof(claims.tenant_id));
  claims.cid.hash_algorithm = bytes[CLAIM_ALGORITHM_OFFSET];
  claims.cid.size = read_u64(bytes + CLAIM_SIZE_OFFSET);
  memcpy(claims.cid.digest, bytes + CLAIM_DIGEST_OFFSET,
         sizeof(claims.cid.digest));
  claims.operation = (m3_chunk_operation_v1_t)bytes[CLAIM_OPERATION_OFFSET];
  claims.range_offset = read_u64(bytes + CLAIM_RANGE_OFFSET_OFFSET);
  claims.range_length = read_u64(bytes + CLAIM_RANGE_LENGTH_OFFSET);
  memcpy(claims.audience_node_id, bytes + CLAIM_AUDIENCE_OFFSET,
         sizeof(claims.audience_node_id));
  memcpy(claims.request_id.bytes, bytes + CLAIM_REQUEST_ID_OFFSET,
         sizeof(claims.request_id.bytes));
  claims.issued_at_ms = read_u64(bytes + CLAIM_ISSUED_AT_OFFSET);
  claims.expires_at_ms = read_u64(bytes + CLAIM_EXPIRES_AT_OFFSET);
  *out_claims = claims;
  return M3_CHUNK_MESH_OK;
}

m3_chunk_mesh_result_t m3_chunk_mesh_claims_sign_v1(
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    const m3_chunk_capability_claims_v1_t *claims,
    uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE]) {
  uint8_t encoded[M3_CHUNK_MESH_CLAIMS_SIZE];
  m3_chunk_mesh_result_t result;

  if (!private_key || !claims || !signature)
    return M3_CHUNK_MESH_INVALID_ARG;
  result = m3_chunk_mesh_claims_encode_v1(claims, encoded);
  if (result != M3_CHUNK_MESH_OK)
    return result;
  if (mesh_mgmt_ed25519_sign(private_key, encoded, sizeof(encoded), signature) !=
      MESH_MGMT_CRYPTO_OK) {
    return M3_CHUNK_MESH_STORE_ERROR;
  }
  return M3_CHUNK_MESH_OK;
}

m3_chunk_mesh_result_t m3_chunk_mesh_claims_verify_v1(
    const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const m3_chunk_capability_claims_v1_t *claims,
    const uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE]) {
  uint8_t encoded[M3_CHUNK_MESH_CLAIMS_SIZE];
  m3_chunk_mesh_result_t result;

  if (!public_key || !claims || !signature)
    return M3_CHUNK_MESH_INVALID_ARG;
  result = m3_chunk_mesh_claims_encode_v1(claims, encoded);
  if (result != M3_CHUNK_MESH_OK)
    return result;
  if (mesh_mgmt_ed25519_verify(public_key, encoded, sizeof(encoded), signature) !=
      MESH_MGMT_CRYPTO_OK) {
    return M3_CHUNK_MESH_AUTH_FAILED;
  }
  return M3_CHUNK_MESH_OK;
}

m3_chunk_mesh_result_t m3_chunk_mesh_frame_encode_v1(
    m3_chunk_mesh_frame_type_t type, m3_chunk_mesh_operation_t operation,
    int32_t status, const uint8_t correlation_id[16],
    const uint8_t claims[M3_CHUNK_MESH_CLAIMS_SIZE],
    const uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE],
    const uint8_t channel_public_key[M3_CHUNK_MESH_CHANNEL_KEY_SIZE],
    const uint8_t signer_public_key[M3_CHUNK_MESH_SIGNER_KEY_SIZE],
    const uint8_t *payload, size_t payload_len, uint8_t *out_frame,
    size_t frame_cap, size_t *out_frame_size) {
  size_t total;

  if (out_frame_size)
    *out_frame_size = 0u;
  if (!out_frame || !out_frame_size || !correlation_id || !claims ||
      !signature || !channel_public_key || !signer_public_key ||
      (payload_len > 0u && !payload) ||
      (type != M3_CHUNK_MESH_FRAME_REQUEST &&
       type != M3_CHUNK_MESH_FRAME_RESPONSE) ||
      (operation != M3_CHUNK_MESH_OP_PUT &&
       operation != M3_CHUNK_MESH_OP_GET)) {
    return M3_CHUNK_MESH_INVALID_ARG;
  }
  if (payload_len > M3_CHUNK_MESH_MAX_PAYLOAD)
    return M3_CHUNK_MESH_OVERFLOW;
  total = FRAME_PAYLOAD_OFFSET + payload_len;
  if (total > frame_cap)
    return M3_CHUNK_MESH_RESOURCE_EXHAUSTED;

  memset(out_frame, 0, total);
  memcpy(out_frame, FRAME_MAGIC, sizeof(FRAME_MAGIC));
  write_u16(out_frame + 8u, 1u);
  out_frame[10] = (uint8_t)type;
  out_frame[11] = (uint8_t)operation;
  write_u32(out_frame + 12u, (uint32_t)status);
  memcpy(out_frame + 16u, correlation_id, 16u);
  write_u32(out_frame + 32u, M3_CHUNK_MESH_CLAIMS_SIZE);
  write_u32(out_frame + 36u, (uint32_t)payload_len);
  memcpy(out_frame + FRAME_CLAIMS_OFFSET, claims, M3_CHUNK_MESH_CLAIMS_SIZE);
  memcpy(out_frame + FRAME_SIGNATURE_OFFSET, signature,
         M3_CHUNK_MESH_SIGNATURE_SIZE);
  memcpy(out_frame + FRAME_CHANNEL_KEY_OFFSET, channel_public_key,
         M3_CHUNK_MESH_CHANNEL_KEY_SIZE);
  memcpy(out_frame + FRAME_SIGNER_KEY_OFFSET, signer_public_key,
         M3_CHUNK_MESH_SIGNER_KEY_SIZE);
  if (payload_len > 0u)
    memcpy(out_frame + FRAME_PAYLOAD_OFFSET, payload, payload_len);
  *out_frame_size = total;
  return M3_CHUNK_MESH_OK;
}

m3_chunk_mesh_result_t m3_chunk_mesh_frame_decode_v1(
    const uint8_t *frame, size_t frame_size, m3_chunk_mesh_frame_type_t *out_type,
    m3_chunk_mesh_operation_t *out_operation, int32_t *out_status,
    uint8_t correlation_id[16], const uint8_t **out_claims,
    const uint8_t **out_signature, const uint8_t **out_channel_public_key,
    const uint8_t **out_signer_public_key, const uint8_t **out_payload,
    size_t *out_payload_len) {
  uint32_t claims_size;
  uint32_t payload_size;
  size_t total;

  if (!frame || !out_type || !out_operation || !out_status ||
      !correlation_id || !out_claims || !out_signature ||
      !out_channel_public_key || !out_signer_public_key || !out_payload ||
      !out_payload_len) {
    return M3_CHUNK_MESH_INVALID_ARG;
  }
  *out_claims = NULL;
  *out_signature = NULL;
  *out_channel_public_key = NULL;
  *out_signer_public_key = NULL;
  *out_payload = NULL;
  *out_payload_len = 0u;
  if (frame_size < FRAME_PAYLOAD_OFFSET ||
      memcmp(frame, FRAME_MAGIC, sizeof(FRAME_MAGIC)) != 0 ||
      read_u16(frame + 8u) != 1u) {
    return M3_CHUNK_MESH_CORRUPT;
  }
  claims_size = read_u32(frame + 32u);
  payload_size = read_u32(frame + 36u);
  if (claims_size != M3_CHUNK_MESH_CLAIMS_SIZE ||
      payload_size > M3_CHUNK_MESH_MAX_PAYLOAD) {
    return M3_CHUNK_MESH_CORRUPT;
  }
  total = FRAME_PAYLOAD_OFFSET + (size_t)payload_size;
  if (frame_size != total)
    return M3_CHUNK_MESH_CORRUPT;
  *out_type = (m3_chunk_mesh_frame_type_t)frame[10];
  *out_operation = (m3_chunk_mesh_operation_t)frame[11];
  *out_status = (int32_t)read_u32(frame + 12u);
  memcpy(correlation_id, frame + 16u, 16u);
  *out_claims = frame + FRAME_CLAIMS_OFFSET;
  *out_signature = frame + FRAME_SIGNATURE_OFFSET;
  *out_channel_public_key = frame + FRAME_CHANNEL_KEY_OFFSET;
  *out_signer_public_key = frame + FRAME_SIGNER_KEY_OFFSET;
  if (payload_size > 0u) {
    *out_payload = frame + FRAME_PAYLOAD_OFFSET;
    *out_payload_len = (size_t)payload_size;
  }
  return M3_CHUNK_MESH_OK;
}

static m3_chunk_mesh_result_t reply_frame(
    p2p_node_t *node, p2p_peer_t *peer, m3_chunk_mesh_operation_t operation,
    const uint8_t correlation_id[16], int32_t status, const uint8_t *payload,
    size_t payload_len) {
  uint8_t frame[M3_CHUNK_MESH_FRAME_MAX];
  uint8_t zero_claims[M3_CHUNK_MESH_CLAIMS_SIZE] = {0};
  uint8_t zero_sig[M3_CHUNK_MESH_SIGNATURE_SIZE] = {0};
  uint8_t zero_channel[M3_CHUNK_MESH_CHANNEL_KEY_SIZE] = {0};
  uint8_t zero_signer[M3_CHUNK_MESH_SIGNER_KEY_SIZE] = {0};
  size_t frame_size = 0u;
  m3_chunk_mesh_result_t result;

  result = m3_chunk_mesh_frame_encode_v1(
      M3_CHUNK_MESH_FRAME_RESPONSE, operation, status,
      correlation_id, zero_claims, zero_sig, zero_channel, zero_signer,
      payload, payload_len, frame, sizeof(frame), &frame_size);
  if (result != M3_CHUNK_MESH_OK)
    return result;
  if (p2p_send(node, peer, frame, frame_size) != P2P_OK)
    return M3_CHUNK_MESH_NETWORK;
  return M3_CHUNK_MESH_OK;
}

static void mesh_service_on_message(p2p_node_t *node, p2p_peer_t *peer,
                                    const void *data, size_t len,
                                    void *user_data) {
  m3_chunk_mesh_service_v1_t *service = (m3_chunk_mesh_service_v1_t *)user_data;
  m3_chunk_mesh_frame_type_t type;
  m3_chunk_mesh_operation_t operation;
  int32_t status;
  uint8_t correlation_id[16];
  const uint8_t *claims_bytes;
  const uint8_t *signature;
  const uint8_t *channel_public_key;
  const uint8_t *signer_public_key;
  const uint8_t *payload;
  size_t payload_len;
  uint8_t peer_channel_key[M3_CHUNK_MESH_CHANNEL_KEY_SIZE];
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  m3_store_node_result_t store_result;
  uint64_t now_ms = (uint64_t)time(NULL) * 1000u;
  int trusted = 0;

  if (!service || !service->node || !service->store)
    return;
  if (m3_chunk_mesh_frame_decode_v1(data, len, &type, &operation, &status,
                                    correlation_id, &claims_bytes, &signature,
                                    &channel_public_key, &signer_public_key,
                                    &payload, &payload_len) !=
          M3_CHUNK_MESH_OK ||
      type != M3_CHUNK_MESH_FRAME_REQUEST) {
    return;
  }
  for (size_t i = 0u; i < service->trusted_count; i++) {
    if (memcmp(service->trusted_keys[i], signer_public_key,
               M3_CHUNK_MESH_SIGNER_KEY_SIZE) == 0) {
      trusted = 1;
      break;
    }
  }
  if (!trusted ||
      p2p_peer_get_public_key(peer, peer_channel_key) != P2P_OK ||
      memcmp(peer_channel_key, channel_public_key,
             M3_CHUNK_MESH_CHANNEL_KEY_SIZE) != 0 ||
      m3_chunk_mesh_claims_decode_v1(claims_bytes, &claims) !=
          M3_CHUNK_MESH_OK ||
      m3_chunk_mesh_claims_verify_v1(signer_public_key, &claims, signature) !=
          M3_CHUNK_MESH_OK) {
    (void)reply_frame(node, peer, operation, correlation_id,
                      (int32_t)M3_CHUNK_MESH_AUTH_FAILED, NULL, 0u);
    return;
  }

  memset(&request, 0, sizeof(request));
  memcpy(request.tenant_id, claims.tenant_id, sizeof(request.tenant_id));
  request.cid = claims.cid;
  request.operation = claims.operation;
  request.range_offset = claims.range_offset;
  request.range_length = claims.range_length;
  memcpy(request.local_node_id, service->store->config.node_id,
         sizeof(request.local_node_id));
  request.request_id = claims.request_id;
  request.now_ms = now_ms;

  if (operation == M3_CHUNK_MESH_OP_PUT) {
    m3_chunk_receipt_v1_t receipt;
    uint8_t receipt_bytes[M3_CHUNK_RECEIPT_ENCODED_SIZE];
    size_t receipt_size = 0u;

    store_result = m3_store_node_put_chunk_v1(
        service->store, &claims, &request, payload, payload_len, &receipt);
    if (store_result != M3_STORE_NODE_OK) {
      (void)reply_frame(node, peer, operation, correlation_id, (int32_t)store_result, NULL, 0u);
      return;
    }
    if (m3_chunk_receipt_encode_v1(&receipt, receipt_bytes, &receipt_size) !=
            M3_CHUNK_RECEIPT_OK ||
        reply_frame(node, peer, operation, correlation_id,
                    (int32_t)M3_CHUNK_MESH_OK, receipt_bytes, receipt_size) !=
            M3_CHUNK_MESH_OK) {
      return;
    }
  } else if (operation == M3_CHUNK_MESH_OP_GET) {
    uint8_t *buffer;
    size_t read = 0u;

    if (claims.range_length > M3_CHUNK_MESH_MAX_PAYLOAD) {
      (void)reply_frame(node, peer, operation, correlation_id,
                        (int32_t)M3_CHUNK_MESH_OVERFLOW, NULL, 0u);
      return;
    }
    buffer = (uint8_t *)malloc((size_t)claims.range_length);
    if (!buffer) {
      (void)reply_frame(node, peer, operation, correlation_id,
                        (int32_t)M3_CHUNK_MESH_RESOURCE_EXHAUSTED, NULL, 0u);
      return;
    }
    store_result = m3_store_node_read_chunk_v1(
        service->store, &claims, &request, buffer, (size_t)claims.range_length,
        &read);
    if (store_result != M3_STORE_NODE_OK) {
      (void)reply_frame(node, peer, operation, correlation_id, (int32_t)store_result, NULL, 0u);
      free(buffer);
      return;
    }
    (void)reply_frame(node, peer, operation, correlation_id,
                      (int32_t)M3_CHUNK_MESH_OK, buffer, read);
    free(buffer);
  }
}

m3_chunk_mesh_result_t m3_chunk_mesh_service_init_v1(
    m3_chunk_mesh_service_v1_t *service, p2p_node_t *node,
    m3_store_node_v1_t *store) {
  if (!service || service->node || !node || !store || !store->initialized)
    return M3_CHUNK_MESH_INVALID_ARG;
  memset(service, 0, sizeof(*service));
  service->node = node;
  service->store = store;
  p2p_set_message_handler(node, mesh_service_on_message, service);
  return M3_CHUNK_MESH_OK;
}

m3_chunk_mesh_result_t m3_chunk_mesh_service_add_trusted_key_v1(
    m3_chunk_mesh_service_v1_t *service,
    const uint8_t signer_public_key[M3_CHUNK_MESH_SIGNER_KEY_SIZE]) {
  if (!service || !signer_public_key)
    return M3_CHUNK_MESH_INVALID_ARG;
  if (service->trusted_count >= M3_CHUNK_MESH_MAX_TRUSTED_KEYS)
    return M3_CHUNK_MESH_RESOURCE_EXHAUSTED;
  for (size_t i = 0u; i < service->trusted_count; i++) {
    if (memcmp(service->trusted_keys[i], signer_public_key,
               M3_CHUNK_MESH_SIGNER_KEY_SIZE) == 0) {
      return M3_CHUNK_MESH_OK;
    }
  }
  memcpy(service->trusted_keys[service->trusted_count], signer_public_key,
         M3_CHUNK_MESH_SIGNER_KEY_SIZE);
  service->trusted_count++;
  return M3_CHUNK_MESH_OK;
}

void m3_chunk_mesh_service_destroy_v1(m3_chunk_mesh_service_v1_t *service) {
  if (!service)
    return;
  if (service->node)
    p2p_set_message_handler(service->node, NULL, NULL);
  memset(service, 0, sizeof(*service));
}

static void mesh_router_on_message(p2p_node_t *node, p2p_peer_t *peer,
                                   const void *data, size_t len,
                                   void *user_data) {
  m3_chunk_mesh_router_v1_t *router = (m3_chunk_mesh_router_v1_t *)user_data;
  m3_chunk_mesh_frame_type_t type;
  m3_chunk_mesh_operation_t operation;
  int32_t status;
  uint8_t correlation_id[16];
  const uint8_t *claims_bytes;
  const uint8_t *signature;
  const uint8_t *channel_public_key;
  const uint8_t *signer_public_key;
  const uint8_t *payload;
  size_t payload_len;
  m3_chunk_mesh_client_v1_t *client;

  (void)node;
  (void)peer;
  (void)claims_bytes;
  (void)signature;
  (void)channel_public_key;
  (void)signer_public_key;
  if (!router)
    return;
  if (m3_chunk_mesh_frame_decode_v1(data, len, &type, &operation, &status,
                                    correlation_id, &claims_bytes, &signature,
                                    &channel_public_key, &signer_public_key,
                                    &payload, &payload_len) !=
          M3_CHUNK_MESH_OK ||
      type != M3_CHUNK_MESH_FRAME_RESPONSE) {
    return;
  }
  for (client = router->clients; client; client = client->next) {
    if (client->done)
      continue;
    if (memcmp(client->pending_correlation, correlation_id, 16u) == 0) {
      client->status = status;
      if (status == (int32_t)M3_CHUNK_MESH_OK && payload_len > 0u &&
          payload_len <= client->response_storage_cap) {
        memcpy(client->response_storage, payload, payload_len);
        client->response_len = payload_len;
      } else {
        client->response_len = 0u;
      }
      if (status == (int32_t)M3_CHUNK_MESH_OK && operation == M3_CHUNK_MESH_OP_PUT &&
          payload_len == M3_CHUNK_RECEIPT_ENCODED_SIZE) {
        (void)m3_chunk_receipt_decode_v1(client->response_storage, payload_len,
                                         &client->receipt);
      }
      client->done = 1;
      return;
    }
  }
}

static void router_on_connected(p2p_peer_t *peer, void *user_data) {
  m3_chunk_mesh_router_v1_t *router = (m3_chunk_mesh_router_v1_t *)user_data;
  char ip[128];
  int port = 0;

  if (!router || p2p_peer_get_address(peer, ip, &port) != P2P_OK)
    return;
  for (m3_chunk_mesh_client_v1_t *client = router->clients; client;
       client = client->next) {
    if (!client->peer && strcmp(client->host, ip) == 0 &&
        client->port == port) {
      client->peer = peer;
      return;
    }
  }
}

static void router_on_disconnected(p2p_peer_t *peer, void *user_data) {
  m3_chunk_mesh_router_v1_t *router = (m3_chunk_mesh_router_v1_t *)user_data;

  if (!router)
    return;
  for (m3_chunk_mesh_client_v1_t *client = router->clients; client;
       client = client->next) {
    if (client->peer == peer)
      client->peer = NULL;
  }
}

m3_chunk_mesh_result_t m3_chunk_mesh_router_init_v1(
    m3_chunk_mesh_router_v1_t *router, p2p_node_t *node) {
  if (!router || router->node || !node)
    return M3_CHUNK_MESH_INVALID_ARG;
  memset(router, 0, sizeof(*router));
  router->node = node;
  p2p_set_message_handler(node, mesh_router_on_message, router);
  p2p_set_peer_callbacks(node, router_on_connected, router_on_disconnected,
                         router);
  return M3_CHUNK_MESH_OK;
}

void m3_chunk_mesh_router_destroy_v1(m3_chunk_mesh_router_v1_t *router) {
  if (!router)
    return;
  if (router->node)
    p2p_set_message_handler(router->node, NULL, NULL);
  memset(router, 0, sizeof(*router));
}

m3_chunk_mesh_result_t m3_chunk_mesh_router_add_client_v1(
    m3_chunk_mesh_router_v1_t *router, m3_chunk_mesh_client_v1_t *client) {
  if (!router || !client || client->next)
    return M3_CHUNK_MESH_INVALID_ARG;
  client->next = router->clients;
  router->clients = client;
  return M3_CHUNK_MESH_OK;
}

m3_chunk_mesh_result_t m3_chunk_mesh_client_connect_v1(
    m3_chunk_mesh_client_v1_t *client, p2p_node_t *node,
    const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
    const uint8_t store_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const char *host, int port) {
  uint8_t aggregate = 0u;

  if (!client || client->node || !node || !store_node_id || !store_public_key ||
      !host || host[0] == '\0' || port <= 0 || port > 65535)
    return M3_CHUNK_MESH_INVALID_ARG;
  for (size_t i = 0u; i < M3_CHUNK_CAPABILITY_NODE_ID_SIZE; i++)
    aggregate |= store_node_id[i];
  if (aggregate == 0u)
    return M3_CHUNK_MESH_INVALID_ARG;
  memset(client, 0, sizeof(*client));
  client->node = node;
  memcpy(client->store_node_id, store_node_id, sizeof(client->store_node_id));
  memcpy(client->store_public_key, store_public_key,
         sizeof(client->store_public_key));
  snprintf(client->host, sizeof(client->host), "%s", host);
  client->port = port;
  client->response_storage_cap = M3_CHUNK_MESH_MAX_PAYLOAD;
  client->response_storage =
      (uint8_t *)malloc(client->response_storage_cap);
  if (!client->response_storage)
    return M3_CHUNK_MESH_RESOURCE_EXHAUSTED;
  if (p2p_connect(node, host, port) != P2P_OK)
    return M3_CHUNK_MESH_NETWORK;
  return M3_CHUNK_MESH_OK;
}

void m3_chunk_mesh_client_destroy_v1(m3_chunk_mesh_client_v1_t *client) {
  if (!client)
    return;
  free(client->response_storage);
  memset(client, 0, sizeof(*client));
}

static m3_chunk_mesh_result_t mesh_client_wait(
    m3_chunk_mesh_client_v1_t *client, uint64_t timeout_ms) {
  uint64_t deadline = turbo_monotonic_ms() + timeout_ms;

  while (turbo_monotonic_ms() < deadline &&
         (!client->peer || !client->done))
    turbo_sleep_ms(1);
  if (!client->peer)
    return M3_CHUNK_MESH_NOT_READY;
  return client->done ? M3_CHUNK_MESH_OK : M3_CHUNK_MESH_TIMEOUT;
}

m3_chunk_mesh_result_t m3_chunk_mesh_client_put_v1(
    m3_chunk_mesh_client_v1_t *client,
    const m3_chunk_capability_claims_v1_t *claims,
    const uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE],
    const uint8_t signer_public_key[M3_CHUNK_MESH_SIGNER_KEY_SIZE],
    const uint8_t *bytes, size_t size, uint64_t timeout_ms,
    m3_chunk_receipt_v1_t *out_receipt) {
  uint8_t claims_bytes[M3_CHUNK_MESH_CLAIMS_SIZE];
  uint8_t channel_public_key[M3_CHUNK_MESH_CHANNEL_KEY_SIZE];
  uint8_t frame[M3_CHUNK_MESH_FRAME_MAX];
  size_t frame_size = 0u;
  m3_chunk_mesh_result_t result;

  if (out_receipt)
    memset(out_receipt, 0, sizeof(*out_receipt));
  if (!client || !client->node || !claims || !signature || !signer_public_key ||
      !out_receipt || (!bytes && size > 0u))
    return M3_CHUNK_MESH_INVALID_ARG;
  if (size > M3_CHUNK_MESH_MAX_PAYLOAD)
    return M3_CHUNK_MESH_OVERFLOW;
  result = m3_chunk_mesh_claims_encode_v1(claims, claims_bytes);
  if (result != M3_CHUNK_MESH_OK)
    return result;
  if (p2p_node_get_public_key(client->node, channel_public_key) != P2P_OK)
    return M3_CHUNK_MESH_NETWORK;
  memset(client->pending_correlation, 0, sizeof(client->pending_correlation));
  client->pending_correlation[0] = (uint8_t)(client->port & 0xffu);
  client->pending_correlation[1] = 0x5au;
  client->done = 0;
  client->status = (int32_t)M3_CHUNK_MESH_NOT_READY;
  client->response_len = 0u;
  memset(&client->receipt, 0, sizeof(client->receipt));
  result = m3_chunk_mesh_frame_encode_v1(
      M3_CHUNK_MESH_FRAME_REQUEST, M3_CHUNK_MESH_OP_PUT, 0,
      client->pending_correlation, claims_bytes, signature, channel_public_key,
      signer_public_key, bytes, size, frame, sizeof(frame), &frame_size);
  if (result != M3_CHUNK_MESH_OK)
    return result;
  if (p2p_send(client->node, client->peer, frame, frame_size) != P2P_OK)
    return M3_CHUNK_MESH_NETWORK;
  result = mesh_client_wait(client, timeout_ms);
  if (result != M3_CHUNK_MESH_OK)
    return result;
  if (client->status != (int32_t)M3_CHUNK_MESH_OK)
    return (m3_chunk_mesh_result_t)client->status;
  if (client->response_len != M3_CHUNK_RECEIPT_ENCODED_SIZE)
    return M3_CHUNK_MESH_CORRUPT;
  *out_receipt = client->receipt;
  return M3_CHUNK_MESH_OK;
}

m3_chunk_mesh_result_t m3_chunk_mesh_client_get_v1(
    m3_chunk_mesh_client_v1_t *client,
    const m3_chunk_capability_claims_v1_t *claims,
    const uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE],
    const uint8_t signer_public_key[M3_CHUNK_MESH_SIGNER_KEY_SIZE],
    uint8_t *buffer, size_t buffer_size, size_t *out_read, uint64_t timeout_ms) {
  uint8_t claims_bytes[M3_CHUNK_MESH_CLAIMS_SIZE];
  uint8_t channel_public_key[M3_CHUNK_MESH_CHANNEL_KEY_SIZE];
  uint8_t frame[M3_CHUNK_MESH_FRAME_MAX];
  size_t frame_size = 0u;
  m3_chunk_mesh_result_t result;

  if (out_read)
    *out_read = 0u;
  if (!client || !client->node || !claims || !signature || !signer_public_key ||
      !buffer || !out_read)
    return M3_CHUNK_MESH_INVALID_ARG;
  result = m3_chunk_mesh_claims_encode_v1(claims, claims_bytes);
  if (result != M3_CHUNK_MESH_OK)
    return result;
  if (p2p_node_get_public_key(client->node, channel_public_key) != P2P_OK)
    return M3_CHUNK_MESH_NETWORK;
  memset(client->pending_correlation, 0, sizeof(client->pending_correlation));
  client->pending_correlation[0] = (uint8_t)(client->port & 0xffu);
  client->pending_correlation[1] = 0x5bu;
  client->done = 0;
  client->status = (int32_t)M3_CHUNK_MESH_NOT_READY;
  client->response_len = 0u;
  result = m3_chunk_mesh_frame_encode_v1(
      M3_CHUNK_MESH_FRAME_REQUEST, M3_CHUNK_MESH_OP_GET, 0,
      client->pending_correlation, claims_bytes, signature, channel_public_key,
      signer_public_key, NULL, 0u, frame, sizeof(frame), &frame_size);
  if (result != M3_CHUNK_MESH_OK)
    return result;
  if (p2p_send(client->node, client->peer, frame, frame_size) != P2P_OK)
    return M3_CHUNK_MESH_NETWORK;
  result = mesh_client_wait(client, timeout_ms);
  if (result != M3_CHUNK_MESH_OK)
    return result;
  if (client->status != (int32_t)M3_CHUNK_MESH_OK)
    return (m3_chunk_mesh_result_t)client->status;
  if (client->response_len > buffer_size)
    return M3_CHUNK_MESH_RESOURCE_EXHAUSTED;
  memcpy(buffer, client->response_storage, client->response_len);
  *out_read = client->response_len;
  return M3_CHUNK_MESH_OK;
}

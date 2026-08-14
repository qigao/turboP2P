#include "mesh_control_agent_service.h"

#include "platform.h"

#include <stdlib.h>
#include <string.h>

#define AGENT_SERVICE_EXCHANGE_STORAGE_SIZE_V1 \
  (2u * MESH_CONTROL_MAX_FRAME_SIZE_V1)

static int zero_bytes(const uint8_t *bytes, size_t size) {
  uint8_t value = 0u;
  size_t index;
  if (!bytes) return 1;
  for (index = 0u; index < size; ++index) value |= bytes[index];
  return value == 0u;
}

static uint64_t next_token(mesh_control_agent_service_v1_t *service) {
  service->request_token++;
  if (service->request_token == 0u) service->request_token++;
  return service->request_token;
}

static mesh_control_result_t real_exchange(
    void *context, const uint8_t *request, size_t request_size,
    uint8_t *response, size_t response_capacity, size_t *out_response_size) {
  return mesh_control_agent_http_client_exchange_v1(
      (mesh_control_agent_http_client_v1_t *)context, request, request_size,
      response, response_capacity, out_response_size);
}

static mesh_control_result_t real_poll(void *context, size_t *out_progress) {
  return mesh_control_agent_poll_v1((mesh_control_agent_v1_t *)context,
                                    out_progress);
}

static mesh_control_result_t real_ingest(void *context, const uint8_t *frame,
                                         size_t frame_size) {
  mesh_control_agent_v1_t *agent = (mesh_control_agent_v1_t *)context;
  if (!agent || !agent->running) return MESH_CONTROL_INVALID_STATE;
  return mesh_control_iris_receive_frame_v1(&agent->iris, frame, frame_size);
}

static mesh_control_result_t real_receipt(
    void *context, const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
    uint8_t output[MESH_CONTROL_RECEIPT_SIZE_V1], size_t *out_size) {
  return mesh_control_agent_receipt_v1((mesh_control_agent_v1_t *)context,
                                       operation_id, output, out_size);
}

static int config_valid(const mesh_control_agent_service_config_v1_t *config) {
  return config && !zero_bytes(config->node_id, sizeof(config->node_id)) &&
         !zero_bytes(config->management_public_key,
                     sizeof(config->management_public_key)) &&
         config->management_private_key &&
         !zero_bytes(config->management_private_key,
                     MESH_MGMT_ED25519_PRIVATE_KEY_SIZE) &&
         !zero_bytes(config->tls_certificate_sha256,
                     sizeof(config->tls_certificate_sha256)) &&
         config->certificate_serial != 0u &&
         config->certificate_policy_generation != 0u &&
         config->hello_lifetime_ms != 0u &&
         config->claim_interval_ms != 0u && config->now_ms &&
         config->random_bytes && config->exchange && config->poll_local &&
         config->ingest && config->receipt;
}

static void disconnect(mesh_control_agent_service_v1_t *service) {
  service->session_generation = 0u;
  service->lease_generation = 0u;
  memset(service->claimed_message_id, 0,
         sizeof(service->claimed_message_id));
  memset(service->session_id, 0, sizeof(service->session_id));
  service->state = MESH_CONTROL_AGENT_SERVICE_DISCONNECTED;
  service->counters.reconnects++;
}

static mesh_control_result_t exchange_message(
    mesh_control_agent_service_v1_t *service,
    const mesh_control_agent_sync_message_v1_t *request,
    mesh_control_agent_sync_message_v1_t *out_response) {
  uint8_t *request_storage;
  uint8_t *response_storage;
  size_t request_size = 0u;
  size_t response_size = 0u;
  mesh_control_result_t result;
  if (!service->exchange_storage) return MESH_CONTROL_INVALID_STATE;
  request_storage = service->exchange_storage;
  response_storage =
      service->exchange_storage + MESH_CONTROL_MAX_FRAME_SIZE_V1;
  if (mesh_control_agent_sync_encode_v1(
          request, request_storage, MESH_CONTROL_MAX_FRAME_SIZE_V1,
          &request_size) !=
      MESH_CONTROL_AGENT_SYNC_OK)
    return MESH_CONTROL_INVALID_STATE;
  result = service->config.exchange(
      service->config.exchange_context, request_storage, request_size,
      response_storage, MESH_CONTROL_MAX_FRAME_SIZE_V1, &response_size);
  if (result != MESH_CONTROL_OK) {
    service->counters.transport_failures++;
    disconnect(service);
    return result;
  }
  if (mesh_control_agent_sync_decode_v1(response_storage, response_size,
                                        out_response) !=
          MESH_CONTROL_AGENT_SYNC_OK ||
      !mesh_mgmt_crypto_equal_32(out_response->node_id,
                                 service->config.node_id) ||
      !mesh_mgmt_crypto_equal_16(out_response->session_id,
                                 service->session_id) ||
      out_response->request_token != request->request_token) {
    service->counters.protocol_failures++;
    disconnect(service);
    return MESH_CONTROL_INVALID_STATE;
  }
  return MESH_CONTROL_OK;
}

static mesh_control_result_t send_hello(
    mesh_control_agent_service_v1_t *service, uint64_t now_ms) {
  mesh_control_agent_sync_message_v1_t request;
  mesh_control_agent_sync_message_v1_t response;
  mesh_control_agent_sync_hello_v1_t hello;
  uint8_t hello_payload[MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1];
  size_t hello_size = 0u;
  mesh_control_result_t result;
  if (UINT64_MAX - now_ms < service->config.hello_lifetime_ms)
    return MESH_CONTROL_INVALID_STATE;
  if (zero_bytes(service->session_id, sizeof(service->session_id)) &&
      service->config.random_bytes(service->config.random_context,
                                   service->session_id,
                                   sizeof(service->session_id)) != 0)
    return MESH_CONTROL_INVALID_STATE;
  if (zero_bytes(service->session_id, sizeof(service->session_id)))
    return MESH_CONTROL_INVALID_STATE;
  memset(&request, 0, sizeof(request));
  memset(&hello, 0, sizeof(hello));
  request.kind = MESH_CONTROL_AGENT_SYNC_HELLO;
  memcpy(request.node_id, service->config.node_id, sizeof(request.node_id));
  memcpy(request.session_id, service->session_id, sizeof(request.session_id));
  request.request_token = next_token(service);
  request.sent_at_ms = now_ms;
  request.payload = hello_payload;
  request.payload_size = sizeof(hello_payload);
  hello.certificate_serial = service->config.certificate_serial;
  hello.not_before_ms = now_ms;
  hello.expires_at_ms = now_ms + service->config.hello_lifetime_ms;
  memcpy(hello.tls_certificate_sha256,
         service->config.tls_certificate_sha256,
         sizeof(hello.tls_certificate_sha256));
  memcpy(hello.management_public_key, service->config.management_public_key,
         sizeof(hello.management_public_key));
  if (service->config.random_bytes(service->config.random_context, hello.nonce,
                                   sizeof(hello.nonce)) != 0 ||
      zero_bytes(hello.nonce, sizeof(hello.nonce)) ||
      mesh_control_agent_sync_hello_sign_v1(
          &request, service->config.management_private_key, &hello) !=
          MESH_CONTROL_AGENT_SYNC_OK ||
      mesh_control_agent_sync_hello_encode_v1(
          &hello, hello_payload, sizeof(hello_payload), &hello_size) !=
          MESH_CONTROL_AGENT_SYNC_OK ||
      hello_size != sizeof(hello_payload))
    return MESH_CONTROL_INVALID_STATE;
  result = exchange_message(service, &request, &response);
  if (result != MESH_CONTROL_OK) return result;
  if (response.kind != MESH_CONTROL_AGENT_SYNC_HELLO_ACK ||
      response.status != MESH_CONTROL_OK || response.session_generation == 0u) {
    service->counters.protocol_failures++;
    disconnect(service);
    return MESH_CONTROL_STALE_EPOCH;
  }
  service->session_generation = response.session_generation;
  service->state = MESH_CONTROL_AGENT_SERVICE_READY;
  service->next_claim_at_ms = now_ms;
  service->counters.hellos++;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t claim(mesh_control_agent_service_v1_t *service,
                                   uint64_t now_ms) {
  mesh_control_agent_sync_message_v1_t request;
  mesh_control_agent_sync_message_v1_t response;
  uint8_t receipt[MESH_CONTROL_RECEIPT_SIZE_V1];
  size_t receipt_size = 0u;
  mesh_control_result_t result;
  memset(&request, 0, sizeof(request));
  request.kind = MESH_CONTROL_AGENT_SYNC_CLAIM_REQUEST;
  memcpy(request.node_id, service->config.node_id, sizeof(request.node_id));
  memcpy(request.session_id, service->session_id, sizeof(request.session_id));
  request.session_generation = service->session_generation;
  request.request_token = next_token(service);
  request.sent_at_ms = now_ms;
  result = exchange_message(service, &request, &response);
  if (result != MESH_CONTROL_OK) return result;
  service->counters.claims++;
  service->next_claim_at_ms = now_ms + service->config.claim_interval_ms;
  if (response.kind == MESH_CONTROL_AGENT_SYNC_ERROR &&
      response.status == MESH_CONTROL_EMPTY)
    return MESH_CONTROL_OK;
  if (response.kind != MESH_CONTROL_AGENT_SYNC_COMMAND ||
      response.status != MESH_CONTROL_OK ||
      response.session_generation != service->session_generation) {
    service->counters.protocol_failures++;
    disconnect(service);
    return MESH_CONTROL_INVALID_STATE;
  }
  memcpy(service->claimed_message_id, response.message_id,
         sizeof(service->claimed_message_id));
  service->lease_generation = response.lease_generation;
  result = service->config.receipt(
      service->config.local_context, service->claimed_message_id, receipt,
      &receipt_size);
  if (result != MESH_CONTROL_OK && result != MESH_CONTROL_EMPTY) {
    service->counters.local_failures++;
    disconnect(service);
    return result;
  }
  if (result == MESH_CONTROL_EMPTY) {
    result = service->config.ingest(service->config.local_context,
                                    response.payload, response.payload_size);
    if (result != MESH_CONTROL_OK) {
      service->counters.local_failures++;
      disconnect(service);
      return result;
    }
  }
  service->state = MESH_CONTROL_AGENT_SERVICE_WAITING_DURABLE_RECEIPT;
  service->counters.commands++;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t send_receipt(
    mesh_control_agent_service_v1_t *service, uint64_t now_ms) {
  mesh_control_agent_sync_message_v1_t request;
  mesh_control_agent_sync_message_v1_t response;
  uint8_t receipt[MESH_CONTROL_RECEIPT_SIZE_V1];
  size_t receipt_size = 0u;
  mesh_control_result_t result = service->config.receipt(
      service->config.local_context, service->claimed_message_id, receipt,
      &receipt_size);
  if (result == MESH_CONTROL_EMPTY) return MESH_CONTROL_OK;
  if (result != MESH_CONTROL_OK || receipt_size != sizeof(receipt)) {
    service->counters.local_failures++;
    return result == MESH_CONTROL_OK ? MESH_CONTROL_INVALID_STATE : result;
  }
  memset(&request, 0, sizeof(request));
  request.kind = MESH_CONTROL_AGENT_SYNC_RECEIPT;
  memcpy(request.node_id, service->config.node_id, sizeof(request.node_id));
  memcpy(request.session_id, service->session_id, sizeof(request.session_id));
  memcpy(request.message_id, service->claimed_message_id,
         sizeof(request.message_id));
  request.session_generation = service->session_generation;
  request.lease_generation = service->lease_generation;
  request.request_token = next_token(service);
  request.sent_at_ms = now_ms;
  request.payload = receipt;
  request.payload_size = receipt_size;
  result = exchange_message(service, &request, &response);
  if (result != MESH_CONTROL_OK) return result;
  if (response.kind != MESH_CONTROL_AGENT_SYNC_HEARTBEAT ||
      response.status != MESH_CONTROL_OK ||
      response.session_generation != service->session_generation) {
    service->counters.protocol_failures++;
    disconnect(service);
    return MESH_CONTROL_INVALID_STATE;
  }
  memset(service->claimed_message_id, 0,
         sizeof(service->claimed_message_id));
  service->lease_generation = 0u;
  service->state = MESH_CONTROL_AGENT_SERVICE_READY;
  service->next_claim_at_ms = now_ms;
  service->counters.receipts++;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_service_init_v1(
    mesh_control_agent_service_v1_t *service,
    const mesh_control_agent_service_config_v1_t *config) {
  if (!service || service->initialized || !config_valid(config))
    return MESH_CONTROL_INVALID_ARG;
  memset(service, 0, sizeof(*service));
  service->exchange_storage =
      (uint8_t *)calloc(1u, AGENT_SERVICE_EXCHANGE_STORAGE_SIZE_V1);
  if (!service->exchange_storage)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  service->config = *config;
  service->request_token = 1u;
  service->certificate_policy_generation =
      config->certificate_policy_generation;
  service->state = MESH_CONTROL_AGENT_SERVICE_DISCONNECTED;
  service->accepting = 1u;
  service->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_service_init_http_v1(
    mesh_control_agent_service_v1_t *service, mesh_control_agent_v1_t *agent,
    mesh_control_agent_http_client_v1_t *http_client,
    const mesh_control_agent_service_config_v1_t *identity_config) {
  mesh_control_agent_service_config_v1_t config;
  if (!agent || !agent->running || !http_client || !http_client->initialized ||
      !identity_config)
    return MESH_CONTROL_INVALID_ARG;
  config = *identity_config;
  config.exchange = real_exchange;
  config.exchange_context = http_client;
  config.poll_local = real_poll;
  config.ingest = real_ingest;
  config.receipt = real_receipt;
  config.local_context = agent;
  return mesh_control_agent_service_init_v1(service, &config);
}

mesh_control_result_t mesh_control_agent_service_poll_v1(
    mesh_control_agent_service_v1_t *service, size_t *out_progress) {
  uint64_t before;
  uint64_t now_ms;
  size_t local_progress = 0u;
  mesh_control_result_t result;
  if (!service || !service->initialized || !service->accepting ||
      !out_progress)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  before = service->counters.hellos + service->counters.claims +
           service->counters.commands + service->counters.receipts;
  result = service->config.poll_local(service->config.local_context,
                                      &local_progress);
  if (result != MESH_CONTROL_OK) {
    service->counters.local_failures++;
    return result;
  }
  now_ms = service->config.now_ms(service->config.now_context);
  if (now_ms == 0u) return MESH_CONTROL_INVALID_STATE;
  if (service->state == MESH_CONTROL_AGENT_SERVICE_DISCONNECTED)
    result = send_hello(service, now_ms);
  else if (service->state == MESH_CONTROL_AGENT_SERVICE_WAITING_DURABLE_RECEIPT)
    result = send_receipt(service, now_ms);
  else if (service->state == MESH_CONTROL_AGENT_SERVICE_READY &&
           now_ms >= service->next_claim_at_ms)
    result = claim(service, now_ms);
  else
    result = MESH_CONTROL_OK;
  *out_progress = local_progress +
                  (before != service->counters.hellos +
                                 service->counters.claims +
                                 service->counters.commands +
                                 service->counters.receipts);
  return result;
}

mesh_control_result_t mesh_control_agent_service_close_v1(
    mesh_control_agent_service_v1_t *service) {
  if (!service || !service->initialized) return MESH_CONTROL_INVALID_ARG;
  service->accepting = 0u;
  service->state = MESH_CONTROL_AGENT_SERVICE_CLOSED;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_service_rotate_certificate_v1(
    mesh_control_agent_service_v1_t *service,
    mesh_control_agent_http_client_v1_t *http_client,
    const mesh_certificate_lifecycle_v1_t *lifecycle,
    const turbo_tls_client_config_t *tls_template) {
  turbo_tls_client_config_t tls;
  uint64_t now_ms;
  mesh_control_result_t result;
  if (!service || !service->initialized || !service->accepting ||
      !http_client || !http_client->initialized || !lifecycle ||
      !lifecycle->initialized ||
      lifecycle->role != MESH_CERTIFICATE_ROLE_CLIENT_V1 || !tls_template ||
      lifecycle->policy_generation <= service->certificate_policy_generation)
    return MESH_CONTROL_INVALID_ARG;
  now_ms = service->config.now_ms(service->config.now_context);
  if (!lifecycle->current.configured ||
      now_ms < lifecycle->current.not_before_ms ||
      now_ms >= lifecycle->current.expires_at_ms)
    return MESH_CONTROL_UNAUTHORIZED;
  tls = *tls_template;
  tls.cert_file = lifecycle->current.certificate_file;
  tls.key_file = lifecycle->current.private_key_file;
  tls.verify_peer = 1;
  result = mesh_control_agent_http_client_reload_tls_v1(http_client, &tls);
  if (result != MESH_CONTROL_OK) return result;
  memcpy(service->config.tls_certificate_sha256,
         lifecycle->current.certificate_sha256,
         sizeof(service->config.tls_certificate_sha256));
  service->config.certificate_serial = lifecycle->current.serial;
  service->config.certificate_policy_generation =
      lifecycle->policy_generation;
  service->certificate_policy_generation = lifecycle->policy_generation;
  service->counters.certificate_rotations++;
  disconnect(service);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_service_get_stats_v1(
    const mesh_control_agent_service_v1_t *service,
    mesh_control_agent_service_stats_v1_t *out_stats) {
  if (!service || !service->initialized || !out_stats)
    return MESH_CONTROL_INVALID_ARG;
  *out_stats = service->counters;
  out_stats->session_generation = service->session_generation;
  out_stats->lease_generation = service->lease_generation;
  out_stats->state = service->state;
  return MESH_CONTROL_OK;
}

void mesh_control_agent_service_destroy_v1(
    mesh_control_agent_service_v1_t *service) {
  if (!service) return;
  mesh_mgmt_crypto_wipe(service->session_id, sizeof(service->session_id));
  if (service->exchange_storage) {
    mesh_mgmt_crypto_wipe(service->exchange_storage,
                          AGENT_SERVICE_EXCHANGE_STORAGE_SIZE_V1);
    free(service->exchange_storage);
  }
  memset(service, 0, sizeof(*service));
}

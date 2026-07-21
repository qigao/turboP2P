#include "mesh_stream_bind.h"

#include "mesh_mgmt_wire.h"

#include <platform.h>

#include <stdlib.h>
#include <string.h>

#define BIND_FRAME_LENGTH_OFFSET 0u
#define BIND_FRAME_TYPE_OFFSET 4u
#define BIND_FRAME_VERSION_OFFSET 5u
#define BIND_FRAME_RESERVED_OFFSET 6u

#define BIND_FRAME_VERSION_V1 1u
#define BIND_FRAME_INIT 1u
#define BIND_FRAME_ACCEPT 2u
#define BIND_FRAME_CONFIRM 3u
#define BIND_RANDOM_ATTEMPTS 8u

#define INIT_TICKET_OFFSET 8u
#define INIT_MESH_OFFSET 40u
#define INIT_INITIATOR_NODE_OFFSET 72u
#define INIT_RESPONDER_NODE_OFFSET 104u
#define INIT_STREAM_OFFSET 136u
#define INIT_EPOCH_OFFSET 152u
#define INIT_GENERATION_OFFSET 160u
#define INIT_EXPIRES_OFFSET 168u
#define INIT_CHANNEL_OFFSET 176u
#define INIT_NONCE_OFFSET 208u
#define INIT_INITIATOR_KEY_OFFSET 240u
#define INIT_RESPONDER_KEY_OFFSET 272u
#define INIT_SIGNATURE_OFFSET 304u

#define ACCEPT_TICKET_OFFSET 8u
#define ACCEPT_INIT_HASH_OFFSET 40u
#define ACCEPT_CHANNEL_OFFSET 72u
#define ACCEPT_NONCE_OFFSET 104u
#define ACCEPT_RESPONDER_KEY_OFFSET 136u
#define ACCEPT_SIGNATURE_OFFSET 168u

#define CONFIRM_TICKET_OFFSET 8u
#define CONFIRM_ACCEPT_HASH_OFFSET 40u
#define CONFIRM_CHANNEL_OFFSET 72u
#define CONFIRM_INITIATOR_KEY_OFFSET 104u
#define CONFIRM_SIGNATURE_OFFSET 136u

static const uint8_t INIT_DOMAIN[] = "TurboNet-Mesh-Stream-Bind-v1/init";
static const uint8_t ACCEPT_DOMAIN[] = "TurboNet-Mesh-Stream-Bind-v1/accept";
static const uint8_t CONFIRM_DOMAIN[] = "TurboNet-Mesh-Stream-Bind-v1/confirm";

#define BIND_SIGNING_INPUT_MAX (sizeof(INIT_DOMAIN) - 1u + INIT_SIGNATURE_OFFSET)

_Static_assert(INIT_SIGNATURE_OFFSET + MESH_MGMT_ED25519_SIGNATURE_SIZE ==
                   MESH_STREAM_BIND_INIT_SIZE,
               "INIT layout must match its declared frame size");
_Static_assert(ACCEPT_SIGNATURE_OFFSET + MESH_MGMT_ED25519_SIGNATURE_SIZE ==
                   MESH_STREAM_BIND_ACCEPT_SIZE,
               "ACCEPT layout must match its declared frame size");
_Static_assert(CONFIRM_SIGNATURE_OFFSET + MESH_MGMT_ED25519_SIGNATURE_SIZE ==
                   MESH_STREAM_BIND_CONFIRM_SIZE,
               "CONFIRM layout must match its declared frame size");

static int bytes_are_nonzero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0;
  size_t index = 0;

  for (index = 0; index < length; index++)
    aggregate |= bytes[index];
  return aggregate != 0;
}

static int claims_are_valid(const mesh_stream_bind_claims_v1_t *claims) {
  if (!claims || claims->stream_epoch == 0 || claims->admission_generation == 0) {
    return 0;
  }
  if (!bytes_are_nonzero(claims->mesh_id_hash, sizeof(claims->mesh_id_hash)) ||
      !bytes_are_nonzero(claims->initiator_node_id, sizeof(claims->initiator_node_id)) ||
      !bytes_are_nonzero(claims->initiator_principal_key,
                         sizeof(claims->initiator_principal_key)) ||
      !bytes_are_nonzero(claims->responder_node_id, sizeof(claims->responder_node_id)) ||
      !bytes_are_nonzero(claims->responder_principal_key,
                         sizeof(claims->responder_principal_key)) ||
      !bytes_are_nonzero(claims->stream_id, sizeof(claims->stream_id))) {
    return 0;
  }
  if (mesh_mgmt_crypto_equal_32(claims->initiator_node_id, claims->responder_node_id) ||
      mesh_mgmt_crypto_equal_32(claims->initiator_principal_key, claims->responder_principal_key)) {
    return 0;
  }
  return 1;
}

static void frame_prefix(uint8_t *output, size_t total_size, uint8_t type) {
  memset(output, 0, total_size);
  mesh_mgmt_wire_write_u32(output + BIND_FRAME_LENGTH_OFFSET,
                           (uint32_t)(total_size - sizeof(uint32_t)));
  output[BIND_FRAME_TYPE_OFFSET] = type;
  output[BIND_FRAME_VERSION_OFFSET] = BIND_FRAME_VERSION_V1;
}

static int frame_prefix_is_valid(const uint8_t *input, size_t input_len, size_t expected_size,
                                 uint8_t expected_type) {
  return input && input_len == expected_size &&
         mesh_mgmt_wire_read_u32(input + BIND_FRAME_LENGTH_OFFSET) ==
             expected_size - sizeof(uint32_t) &&
         input[BIND_FRAME_TYPE_OFFSET] == expected_type &&
         input[BIND_FRAME_VERSION_OFFSET] == BIND_FRAME_VERSION_V1 &&
         input[BIND_FRAME_RESERVED_OFFSET] == 0 && input[BIND_FRAME_RESERVED_OFFSET + 1u] == 0;
}

static mesh_stream_bind_result_t
sign_frame(const uint8_t *domain, size_t domain_len,
           const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], uint8_t *frame,
           size_t unsigned_len, uint8_t *signature) {
  uint8_t signing_input[BIND_SIGNING_INPUT_MAX];

  if (domain_len + unsigned_len > sizeof(signing_input))
    return MESH_STREAM_BIND_CRYPTO_FAILURE;
  memcpy(signing_input, domain, domain_len);
  memcpy(signing_input + domain_len, frame, unsigned_len);
  if (mesh_mgmt_ed25519_sign(private_key, signing_input, domain_len + unsigned_len, signature) !=
      MESH_MGMT_CRYPTO_OK) {
    return MESH_STREAM_BIND_CRYPTO_FAILURE;
  }
  return MESH_STREAM_BIND_OK;
}

static mesh_stream_bind_result_t
verify_frame(const uint8_t *domain, size_t domain_len,
             const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE], const uint8_t *frame,
             size_t unsigned_len, const uint8_t *signature) {
  uint8_t signing_input[BIND_SIGNING_INPUT_MAX];

  if (domain_len + unsigned_len > sizeof(signing_input))
    return MESH_STREAM_BIND_CRYPTO_FAILURE;
  memcpy(signing_input, domain, domain_len);
  memcpy(signing_input + domain_len, frame, unsigned_len);
  if (mesh_mgmt_ed25519_verify(public_key, signing_input, domain_len + unsigned_len, signature) !=
      MESH_MGMT_CRYPTO_OK) {
    return MESH_STREAM_BIND_AUTH_FAILED;
  }
  return MESH_STREAM_BIND_OK;
}

static mesh_stream_bind_result_t hash_frame(const uint8_t *frame, size_t frame_len,
                                            uint8_t output[32]) {
  return mesh_mgmt_blake2b_256(frame, frame_len, output) == MESH_MGMT_CRYPTO_OK
             ? MESH_STREAM_BIND_OK
             : MESH_STREAM_BIND_CRYPTO_FAILURE;
}

static mesh_stream_bind_store_entry_v1_t *
find_ticket(mesh_stream_bind_store_v1_t *store, const uint8_t ticket_id[MESH_STREAM_BIND_ID_SIZE]) {
  size_t index = 0;

  if (!store || !store->entries || !ticket_id)
    return NULL;
  for (index = 0; index < store->capacity; index++) {
    mesh_stream_bind_store_entry_v1_t *entry = &store->entries[index];
    if (entry->state != MESH_STREAM_BIND_TICKET_FREE &&
        mesh_mgmt_crypto_equal_32(entry->ticket.ticket_id, ticket_id)) {
      return entry;
    }
  }
  return NULL;
}

static mesh_stream_bind_result_t validate_live_entry(mesh_stream_bind_store_entry_v1_t *entry,
                                                     uint64_t now_ms) {
  if (!entry)
    return MESH_STREAM_BIND_NOT_FOUND;
  if (now_ms >= entry->ticket.expires_at_ms)
    return MESH_STREAM_BIND_EXPIRED;
  if (entry->state == MESH_STREAM_BIND_TICKET_CONSUMED)
    return MESH_STREAM_BIND_REPLAY;
  return MESH_STREAM_BIND_OK;
}

static int ticket_matches_init(const mesh_stream_bind_ticket_v1_t *ticket, const uint8_t *input) {
  const mesh_stream_bind_claims_v1_t *claims = &ticket->claims;

  return mesh_mgmt_crypto_equal_32(ticket->ticket_id, input + INIT_TICKET_OFFSET) &&
         mesh_mgmt_crypto_equal_32(claims->mesh_id_hash, input + INIT_MESH_OFFSET) &&
         mesh_mgmt_crypto_equal_32(claims->initiator_node_id, input + INIT_INITIATOR_NODE_OFFSET) &&
         mesh_mgmt_crypto_equal_32(claims->responder_node_id, input + INIT_RESPONDER_NODE_OFFSET) &&
         memcmp(claims->stream_id, input + INIT_STREAM_OFFSET, sizeof(claims->stream_id)) == 0 &&
         claims->stream_epoch == mesh_mgmt_wire_read_u64(input + INIT_EPOCH_OFFSET) &&
         claims->admission_generation == mesh_mgmt_wire_read_u64(input + INIT_GENERATION_OFFSET) &&
         ticket->expires_at_ms == mesh_mgmt_wire_read_u64(input + INIT_EXPIRES_OFFSET) &&
         mesh_mgmt_crypto_equal_32(claims->initiator_principal_key,
                                   input + INIT_INITIATOR_KEY_OFFSET) &&
         mesh_mgmt_crypto_equal_32(claims->responder_principal_key,
                                   input + INIT_RESPONDER_KEY_OFFSET);
}

mesh_stream_bind_result_t
mesh_stream_bind_store_init_v1(mesh_stream_bind_store_v1_t *store,
                               const mesh_stream_bind_store_config_v1_t *config) {
  mesh_stream_bind_store_entry_v1_t *entries = NULL;

  if (!store || !config || store->entries || store->capacity != 0 || config->capacity == 0 ||
      config->capacity > MESH_STREAM_BIND_MAX_TICKETS || config->max_ttl_ms == 0 ||
      config->max_ttl_ms > MESH_STREAM_BIND_MAX_TTL_MS) {
    return MESH_STREAM_BIND_INVALID_ARG;
  }
  entries = (mesh_stream_bind_store_entry_v1_t *)calloc(config->capacity, sizeof(*entries));
  if (!entries)
    return MESH_STREAM_BIND_RESOURCE_EXHAUSTED;
  store->entries = entries;
  store->capacity = config->capacity;
  store->max_ttl_ms = config->max_ttl_ms;
  return MESH_STREAM_BIND_OK;
}

void mesh_stream_bind_store_destroy_v1(mesh_stream_bind_store_v1_t *store) {
  if (!store)
    return;
  free(store->entries);
  memset(store, 0, sizeof(*store));
}

size_t mesh_stream_bind_ticket_sweep_v1(mesh_stream_bind_store_v1_t *store, uint64_t now_ms) {
  size_t removed = 0;
  size_t index = 0;

  if (!store || !store->entries)
    return 0;
  for (index = 0; index < store->capacity; index++) {
    mesh_stream_bind_store_entry_v1_t *entry = &store->entries[index];
    if (entry->state != MESH_STREAM_BIND_TICKET_FREE && now_ms >= entry->ticket.expires_at_ms) {
      memset(entry, 0, sizeof(*entry));
      removed++;
    }
  }
  return removed;
}

mesh_stream_bind_result_t
mesh_stream_bind_ticket_issue_v1(mesh_stream_bind_store_v1_t *store,
                                 const mesh_stream_bind_claims_v1_t *claims, uint64_t now_ms,
                                 uint64_t ttl_ms, mesh_stream_bind_ticket_v1_t *out_ticket) {
  mesh_stream_bind_store_entry_v1_t *free_entry = NULL;
  mesh_stream_bind_ticket_v1_t ticket;
  size_t index = 0;
  size_t attempt = 0;

  if (out_ticket)
    memset(out_ticket, 0, sizeof(*out_ticket));
  if (!store || !store->entries || !claims_are_valid(claims) || !out_ticket || ttl_ms == 0 ||
      ttl_ms > store->max_ttl_ms || UINT64_MAX - now_ms < ttl_ms) {
    return MESH_STREAM_BIND_INVALID_ARG;
  }
  mesh_stream_bind_ticket_sweep_v1(store, now_ms);
  for (index = 0; index < store->capacity; index++) {
    if (store->entries[index].state == MESH_STREAM_BIND_TICKET_FREE) {
      free_entry = &store->entries[index];
      break;
    }
  }
  if (!free_entry)
    return MESH_STREAM_BIND_RESOURCE_EXHAUSTED;

  memset(&ticket, 0, sizeof(ticket));
  ticket.claims = *claims;
  ticket.issued_at_ms = now_ms;
  ticket.expires_at_ms = now_ms + ttl_ms;
  for (attempt = 0; attempt < BIND_RANDOM_ATTEMPTS; attempt++) {
    if (turbo_secure_random(ticket.ticket_id, sizeof(ticket.ticket_id)) != 0) {
      memset(&ticket, 0, sizeof(ticket));
      return MESH_STREAM_BIND_RANDOM_FAILURE;
    }
    if (!find_ticket(store, ticket.ticket_id))
      break;
  }
  if (attempt == BIND_RANDOM_ATTEMPTS) {
    memset(&ticket, 0, sizeof(ticket));
    return MESH_STREAM_BIND_RANDOM_FAILURE;
  }
  free_entry->ticket = ticket;
  free_entry->state = MESH_STREAM_BIND_TICKET_ISSUED;
  *out_ticket = ticket;
  return MESH_STREAM_BIND_OK;
}

mesh_stream_bind_result_t
mesh_stream_bind_ticket_invalidate_v1(mesh_stream_bind_store_v1_t *store,
                                      const uint8_t ticket_id[MESH_STREAM_BIND_ID_SIZE],
                                      uint64_t now_ms) {
  mesh_stream_bind_store_entry_v1_t *entry = NULL;
  mesh_stream_bind_result_t result;

  if (!store || !store->entries || !ticket_id)
    return MESH_STREAM_BIND_INVALID_ARG;
  entry = find_ticket(store, ticket_id);
  result = validate_live_entry(entry, now_ms);
  if (result != MESH_STREAM_BIND_OK)
    return result;
  entry->state = MESH_STREAM_BIND_TICKET_CONSUMED;
  memset(entry->init_hash, 0, sizeof(entry->init_hash));
  memset(entry->accept_hash, 0, sizeof(entry->accept_hash));
  memset(entry->channel_binding, 0, sizeof(entry->channel_binding));
  return MESH_STREAM_BIND_OK;
}

mesh_stream_bind_result_t
mesh_stream_bind_responder_abort_init_v1(mesh_stream_bind_store_v1_t *store,
                                         const uint8_t *input, size_t input_len,
                                         uint64_t now_ms) {
  if (!frame_prefix_is_valid(input, input_len, MESH_STREAM_BIND_INIT_SIZE, BIND_FRAME_INIT))
    return MESH_STREAM_BIND_INVALID_FRAME;
  return mesh_stream_bind_ticket_invalidate_v1(store, input + INIT_TICKET_OFFSET, now_ms);
}

mesh_stream_bind_result_t mesh_stream_bind_initiator_start_v1(
    mesh_stream_bind_initiator_v1_t *initiator, const mesh_stream_bind_ticket_v1_t *ticket,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    const uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE],
    uint8_t output[MESH_STREAM_BIND_INIT_SIZE]) {
  uint8_t public_key[32];
  mesh_mgmt_crypto_result_t crypto_result;
  mesh_stream_bind_result_t result;

  if (output)
    memset(output, 0, MESH_STREAM_BIND_INIT_SIZE);
  if (!initiator || !ticket || !private_key || !channel_binding || !output ||
      initiator->state != MESH_STREAM_BIND_INITIATOR_UNINITIALIZED ||
      !claims_are_valid(&ticket->claims) ||
      !bytes_are_nonzero(ticket->ticket_id, sizeof(ticket->ticket_id)) ||
      !bytes_are_nonzero(channel_binding, MESH_STREAM_BIND_CHANNEL_BINDING_SIZE) ||
      ticket->issued_at_ms >= ticket->expires_at_ms) {
    return MESH_STREAM_BIND_INVALID_ARG;
  }
  crypto_result = mesh_mgmt_ed25519_public_from_private(private_key, public_key);
  if (crypto_result != MESH_MGMT_CRYPTO_OK)
    return MESH_STREAM_BIND_CRYPTO_FAILURE;
  if (!mesh_mgmt_crypto_equal_32(public_key, ticket->claims.initiator_principal_key)) {
    return MESH_STREAM_BIND_AUTH_FAILED;
  }

  frame_prefix(output, MESH_STREAM_BIND_INIT_SIZE, BIND_FRAME_INIT);
  memcpy(output + INIT_TICKET_OFFSET, ticket->ticket_id, 32);
  memcpy(output + INIT_MESH_OFFSET, ticket->claims.mesh_id_hash, 32);
  memcpy(output + INIT_INITIATOR_NODE_OFFSET, ticket->claims.initiator_node_id, 32);
  memcpy(output + INIT_RESPONDER_NODE_OFFSET, ticket->claims.responder_node_id, 32);
  memcpy(output + INIT_STREAM_OFFSET, ticket->claims.stream_id, 16);
  mesh_mgmt_wire_write_u64(output + INIT_EPOCH_OFFSET, ticket->claims.stream_epoch);
  mesh_mgmt_wire_write_u64(output + INIT_GENERATION_OFFSET, ticket->claims.admission_generation);
  mesh_mgmt_wire_write_u64(output + INIT_EXPIRES_OFFSET, ticket->expires_at_ms);
  memcpy(output + INIT_CHANNEL_OFFSET, channel_binding, 32);
  if (turbo_secure_random(output + INIT_NONCE_OFFSET, MESH_STREAM_BIND_NONCE_SIZE) != 0) {
    memset(output, 0, MESH_STREAM_BIND_INIT_SIZE);
    return MESH_STREAM_BIND_RANDOM_FAILURE;
  }
  memcpy(output + INIT_INITIATOR_KEY_OFFSET, ticket->claims.initiator_principal_key, 32);
  memcpy(output + INIT_RESPONDER_KEY_OFFSET, ticket->claims.responder_principal_key, 32);
  result = sign_frame(INIT_DOMAIN, sizeof(INIT_DOMAIN) - 1u, private_key, output,
                      INIT_SIGNATURE_OFFSET, output + INIT_SIGNATURE_OFFSET);
  if (result != MESH_STREAM_BIND_OK) {
    memset(output, 0, MESH_STREAM_BIND_INIT_SIZE);
    return result;
  }
  initiator->ticket = *ticket;
  memcpy(initiator->channel_binding, channel_binding, 32);
  result = hash_frame(output, MESH_STREAM_BIND_INIT_SIZE, initiator->init_hash);
  if (result != MESH_STREAM_BIND_OK) {
    memset(initiator, 0, sizeof(*initiator));
    memset(output, 0, MESH_STREAM_BIND_INIT_SIZE);
    return result;
  }
  initiator->state = MESH_STREAM_BIND_INITIATOR_STARTED;
  return MESH_STREAM_BIND_OK;
}

mesh_stream_bind_result_t mesh_stream_bind_responder_accept_v1(
    mesh_stream_bind_store_v1_t *store, const uint8_t *input, size_t input_len,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    const uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE], uint64_t now_ms,
    uint8_t output[MESH_STREAM_BIND_ACCEPT_SIZE]) {
  mesh_stream_bind_store_entry_v1_t *entry = NULL;
  mesh_stream_bind_result_t result;
  mesh_mgmt_crypto_result_t crypto_result;
  uint8_t responder_public[32];
  uint8_t init_hash[32];
  uint8_t accept_hash[32];

  if (output)
    memset(output, 0, MESH_STREAM_BIND_ACCEPT_SIZE);
  if (!store || !store->entries || !private_key || !channel_binding || !output)
    return MESH_STREAM_BIND_INVALID_ARG;
  if (!bytes_are_nonzero(channel_binding, MESH_STREAM_BIND_CHANNEL_BINDING_SIZE))
    return MESH_STREAM_BIND_INVALID_ARG;
  if (!frame_prefix_is_valid(input, input_len, MESH_STREAM_BIND_INIT_SIZE, BIND_FRAME_INIT)) {
    return MESH_STREAM_BIND_INVALID_FRAME;
  }
  entry = find_ticket(store, input + INIT_TICKET_OFFSET);
  result = validate_live_entry(entry, now_ms);
  if (result != MESH_STREAM_BIND_OK)
    return result;
  if (entry->state != MESH_STREAM_BIND_TICKET_ISSUED)
    return MESH_STREAM_BIND_REPLAY;
  if (!ticket_matches_init(&entry->ticket, input))
    return MESH_STREAM_BIND_AUTH_FAILED;
  if (!mesh_mgmt_crypto_equal_32(channel_binding, input + INIT_CHANNEL_OFFSET)) {
    return MESH_STREAM_BIND_CHANNEL_MISMATCH;
  }
  result = verify_frame(INIT_DOMAIN, sizeof(INIT_DOMAIN) - 1u,
                        entry->ticket.claims.initiator_principal_key, input, INIT_SIGNATURE_OFFSET,
                        input + INIT_SIGNATURE_OFFSET);
  if (result != MESH_STREAM_BIND_OK)
    return result;
  crypto_result = mesh_mgmt_ed25519_public_from_private(private_key, responder_public);
  if (crypto_result != MESH_MGMT_CRYPTO_OK)
    return MESH_STREAM_BIND_CRYPTO_FAILURE;
  if (!mesh_mgmt_crypto_equal_32(responder_public, entry->ticket.claims.responder_principal_key)) {
    return MESH_STREAM_BIND_AUTH_FAILED;
  }
  result = hash_frame(input, input_len, init_hash);
  if (result != MESH_STREAM_BIND_OK)
    return result;

  frame_prefix(output, MESH_STREAM_BIND_ACCEPT_SIZE, BIND_FRAME_ACCEPT);
  memcpy(output + ACCEPT_TICKET_OFFSET, entry->ticket.ticket_id, 32);
  memcpy(output + ACCEPT_INIT_HASH_OFFSET, init_hash, 32);
  memcpy(output + ACCEPT_CHANNEL_OFFSET, channel_binding, 32);
  if (turbo_secure_random(output + ACCEPT_NONCE_OFFSET, MESH_STREAM_BIND_NONCE_SIZE) != 0) {
    memset(output, 0, MESH_STREAM_BIND_ACCEPT_SIZE);
    return MESH_STREAM_BIND_RANDOM_FAILURE;
  }
  memcpy(output + ACCEPT_RESPONDER_KEY_OFFSET, responder_public, 32);
  result = sign_frame(ACCEPT_DOMAIN, sizeof(ACCEPT_DOMAIN) - 1u, private_key, output,
                      ACCEPT_SIGNATURE_OFFSET, output + ACCEPT_SIGNATURE_OFFSET);
  if (result != MESH_STREAM_BIND_OK) {
    memset(output, 0, MESH_STREAM_BIND_ACCEPT_SIZE);
    return result;
  }
  result = hash_frame(output, MESH_STREAM_BIND_ACCEPT_SIZE, accept_hash);
  if (result != MESH_STREAM_BIND_OK) {
    memset(output, 0, MESH_STREAM_BIND_ACCEPT_SIZE);
    return result;
  }
  memcpy(entry->init_hash, init_hash, 32);
  memcpy(entry->accept_hash, accept_hash, 32);
  memcpy(entry->channel_binding, channel_binding, 32);
  entry->state = MESH_STREAM_BIND_TICKET_CHALLENGE;
  return MESH_STREAM_BIND_OK;
}

mesh_stream_bind_result_t
mesh_stream_bind_initiator_confirm_v1(mesh_stream_bind_initiator_v1_t *initiator,
                                      const uint8_t *input, size_t input_len,
                                      const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
                                      const uint8_t channel_binding
                                          [MESH_STREAM_BIND_CHANNEL_BINDING_SIZE],
                                      uint8_t output[MESH_STREAM_BIND_CONFIRM_SIZE]) {
  mesh_stream_bind_result_t result;
  mesh_mgmt_crypto_result_t crypto_result;
  uint8_t initiator_public[32];
  uint8_t accept_hash[32];

  if (output)
    memset(output, 0, MESH_STREAM_BIND_CONFIRM_SIZE);
  if (!initiator || !input || !private_key || !channel_binding || !output)
    return MESH_STREAM_BIND_INVALID_ARG;
  if (initiator->state != MESH_STREAM_BIND_INITIATOR_STARTED) {
    return MESH_STREAM_BIND_INVALID_STATE;
  }
  if (!mesh_mgmt_crypto_equal_32(initiator->channel_binding, channel_binding))
    return MESH_STREAM_BIND_CHANNEL_MISMATCH;
  if (!frame_prefix_is_valid(input, input_len, MESH_STREAM_BIND_ACCEPT_SIZE, BIND_FRAME_ACCEPT)) {
    return MESH_STREAM_BIND_INVALID_FRAME;
  }
  if (!mesh_mgmt_crypto_equal_32(initiator->ticket.ticket_id, input + ACCEPT_TICKET_OFFSET) ||
      !mesh_mgmt_crypto_equal_32(initiator->init_hash, input + ACCEPT_INIT_HASH_OFFSET)) {
    return MESH_STREAM_BIND_AUTH_FAILED;
  }
  if (!mesh_mgmt_crypto_equal_32(initiator->channel_binding, input + ACCEPT_CHANNEL_OFFSET)) {
    return MESH_STREAM_BIND_CHANNEL_MISMATCH;
  }
  if (!mesh_mgmt_crypto_equal_32(initiator->ticket.claims.responder_principal_key,
                                 input + ACCEPT_RESPONDER_KEY_OFFSET)) {
    return MESH_STREAM_BIND_AUTH_FAILED;
  }
  result = verify_frame(ACCEPT_DOMAIN, sizeof(ACCEPT_DOMAIN) - 1u,
                        initiator->ticket.claims.responder_principal_key, input,
                        ACCEPT_SIGNATURE_OFFSET, input + ACCEPT_SIGNATURE_OFFSET);
  if (result != MESH_STREAM_BIND_OK)
    return result;
  crypto_result = mesh_mgmt_ed25519_public_from_private(private_key, initiator_public);
  if (crypto_result != MESH_MGMT_CRYPTO_OK)
    return MESH_STREAM_BIND_CRYPTO_FAILURE;
  if (!mesh_mgmt_crypto_equal_32(initiator_public,
                                 initiator->ticket.claims.initiator_principal_key)) {
    return MESH_STREAM_BIND_AUTH_FAILED;
  }
  result = hash_frame(input, input_len, accept_hash);
  if (result != MESH_STREAM_BIND_OK)
    return result;

  frame_prefix(output, MESH_STREAM_BIND_CONFIRM_SIZE, BIND_FRAME_CONFIRM);
  memcpy(output + CONFIRM_TICKET_OFFSET, initiator->ticket.ticket_id, 32);
  memcpy(output + CONFIRM_ACCEPT_HASH_OFFSET, accept_hash, 32);
  memcpy(output + CONFIRM_CHANNEL_OFFSET, initiator->channel_binding, 32);
  memcpy(output + CONFIRM_INITIATOR_KEY_OFFSET, initiator_public, 32);
  result = sign_frame(CONFIRM_DOMAIN, sizeof(CONFIRM_DOMAIN) - 1u, private_key, output,
                      CONFIRM_SIGNATURE_OFFSET, output + CONFIRM_SIGNATURE_OFFSET);
  if (result != MESH_STREAM_BIND_OK) {
    memset(output, 0, MESH_STREAM_BIND_CONFIRM_SIZE);
    return result;
  }
  initiator->state = MESH_STREAM_BIND_INITIATOR_CONFIRM_READY;
  return MESH_STREAM_BIND_OK;
}

mesh_stream_bind_result_t
mesh_stream_bind_responder_finish_v1(mesh_stream_bind_store_v1_t *store, const uint8_t *input,
                                     size_t input_len,
                                     const uint8_t channel_binding
                                         [MESH_STREAM_BIND_CHANNEL_BINDING_SIZE],
                                     uint64_t now_ms,
                                     mesh_stream_bind_ticket_v1_t *out_ticket) {
  mesh_stream_bind_store_entry_v1_t *entry = NULL;
  mesh_stream_bind_result_t result;

  if (out_ticket)
    memset(out_ticket, 0, sizeof(*out_ticket));
  if (!store || !store->entries || !channel_binding || !out_ticket)
    return MESH_STREAM_BIND_INVALID_ARG;
  if (!frame_prefix_is_valid(input, input_len, MESH_STREAM_BIND_CONFIRM_SIZE, BIND_FRAME_CONFIRM)) {
    return MESH_STREAM_BIND_INVALID_FRAME;
  }
  entry = find_ticket(store, input + CONFIRM_TICKET_OFFSET);
  result = validate_live_entry(entry, now_ms);
  if (result != MESH_STREAM_BIND_OK)
    return result;
  if (entry->state != MESH_STREAM_BIND_TICKET_CHALLENGE)
    return MESH_STREAM_BIND_INVALID_STATE;
  if (!mesh_mgmt_crypto_equal_32(entry->channel_binding, channel_binding))
    return MESH_STREAM_BIND_CHANNEL_MISMATCH;
  if (!mesh_mgmt_crypto_equal_32(entry->channel_binding, input + CONFIRM_CHANNEL_OFFSET))
    return MESH_STREAM_BIND_CHANNEL_MISMATCH;
  if (!mesh_mgmt_crypto_equal_32(entry->accept_hash, input + CONFIRM_ACCEPT_HASH_OFFSET) ||
      !mesh_mgmt_crypto_equal_32(entry->ticket.claims.initiator_principal_key,
                                 input + CONFIRM_INITIATOR_KEY_OFFSET)) {
    return MESH_STREAM_BIND_AUTH_FAILED;
  }
  result = verify_frame(CONFIRM_DOMAIN, sizeof(CONFIRM_DOMAIN) - 1u,
                        entry->ticket.claims.initiator_principal_key, input,
                        CONFIRM_SIGNATURE_OFFSET, input + CONFIRM_SIGNATURE_OFFSET);
  if (result != MESH_STREAM_BIND_OK)
    return result;
  *out_ticket = entry->ticket;
  entry->state = MESH_STREAM_BIND_TICKET_CONSUMED;
  memset(entry->init_hash, 0, sizeof(entry->init_hash));
  memset(entry->accept_hash, 0, sizeof(entry->accept_hash));
  memset(entry->channel_binding, 0, sizeof(entry->channel_binding));
  return MESH_STREAM_BIND_OK;
}

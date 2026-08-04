#include "m3_chunk_receipt.h"

#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

#define RECEIPT_BODY_SIZE 112u
#define RECEIPT_MAGIC_OFFSET 0u
#define RECEIPT_NODE_ID_OFFSET 8u
#define RECEIPT_ALGORITHM_OFFSET 40u
#define RECEIPT_RESERVED_OFFSET 41u
#define RECEIPT_SIZE_OFFSET 48u
#define RECEIPT_DIGEST_OFFSET 56u
#define RECEIPT_REQUEST_ID_OFFSET 88u
#define RECEIPT_ISSUED_AT_OFFSET 104u
#define RECEIPT_SIGNATURE_OFFSET RECEIPT_BODY_SIZE

static const uint8_t RECEIPT_MAGIC[8] = {
    'M', '3', 'R', 'C', 'P', 'T', '1', 0,
};

static void write_u64(uint8_t output[8], uint64_t value) {
  for (size_t i = 0; i < 8u; i++)
    output[i] = (uint8_t)(value >> (56u - i * 8u));
}

static uint64_t read_u64(const uint8_t input[8]) {
  uint64_t value = 0u;

  for (size_t i = 0; i < 8u; i++)
    value = (value << 8u) | input[i];
  return value;
}

static int bytes_are_nonzero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < size; i++)
    aggregate |= bytes[i];
  return aggregate != 0u;
}

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < size; i++)
    aggregate |= bytes[i];
  return aggregate == 0u;
}

static int cid_is_valid(const m3_chunk_cid_v1_t *cid) {
  return cid &&
         cid->hash_algorithm == M3_CHUNK_STORE_HASH_ALGORITHM_SHA256 &&
         bytes_are_nonzero(cid->digest, sizeof(cid->digest));
}

static int receipt_is_well_formed(const m3_chunk_receipt_v1_t *receipt) {
  return receipt &&
         bytes_are_nonzero(receipt->store_node_id,
                           sizeof(receipt->store_node_id)) &&
         cid_is_valid(&receipt->cid) &&
         bytes_are_nonzero(receipt->request_id.bytes,
                           sizeof(receipt->request_id.bytes)) &&
         receipt->issued_at_ms != 0u;
}

static m3_chunk_receipt_result_t encode_body(
    const m3_chunk_receipt_v1_t *receipt, uint8_t output[RECEIPT_BODY_SIZE]) {
  memset(output, 0, RECEIPT_BODY_SIZE);
  memcpy(output + RECEIPT_MAGIC_OFFSET, RECEIPT_MAGIC, sizeof(RECEIPT_MAGIC));
  memcpy(output + RECEIPT_NODE_ID_OFFSET, receipt->store_node_id,
         sizeof(receipt->store_node_id));
  output[RECEIPT_ALGORITHM_OFFSET] = receipt->cid.hash_algorithm;
  write_u64(output + RECEIPT_SIZE_OFFSET, receipt->cid.size);
  memcpy(output + RECEIPT_DIGEST_OFFSET, receipt->cid.digest,
         sizeof(receipt->cid.digest));
  memcpy(output + RECEIPT_REQUEST_ID_OFFSET, receipt->request_id.bytes,
         sizeof(receipt->request_id.bytes));
  write_u64(output + RECEIPT_ISSUED_AT_OFFSET, receipt->issued_at_ms);
  return M3_CHUNK_RECEIPT_OK;
}

static m3_chunk_receipt_result_t decode_body(
    const uint8_t input[RECEIPT_BODY_SIZE], m3_chunk_receipt_v1_t *out) {
  m3_chunk_receipt_v1_t receipt = {0};

  if (!bytes_are_zero(input + RECEIPT_RESERVED_OFFSET, 7u))
    return M3_CHUNK_RECEIPT_CORRUPT;
  memcpy(receipt.store_node_id, input + RECEIPT_NODE_ID_OFFSET,
         sizeof(receipt.store_node_id));
  receipt.cid.hash_algorithm = input[RECEIPT_ALGORITHM_OFFSET];
  receipt.cid.size = read_u64(input + RECEIPT_SIZE_OFFSET);
  memcpy(receipt.cid.digest, input + RECEIPT_DIGEST_OFFSET,
         sizeof(receipt.cid.digest));
  memcpy(receipt.request_id.bytes, input + RECEIPT_REQUEST_ID_OFFSET,
         sizeof(receipt.request_id.bytes));
  receipt.issued_at_ms = read_u64(input + RECEIPT_ISSUED_AT_OFFSET);
  if (!receipt_is_well_formed(&receipt))
    return M3_CHUNK_RECEIPT_CORRUPT;
  *out = receipt;
  return M3_CHUNK_RECEIPT_OK;
}

static m3_chunk_receipt_result_t calculate_digest(
    const uint8_t *bytes, size_t size,
    uint8_t output[M3_CHUNK_RECEIPT_DIGEST_SIZE]) {
  unsigned int digest_size = 0u;
  m3_chunk_receipt_result_t result = M3_CHUNK_RECEIPT_CRYPTO_FAILED;

  if (!bytes || size != M3_CHUNK_RECEIPT_ENCODED_SIZE || !output)
    return M3_CHUNK_RECEIPT_INVALID_ARG;
  if (EVP_Digest(bytes, size, output, &digest_size, EVP_sha256(), NULL) != 1 ||
      digest_size != M3_CHUNK_RECEIPT_DIGEST_SIZE) {
    memset(output, 0, M3_CHUNK_RECEIPT_DIGEST_SIZE);
    return result;
  }
  return M3_CHUNK_RECEIPT_OK;
}

m3_chunk_receipt_result_t m3_chunk_receipt_validate_v1(
    const m3_chunk_receipt_v1_t *receipt) {
  return receipt_is_well_formed(receipt) ? M3_CHUNK_RECEIPT_OK
                                         : M3_CHUNK_RECEIPT_INVALID_ARG;
}

m3_chunk_receipt_result_t m3_chunk_receipt_encode_v1(
    const m3_chunk_receipt_v1_t *receipt, uint8_t *out_bytes,
    size_t *out_size) {
  uint8_t body[RECEIPT_BODY_SIZE];
  m3_chunk_receipt_result_t result;

  if (!out_bytes || !out_size)
    return M3_CHUNK_RECEIPT_INVALID_ARG;
  *out_size = 0u;
  result = m3_chunk_receipt_validate_v1(receipt);
  if (result != M3_CHUNK_RECEIPT_OK)
    return result;
  result = encode_body(receipt, body);
  if (result != M3_CHUNK_RECEIPT_OK)
    return result;
  memcpy(out_bytes, body, sizeof(body));
  memcpy(out_bytes + RECEIPT_SIGNATURE_OFFSET, receipt->signature,
         sizeof(receipt->signature));
  *out_size = M3_CHUNK_RECEIPT_ENCODED_SIZE;
  return M3_CHUNK_RECEIPT_OK;
}

m3_chunk_receipt_result_t m3_chunk_receipt_decode_v1(
    const uint8_t *bytes, size_t size, m3_chunk_receipt_v1_t *out_receipt) {
  m3_chunk_receipt_v1_t receipt = {0};
  m3_chunk_receipt_result_t result;

  if (!bytes || !out_receipt)
    return M3_CHUNK_RECEIPT_INVALID_ARG;
  memset(out_receipt, 0, sizeof(*out_receipt));
  if (size != M3_CHUNK_RECEIPT_ENCODED_SIZE ||
      memcmp(bytes + RECEIPT_MAGIC_OFFSET, RECEIPT_MAGIC,
             sizeof(RECEIPT_MAGIC)) != 0) {
    return M3_CHUNK_RECEIPT_CORRUPT;
  }
  result = decode_body(bytes, &receipt);
  if (result != M3_CHUNK_RECEIPT_OK)
    return result;
  memcpy(receipt.signature, bytes + RECEIPT_SIGNATURE_OFFSET,
         sizeof(receipt.signature));
  *out_receipt = receipt;
  return M3_CHUNK_RECEIPT_OK;
}

m3_chunk_receipt_result_t m3_chunk_receipt_sign_v1(
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    m3_chunk_receipt_v1_t *receipt) {
  uint8_t body[RECEIPT_BODY_SIZE];
  uint8_t signature[M3_CHUNK_RECEIPT_SIGNATURE_SIZE];
  m3_chunk_receipt_result_t result;

  if (!private_key || !receipt)
    return M3_CHUNK_RECEIPT_INVALID_ARG;
  memset(signature, 0, sizeof(signature));
  result = m3_chunk_receipt_validate_v1(receipt);
  if (result != M3_CHUNK_RECEIPT_OK)
    return result;
  result = encode_body(receipt, body);
  if (result != M3_CHUNK_RECEIPT_OK)
    return result;
  if (mesh_mgmt_ed25519_sign(private_key, body, sizeof(body), signature) !=
      MESH_MGMT_CRYPTO_OK) {
    return M3_CHUNK_RECEIPT_CRYPTO_FAILED;
  }
  memcpy(receipt->signature, signature, sizeof(signature));
  return M3_CHUNK_RECEIPT_OK;
}

m3_chunk_receipt_result_t m3_chunk_receipt_verify_v1(
    const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const m3_chunk_receipt_v1_t *receipt) {
  uint8_t body[RECEIPT_BODY_SIZE];
  m3_chunk_receipt_result_t result;

  if (!public_key || !receipt)
    return M3_CHUNK_RECEIPT_INVALID_ARG;
  result = m3_chunk_receipt_validate_v1(receipt);
  if (result != M3_CHUNK_RECEIPT_OK)
    return result;
  result = encode_body(receipt, body);
  if (result != M3_CHUNK_RECEIPT_OK)
    return result;
  if (mesh_mgmt_ed25519_verify(public_key, body, sizeof(body),
                               receipt->signature) == MESH_MGMT_CRYPTO_OK) {
    return M3_CHUNK_RECEIPT_OK;
  }
  return M3_CHUNK_RECEIPT_AUTH_FAILED;
}

m3_chunk_receipt_result_t m3_chunk_receipt_digest_v1(
    const m3_chunk_receipt_v1_t *receipt,
    uint8_t out_digest[M3_CHUNK_RECEIPT_DIGEST_SIZE]) {
  uint8_t encoded[M3_CHUNK_RECEIPT_ENCODED_SIZE];
  size_t encoded_size = 0u;
  m3_chunk_receipt_result_t result;

  if (!out_digest)
    return M3_CHUNK_RECEIPT_INVALID_ARG;
  memset(out_digest, 0, M3_CHUNK_RECEIPT_DIGEST_SIZE);
  result = m3_chunk_receipt_encode_v1(receipt, encoded, &encoded_size);
  if (result != M3_CHUNK_RECEIPT_OK)
    return result;
  return calculate_digest(encoded, encoded_size, out_digest);
}

m3_chunk_receipt_result_t m3_chunk_receipt_check_binding_v1(
    const m3_chunk_receipt_v1_t *receipt,
    const uint8_t store_node_id[M3_CHUNK_RECEIPT_STORE_NODE_ID_SIZE],
    const m3_chunk_cid_v1_t *cid, const turbo_uuid_t *request_id,
    uint64_t now_ms, uint64_t max_age_ms) {
  m3_chunk_receipt_result_t result;

  if (!receipt || !store_node_id || !cid || !request_id)
    return M3_CHUNK_RECEIPT_INVALID_ARG;
  result = m3_chunk_receipt_validate_v1(receipt);
  if (result != M3_CHUNK_RECEIPT_OK)
    return result;
  if (memcmp(receipt->store_node_id, store_node_id,
             sizeof(receipt->store_node_id)) != 0) {
    return M3_CHUNK_RECEIPT_STORE_MISMATCH;
  }
  if (receipt->cid.hash_algorithm != cid->hash_algorithm ||
      receipt->cid.size != cid->size ||
      memcmp(receipt->cid.digest, cid->digest, sizeof(cid->digest)) != 0) {
    return M3_CHUNK_RECEIPT_CID_MISMATCH;
  }
  if (!turbo_uuid_equal(&receipt->request_id, request_id))
    return M3_CHUNK_RECEIPT_REQUEST_MISMATCH;
  if (max_age_ms != 0u &&
      (now_ms < receipt->issued_at_ms ||
       now_ms - receipt->issued_at_ms > max_age_ms)) {
    return M3_CHUNK_RECEIPT_EXPIRED;
  }
  return M3_CHUNK_RECEIPT_OK;
}


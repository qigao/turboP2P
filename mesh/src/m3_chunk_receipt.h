#ifndef M3_CHUNK_RECEIPT_H
#define M3_CHUNK_RECEIPT_H

#include "m3_chunk_capability.h"
#include "mesh_mgmt_crypto.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_CHUNK_RECEIPT_ENCODED_SIZE 176u
#define M3_CHUNK_RECEIPT_DIGEST_SIZE M3_CHUNK_CID_DIGEST_SIZE
#define M3_CHUNK_RECEIPT_STORE_NODE_ID_SIZE M3_CHUNK_CAPABILITY_NODE_ID_SIZE
#define M3_CHUNK_RECEIPT_SIGNATURE_SIZE MESH_MGMT_ED25519_SIGNATURE_SIZE

typedef enum {
  M3_CHUNK_RECEIPT_OK = 0,
  M3_CHUNK_RECEIPT_INVALID_ARG = -1,
  M3_CHUNK_RECEIPT_CORRUPT = -2,
  M3_CHUNK_RECEIPT_CRYPTO_FAILED = -3,
  M3_CHUNK_RECEIPT_AUTH_FAILED = -4,
  M3_CHUNK_RECEIPT_EXPIRED = -5,
  M3_CHUNK_RECEIPT_STORE_MISMATCH = -6,
  M3_CHUNK_RECEIPT_CID_MISMATCH = -7,
  M3_CHUNK_RECEIPT_REQUEST_MISMATCH = -8,
} m3_chunk_receipt_result_t;

/**
 * Verifiable durable-evidence issued by one store node.
 *
 * The receipt attests that the store durably published the immutable chunk
 * `cid` for the PUT request `request_id`. The Ed25519 signature binds
 * store_node_id, cid and request_id; expiry is an issuance policy check, not
 * part of the signed body (the signature must remain verifiable forever).
 */
typedef struct {
  uint8_t store_node_id[M3_CHUNK_RECEIPT_STORE_NODE_ID_SIZE];
  m3_chunk_cid_v1_t cid;
  turbo_uuid_t request_id;
  uint64_t issued_at_ms;
  uint8_t signature[M3_CHUNK_RECEIPT_SIGNATURE_SIZE];
} m3_chunk_receipt_v1_t;

/**
 * Structurally validate a receipt (non-zero ids, valid CID, sane issuance).
 * The signature is not checked here.
 */
m3_chunk_receipt_result_t m3_chunk_receipt_validate_v1(
    const m3_chunk_receipt_v1_t *receipt);

/**
 * Encode the canonical fixed-size receipt (signed body + signature).
 * out_bytes must provide M3_CHUNK_RECEIPT_ENCODED_SIZE bytes.
 */
m3_chunk_receipt_result_t m3_chunk_receipt_encode_v1(
    const m3_chunk_receipt_v1_t *receipt, uint8_t *out_bytes,
    size_t *out_size);

/** Decode and structurally validate a canonical receipt. */
m3_chunk_receipt_result_t m3_chunk_receipt_decode_v1(
    const uint8_t *bytes, size_t size, m3_chunk_receipt_v1_t *out_receipt);

/**
 * Sign the canonical receipt body with the store private key. The receipt
 * must already be structurally valid; the signature field is replaced.
 */
m3_chunk_receipt_result_t m3_chunk_receipt_sign_v1(
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    m3_chunk_receipt_v1_t *receipt);

/** Verify the Ed25519 signature over the canonical body. */
m3_chunk_receipt_result_t m3_chunk_receipt_verify_v1(
    const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const m3_chunk_receipt_v1_t *receipt);

/**
 * SHA-256 fingerprint of the canonical signed receipt. Manifests reference
 * receipts by this digest (m3_object_manifest placement segment).
 */
m3_chunk_receipt_result_t m3_chunk_receipt_digest_v1(
    const m3_chunk_receipt_v1_t *receipt,
    uint8_t out_digest[M3_CHUNK_RECEIPT_DIGEST_SIZE]);

/**
 * Check that a verified receipt binds the intended store, chunk, request and
 * is not older than max_age_ms. Intended for the placement decision and GET
 * replica selection boundaries.
 */
m3_chunk_receipt_result_t m3_chunk_receipt_check_binding_v1(
    const m3_chunk_receipt_v1_t *receipt,
    const uint8_t store_node_id[M3_CHUNK_RECEIPT_STORE_NODE_ID_SIZE],
    const m3_chunk_cid_v1_t *cid, const turbo_uuid_t *request_id,
    uint64_t now_ms, uint64_t max_age_ms);

#ifdef __cplusplus
}
#endif

#endif


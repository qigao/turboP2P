#include <tinytest.h>

#include "m3_chunk_receipt.h"

#include <string.h>

static const uint8_t STORE_PRIVATE_KEY[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t STORE_PUBLIC_KEY[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

static void fill_store_node_id(uint8_t node_id[32], uint8_t seed) {
  for (size_t i = 0u; i < 32u; i++)
    node_id[i] = (uint8_t)(seed + i);
}

static void make_receipt(m3_chunk_receipt_v1_t *receipt) {
  memset(receipt, 0, sizeof(*receipt));
  fill_store_node_id(receipt->store_node_id, 0x10u);
  receipt->cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  receipt->cid.size = 4096u;
  for (size_t i = 0u; i < sizeof(receipt->cid.digest); i++)
    receipt->cid.digest[i] = (uint8_t)(0xa0u + i);
  for (size_t i = 0u; i < sizeof(receipt->request_id.bytes); i++)
    receipt->request_id.bytes[i] = (uint8_t)(0x30u + i);
  receipt->issued_at_ms = 1u * 1000u * 1000u;
}

static void test_receipt_sign_verify_round_trip(void) {
  m3_chunk_receipt_v1_t receipt;
  uint8_t digest_a[M3_CHUNK_RECEIPT_DIGEST_SIZE];
  uint8_t digest_b[M3_CHUNK_RECEIPT_DIGEST_SIZE];

  make_receipt(&receipt);
  check_int_eq(m3_chunk_receipt_sign_v1(STORE_PRIVATE_KEY, &receipt),
               M3_CHUNK_RECEIPT_OK);
  check_int_eq(m3_chunk_receipt_verify_v1(STORE_PUBLIC_KEY, &receipt),
               M3_CHUNK_RECEIPT_OK);
  check_int_eq(m3_chunk_receipt_digest_v1(&receipt, digest_a),
               M3_CHUNK_RECEIPT_OK);
  check_int_eq(m3_chunk_receipt_digest_v1(&receipt, digest_b),
               M3_CHUNK_RECEIPT_OK);
  check_mem_eq(digest_a, digest_b, sizeof(digest_a));
}

static void test_receipt_rejects_tampered_signature_and_body(void) {
  m3_chunk_receipt_v1_t receipt;

  make_receipt(&receipt);
  check_int_eq(m3_chunk_receipt_sign_v1(STORE_PRIVATE_KEY, &receipt),
               M3_CHUNK_RECEIPT_OK);
  receipt.signature[0] ^= 0x01u;
  check_int_eq(m3_chunk_receipt_verify_v1(STORE_PUBLIC_KEY, &receipt),
               M3_CHUNK_RECEIPT_AUTH_FAILED);
  receipt.signature[0] ^= 0x01u;
  receipt.cid.digest[5] ^= 0x02u;
  check_int_eq(m3_chunk_receipt_verify_v1(STORE_PUBLIC_KEY, &receipt),
               M3_CHUNK_RECEIPT_AUTH_FAILED);
  check_int_eq(m3_chunk_receipt_verify_v1(STORE_PUBLIC_KEY, NULL),
               M3_CHUNK_RECEIPT_INVALID_ARG);
}

static void test_receipt_encode_decode_round_trip(void) {
  m3_chunk_receipt_v1_t receipt;
  m3_chunk_receipt_v1_t decoded;
  uint8_t encoded[M3_CHUNK_RECEIPT_ENCODED_SIZE];
  size_t encoded_size = 0u;

  make_receipt(&receipt);
  check_int_eq(m3_chunk_receipt_sign_v1(STORE_PRIVATE_KEY, &receipt),
               M3_CHUNK_RECEIPT_OK);
  check_int_eq(m3_chunk_receipt_encode_v1(&receipt, encoded, &encoded_size),
               M3_CHUNK_RECEIPT_OK);
  check_size_eq(encoded_size, M3_CHUNK_RECEIPT_ENCODED_SIZE);
  check_int_eq(m3_chunk_receipt_decode_v1(encoded, encoded_size, &decoded),
               M3_CHUNK_RECEIPT_OK);
  check_mem_eq(&decoded, &receipt, sizeof(decoded));

  check_int_eq(m3_chunk_receipt_decode_v1(encoded, encoded_size - 1u, &decoded),
               M3_CHUNK_RECEIPT_CORRUPT);
  encoded[1] ^= 0xffu;
  check_int_eq(m3_chunk_receipt_decode_v1(encoded, encoded_size, &decoded),
               M3_CHUNK_RECEIPT_CORRUPT);
}

static void test_receipt_check_binding(void) {
  m3_chunk_receipt_v1_t receipt;
  uint8_t other_store[32];
  m3_chunk_cid_v1_t other_cid;
  turbo_uuid_t other_request;
  uint64_t now_ms;

  make_receipt(&receipt);
  now_ms = receipt.issued_at_ms;
  check_int_eq(m3_chunk_receipt_sign_v1(STORE_PRIVATE_KEY, &receipt),
               M3_CHUNK_RECEIPT_OK);

  check_int_eq(m3_chunk_receipt_check_binding_v1(
                   &receipt, receipt.store_node_id, &receipt.cid,
                   &receipt.request_id, now_ms, 1000u * 1000u),
               M3_CHUNK_RECEIPT_OK);

  fill_store_node_id(other_store, 0x40u);
  check_int_eq(m3_chunk_receipt_check_binding_v1(
                   &receipt, other_store, &receipt.cid, &receipt.request_id,
                   now_ms, 1000u * 1000u),
               M3_CHUNK_RECEIPT_STORE_MISMATCH);

  other_cid = receipt.cid;
  other_cid.digest[3] ^= 0x40u;
  check_int_eq(m3_chunk_receipt_check_binding_v1(
                   &receipt, receipt.store_node_id, &other_cid,
                   &receipt.request_id, now_ms, 1000u * 1000u),
               M3_CHUNK_RECEIPT_CID_MISMATCH);

  other_request = receipt.request_id;
  other_request.bytes[2] ^= 0x10u;
  check_int_eq(m3_chunk_receipt_check_binding_v1(
                   &receipt, receipt.store_node_id, &receipt.cid,
                   &other_request, now_ms, 1000u * 1000u),
               M3_CHUNK_RECEIPT_REQUEST_MISMATCH);

  check_int_eq(m3_chunk_receipt_check_binding_v1(
                   &receipt, receipt.store_node_id, &receipt.cid,
                   &receipt.request_id, now_ms + 2000u * 1000u, 1000u * 1000u),
               M3_CHUNK_RECEIPT_EXPIRED);
  check_int_eq(m3_chunk_receipt_check_binding_v1(
                   &receipt, receipt.store_node_id, &receipt.cid,
                   &receipt.request_id, now_ms, 0u),
               M3_CHUNK_RECEIPT_OK);
}

static void test_receipt_invalid_arguments(void) {
  m3_chunk_receipt_v1_t receipt;
  uint8_t node_id[32];
  m3_chunk_cid_v1_t cid;
  uint8_t digest[M3_CHUNK_RECEIPT_DIGEST_SIZE];

  make_receipt(&receipt);
  check_int_eq(m3_chunk_receipt_validate_v1(NULL),
               M3_CHUNK_RECEIPT_INVALID_ARG);
  check_int_eq(m3_chunk_receipt_sign_v1(STORE_PRIVATE_KEY, NULL),
               M3_CHUNK_RECEIPT_INVALID_ARG);
  check_int_eq(m3_chunk_receipt_sign_v1(NULL, &receipt),
               M3_CHUNK_RECEIPT_INVALID_ARG);
  check_int_eq(m3_chunk_receipt_encode_v1(&receipt, NULL, NULL),
               M3_CHUNK_RECEIPT_INVALID_ARG);
  check_int_eq(m3_chunk_receipt_decode_v1(NULL, 0u, &receipt),
               M3_CHUNK_RECEIPT_INVALID_ARG);
  check_int_eq(m3_chunk_receipt_digest_v1(&receipt, NULL),
               M3_CHUNK_RECEIPT_INVALID_ARG);
  check_int_eq(m3_chunk_receipt_check_binding_v1(
                   NULL, node_id, &cid, &receipt.request_id, 1u, 1u),
               M3_CHUNK_RECEIPT_INVALID_ARG);

  memset(receipt.store_node_id, 0, sizeof(receipt.store_node_id));
  check_int_eq(m3_chunk_receipt_validate_v1(&receipt),
               M3_CHUNK_RECEIPT_INVALID_ARG);
  check_int_eq(m3_chunk_receipt_sign_v1(STORE_PRIVATE_KEY, &receipt),
               M3_CHUNK_RECEIPT_INVALID_ARG);
  memset(digest, 0xa5, sizeof(digest));
  check_int_eq(m3_chunk_receipt_digest_v1(&receipt, digest),
               M3_CHUNK_RECEIPT_INVALID_ARG);
  check_mem_eq(digest, (uint8_t[M3_CHUNK_RECEIPT_DIGEST_SIZE]){0},
               sizeof(digest));
}

spec("m3 chunk receipt") {
    describe("durable receipt") {
        it("signs and verifies a receipt with Ed25519") {
            test_receipt_sign_verify_round_trip();
        }
        it("rejects a tampered signature or body") {
            test_receipt_rejects_tampered_signature_and_body();
        }
        it("round-trips the canonical encoding") {
            test_receipt_encode_decode_round_trip();
        }
        it("checks store/cid/request/expiry bindings") {
            test_receipt_check_binding();
        }
        it("rejects invalid arguments before crypto providers") {
            test_receipt_invalid_arguments();
        }
    }
}


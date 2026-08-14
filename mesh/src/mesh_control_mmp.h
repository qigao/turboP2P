#ifndef MESH_CONTROL_MMP_H
#define MESH_CONTROL_MMP_H

#include "mesh_control_primitives.h"
#include "mesh_mgmt_envelope.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_MMP_PAYLOAD_HEADER_SIZE_V1 118u
#define MESH_CONTROL_MMP_BODY_MAX_V1                                      \
  (MESH_MGMT_FRAME_MAX - MESH_MGMT_PREFIX_SIZE - MESH_MGMT_SIGNATURE_SIZE - \
   MESH_MGMT_HEADER_V1_ENCODED_SIZE - MESH_CONTROL_MMP_PAYLOAD_HEADER_SIZE_V1)

typedef enum {
  MESH_CONTROL_MMP_OK = 0,
  MESH_CONTROL_MMP_INVALID_ARG = -1,
  MESH_CONTROL_MMP_INVALID_SCHEMA = -2,
  MESH_CONTROL_MMP_RESOURCE_EXHAUSTED = -3,
  MESH_CONTROL_MMP_DIGEST_MISMATCH = -4,
  MESH_CONTROL_MMP_CRYPTO_FAILED = -5
} mesh_control_mmp_result_t;

/** Compute the digest bound by mesh_control_envelope_v1_t::payload_digest. */
mesh_control_mmp_result_t mesh_control_mmp_body_digest_v1(
    const uint8_t *body, size_t body_size,
    uint8_t out_digest[MESH_CONTROL_DIGEST_SIZE]);

/**
 * Encode the canonical control payload placed inside a signed MMP CONTROL
 * frame. Identity, target, sequence and time fields remain in the MMP header.
 */
mesh_control_mmp_result_t mesh_control_mmp_payload_encode_v1(
    const mesh_control_envelope_v1_t *envelope, const uint8_t *body,
    size_t body_size, uint8_t *output, size_t output_capacity,
    size_t *out_size);

/**
 * Convert a cryptographically verified MMP CONTROL frame into the shared
 * transport-neutral envelope. The returned body view borrows MMP frame bytes.
 * Policy authorization, replay admission and current-time checks remain the
 * responsibility of the domain owner.
 */
mesh_control_mmp_result_t mesh_control_mmp_payload_decode_v1(
    const mesh_mgmt_verified_envelope_v1_t *verified,
    mesh_control_envelope_v1_t *out_envelope, const uint8_t **out_body,
    size_t *out_body_size);

#ifdef __cplusplus
}
#endif

#endif

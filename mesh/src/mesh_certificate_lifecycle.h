#ifndef MESH_CERTIFICATE_LIFECYCLE_H
#define MESH_CERTIFICATE_LIFECYCLE_H

#include "mesh_control_primitives.h"
#include "turbo_fs.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CERTIFICATE_MAX_REVOKED_SERIALS_V1 256u

typedef enum {
  MESH_CERTIFICATE_ROLE_CLIENT_V1 = 1,
  MESH_CERTIFICATE_ROLE_SERVER_V1 = 2
} mesh_certificate_role_v1_t;

typedef struct {
  const char *certificate_file;
  const char *private_key_file;
} mesh_certificate_leaf_config_v1_t;

typedef struct {
  const char *ca_file;
  mesh_certificate_role_v1_t role;
  mesh_certificate_leaf_config_v1_t current;
  /** Both fields NULL means no prestaged next leaf. */
  mesh_certificate_leaf_config_v1_t next;
  const uint64_t *revoked_serials;
  size_t revoked_serial_count;
  uint64_t policy_generation;
  uint64_t now_ms;
  /** Production services set this to reject exposed or linked private keys. */
  uint8_t require_private_key_file_security;
  /** Trust registries set this to load a public leaf without owning its key. */
  uint8_t certificate_only;
} mesh_certificate_lifecycle_config_v1_t;

typedef struct {
  char certificate_file[TURBO_FS_MAX_PATH];
  char private_key_file[TURBO_FS_MAX_PATH];
  uint8_t certificate_sha256[MESH_CONTROL_DIGEST_SIZE];
  uint64_t serial;
  uint64_t not_before_ms;
  uint64_t expires_at_ms;
  uint8_t configured;
  uint8_t valid_now;
} mesh_certificate_leaf_v1_t;

/** Single-owner immutable snapshot; reload commits only a fully valid candidate. */
typedef struct {
  char ca_file[TURBO_FS_MAX_PATH];
  mesh_certificate_leaf_v1_t current;
  mesh_certificate_leaf_v1_t next;
  uint64_t revoked_serials[MESH_CERTIFICATE_MAX_REVOKED_SERIALS_V1];
  size_t revoked_serial_count;
  uint64_t policy_generation;
  mesh_certificate_role_v1_t role;
  uint8_t initialized;
} mesh_certificate_lifecycle_v1_t;

mesh_control_result_t mesh_certificate_lifecycle_init_v1(
    mesh_certificate_lifecycle_v1_t *lifecycle,
    const mesh_certificate_lifecycle_config_v1_t *config);

/** New generation must be greater; failure leaves the old snapshot untouched. */
mesh_control_result_t mesh_certificate_lifecycle_reload_v1(
    mesh_certificate_lifecycle_v1_t *lifecycle,
    const mesh_certificate_lifecycle_config_v1_t *config);

/** Accepts current or next only while valid and not revoked. */
mesh_control_result_t mesh_certificate_lifecycle_authorize_v1(
    const mesh_certificate_lifecycle_v1_t *lifecycle,
    const uint8_t certificate_sha256[MESH_CONTROL_DIGEST_SIZE],
    uint64_t certificate_serial, uint64_t now_ms,
    uint64_t *out_policy_generation);

void mesh_certificate_lifecycle_destroy_v1(
    mesh_certificate_lifecycle_v1_t *lifecycle);

#ifdef __cplusplus
}
#endif

#endif

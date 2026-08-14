#ifndef TURBO_P2P_MESH_MGMT_P2P_SECURITY_H
#define TURBO_P2P_MESH_MGMT_P2P_SECURITY_H

#include "mesh_mgmt_identity.h"

#include <p2p.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { MESH_MGMT_P2P_REVOKED_SERIAL_LIMIT = 256 };

typedef uint64_t (*mesh_mgmt_p2p_security_now_fn)(void *context);

typedef struct {
  uint8_t local_certificate[MESH_MGMT_CERTIFICATE_V1_SIZE];
  size_t local_certificate_len;
  uint8_t trusted_issuer_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t mesh_id_hash[P2P_SECURITY_ID_SIZE];
  uint64_t minimum_principal_epoch;
  uint64_t required_remote_roles;
  uint64_t revoked_serials[MESH_MGMT_P2P_REVOKED_SERIAL_LIMIT];
  size_t revoked_serial_count;
  mesh_mgmt_p2p_security_now_fn now_ms;
  void *now_context;
  uint8_t initialized;
} mesh_mgmt_p2p_security_provider_v2_t;

typedef struct {
  const uint8_t *local_certificate;
  size_t local_certificate_len;
  const uint8_t *trusted_issuer_key;
  const uint8_t *mesh_id_hash;
  uint64_t minimum_principal_epoch;
  uint64_t required_remote_roles;
  const uint64_t *revoked_serials;
  size_t revoked_serial_count;
  mesh_mgmt_p2p_security_now_fn now_ms;
  void *now_context;
} mesh_mgmt_p2p_security_config_v2_t;

typedef struct {
  size_t struct_size;
  uint64_t minimum_remote_principal_epoch;
  uint64_t required_remote_roles;
  const uint64_t *revoked_serials;
  size_t revoked_serial_count;
} mesh_mgmt_p2p_remote_trust_v2_t;

/**
 * Copy an immutable Mesh trust snapshot and produce a P2P v2 provider
 * configuration. Certificate validation runs synchronously when P2P builds
 * the local credential and whenever it verifies a remote credential. The
 * provider must outlive the configured P2P node.
 *
 * config->now_ms is an optional trusted wall-clock source used for both local
 * and remote certificate validation; production may omit it to use system
 * time. required_remote_roles does not constrain the local certificate.
 *
 * @param provider Zero-initialized caller-owned provider storage.
 * @param config Certificate, issuer, Mesh ID, epoch/role/revocation policy and
 *               optional clock; all bytes and serials are copied.
 * @param out_p2p_config Output passed once to
 *                       p2p_node_configure_security_v2().
 * @return P2P_OK, P2P_ERR_INVALID_ARG, or a later callback error when the
 *         resulting P2P configuration validates a credential.
 */
int mesh_mgmt_p2p_security_provider_init_v2(
    mesh_mgmt_p2p_security_provider_v2_t *provider,
    const mesh_mgmt_p2p_security_config_v2_t *config,
    p2p_security_config_v2_t *out_p2p_config);

/**
 * Atomically replace the remote epoch/role/revocation snapshot. Call only on
 * the owning CoroNet thread, then call p2p_node_revalidate_security_v2() before
 * processing more peer traffic. The issuer key and Mesh ID are immutable for
 * the provider lifetime and require a coordinated node restart to rotate.
 */
int mesh_mgmt_p2p_security_provider_update_remote_trust_v2(
    mesh_mgmt_p2p_security_provider_v2_t *provider,
    const mesh_mgmt_p2p_remote_trust_v2_t *trust);

/** Wipe an initialized or zeroed provider after its P2P node is destroyed. */
void mesh_mgmt_p2p_security_provider_destroy_v2(
    mesh_mgmt_p2p_security_provider_v2_t *provider);

#ifdef __cplusplus
}
#endif

#endif

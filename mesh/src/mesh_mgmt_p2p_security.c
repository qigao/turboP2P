#include "mesh_mgmt_p2p_security.h"

#include <turbo_crypto.h>

#include <string.h>
#include <time.h>

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  uint8_t combined = 0u;
  size_t index;

  for (index = 0u; index < length; ++index)
    combined |= bytes[index];
  return combined == 0u;
}

static int revoked_serials_are_valid(const uint64_t *serials,
                                     size_t count) {
  size_t left;
  size_t right;

  for (left = 0u; left < count; ++left) {
    if (serials[left] == 0u)
      return 0;
    for (right = left + 1u; right < count; ++right) {
      if (serials[left] == serials[right])
        return 0;
    }
  }
  return 1;
}

static int serial_is_revoked(
    const mesh_mgmt_p2p_security_provider_v2_t *provider, uint64_t serial) {
  size_t index;

  for (index = 0; index < provider->revoked_serial_count; ++index) {
    if (provider->revoked_serials[index] == serial)
      return 1;
  }
  return 0;
}

static int derive_identity(
    const mesh_mgmt_p2p_security_provider_v2_t *provider,
    const mesh_mgmt_certificate_v1_t *certificate,
    const uint8_t *credential, size_t credential_len,
    p2p_authenticated_identity_v2_t *out_identity) {
  static const uint8_t routing_domain[] = "turbo-p2p-routing-id-v2";
  turbo_crypto_sha256_ctx_t hash;

  memset(out_identity, 0, sizeof(*out_identity));
  memcpy(out_identity->principal_id, certificate->management_key,
         P2P_SECURITY_ID_SIZE);
  if (turbo_crypto_sha256_init(&hash) != TURBO_CRYPTO_OK ||
      turbo_crypto_sha256_update(&hash, routing_domain,
                                 sizeof(routing_domain) - 1u) !=
          TURBO_CRYPTO_OK ||
      turbo_crypto_sha256_update(&hash, provider->mesh_id_hash,
                                 P2P_SECURITY_ID_SIZE) != TURBO_CRYPTO_OK ||
      turbo_crypto_sha256_update(&hash, certificate->managed_node_id,
                                 P2P_SECURITY_ID_SIZE) != TURBO_CRYPTO_OK ||
      turbo_crypto_sha256_final(&hash, out_identity->routing_id) !=
          TURBO_CRYPTO_OK ||
      turbo_crypto_sha256(credential, credential_len,
                          out_identity->credential_digest) != TURBO_CRYPTO_OK) {
    memset(&hash, 0, sizeof(hash));
    memset(out_identity, 0, sizeof(*out_identity));
    return P2P_ERR_CRYPTO;
  }
  memset(&hash, 0, sizeof(hash));
  out_identity->trust_epoch = certificate->principal_epoch;
  out_identity->expires_at_ms = certificate->expires_at_ms;
  out_identity->flags = (uint32_t)certificate->roles;
  return P2P_OK;
}

static int verify_certificate(
    mesh_mgmt_p2p_security_provider_v2_t *provider,
    const uint8_t noise_static[P2P_KEY_SIZE], const uint8_t *credential,
    size_t credential_len, uint64_t now_ms,
    int enforce_remote_roles,
    p2p_authenticated_identity_v2_t *out_identity) {
  mesh_mgmt_certificate_v1_t certificate;
  mesh_mgmt_identity_result_t result;
  int derive_result;

  memset(&certificate, 0, sizeof(certificate));
  result = mesh_mgmt_certificate_verify_v1(
      credential, credential_len, provider->trusted_issuer_key,
      provider->mesh_id_hash, now_ms, &certificate);
  if (result != MESH_MGMT_IDENTITY_OK ||
      certificate.principal_type != MESH_MGMT_PRINCIPAL_NODE ||
      !mesh_mgmt_crypto_equal_32(certificate.transport_peer_id,
                                 noise_static) ||
      certificate.principal_epoch < provider->minimum_principal_epoch ||
      (enforce_remote_roles &&
       (certificate.roles & provider->required_remote_roles) !=
           provider->required_remote_roles) ||
      serial_is_revoked(provider, certificate.serial)) {
    memset(&certificate, 0, sizeof(certificate));
    return P2P_ERR_UNTRUSTED_IDENTITY;
  }
  derive_result = derive_identity(
      provider, &certificate, credential, credential_len, out_identity);
  memset(&certificate, 0, sizeof(certificate));
  return derive_result;
}

static int build_local_credential(
    void *context, const uint8_t local_noise_static[P2P_KEY_SIZE],
    uint8_t *output, size_t output_capacity, size_t *out_len,
    p2p_authenticated_identity_v2_t *out_identity) {
  mesh_mgmt_p2p_security_provider_v2_t *provider =
      (mesh_mgmt_p2p_security_provider_v2_t *)context;
  int result;

  if (!provider || !provider->initialized || !output || !out_len ||
      output_capacity < provider->local_certificate_len) {
    return P2P_ERR_INVALID_ARG;
  }
  result = verify_certificate(
      provider, local_noise_static, provider->local_certificate,
      provider->local_certificate_len,
      provider->now_ms ? provider->now_ms(provider->now_context)
                       : (uint64_t)time(NULL) * 1000u,
      0,
      out_identity);
  if (result != P2P_OK)
    return result;
  memcpy(output, provider->local_certificate,
         provider->local_certificate_len);
  *out_len = provider->local_certificate_len;
  return P2P_OK;
}

static int verify_remote_credential(
    void *context, const uint8_t remote_noise_static[P2P_KEY_SIZE],
    const uint8_t channel_binding[P2P_SECURITY_ID_SIZE],
    const uint8_t *credential, size_t credential_len, uint64_t now_ms,
    p2p_authenticated_identity_v2_t *out_identity) {
  mesh_mgmt_p2p_security_provider_v2_t *provider =
      (mesh_mgmt_p2p_security_provider_v2_t *)context;

  (void)channel_binding;
  if (!provider || !provider->initialized)
    return P2P_ERR_INVALID_STATE;
  if (provider->now_ms)
    now_ms = provider->now_ms(provider->now_context);
  return verify_certificate(provider, remote_noise_static, credential,
                            credential_len, now_ms, 1, out_identity);
}

int mesh_mgmt_p2p_security_provider_init_v2(
    mesh_mgmt_p2p_security_provider_v2_t *provider,
    const mesh_mgmt_p2p_security_config_v2_t *config,
    p2p_security_config_v2_t *out_p2p_config) {
  if (!provider || !config || !out_p2p_config ||
      !config->local_certificate ||
      config->local_certificate_len != MESH_MGMT_CERTIFICATE_V1_SIZE ||
      !config->trusted_issuer_key || !config->mesh_id_hash ||
      (config->revoked_serial_count && !config->revoked_serials) ||
      config->revoked_serial_count > MESH_MGMT_P2P_REVOKED_SERIAL_LIMIT ||
      bytes_are_zero(config->trusted_issuer_key,
                     MESH_MGMT_ED25519_PUBLIC_KEY_SIZE) ||
      bytes_are_zero(config->mesh_id_hash, P2P_SECURITY_ID_SIZE) ||
      (config->required_remote_roles &
       ~((uint64_t)MESH_MGMT_ROLE_KNOWN_MASK)) != 0u ||
      !revoked_serials_are_valid(config->revoked_serials,
                                 config->revoked_serial_count) ||
      provider->initialized) {
    return P2P_ERR_INVALID_ARG;
  }
  memset(provider, 0, sizeof(*provider));
  memcpy(provider->local_certificate, config->local_certificate,
         config->local_certificate_len);
  provider->local_certificate_len = config->local_certificate_len;
  memcpy(provider->trusted_issuer_key, config->trusted_issuer_key,
         MESH_MGMT_ED25519_PUBLIC_KEY_SIZE);
  memcpy(provider->mesh_id_hash, config->mesh_id_hash,
         P2P_SECURITY_ID_SIZE);
  provider->minimum_principal_epoch = config->minimum_principal_epoch;
  provider->required_remote_roles = config->required_remote_roles;
  if (config->revoked_serial_count) {
    memcpy(provider->revoked_serials, config->revoked_serials,
           config->revoked_serial_count * sizeof(uint64_t));
  }
  provider->revoked_serial_count = config->revoked_serial_count;
  provider->now_ms = config->now_ms;
  provider->now_context = config->now_context;
  provider->initialized = 1u;

  memset(out_p2p_config, 0, sizeof(*out_p2p_config));
  out_p2p_config->struct_size = sizeof(*out_p2p_config);
  memcpy(out_p2p_config->network_id_hash, provider->mesh_id_hash,
         P2P_SECURITY_ID_SIZE);
  out_p2p_config->identity_provider.build_local_credential =
      build_local_credential;
  out_p2p_config->identity_provider.verify_remote_credential =
      verify_remote_credential;
  out_p2p_config->identity_provider.context = provider;
  return P2P_OK;
}

int mesh_mgmt_p2p_security_provider_update_remote_trust_v2(
    mesh_mgmt_p2p_security_provider_v2_t *provider,
    const mesh_mgmt_p2p_remote_trust_v2_t *trust) {
  if (!provider || !provider->initialized || !trust ||
      trust->struct_size != sizeof(*trust) ||
      (trust->revoked_serial_count && !trust->revoked_serials) ||
      trust->revoked_serial_count > MESH_MGMT_P2P_REVOKED_SERIAL_LIMIT ||
      (trust->required_remote_roles &
       ~((uint64_t)MESH_MGMT_ROLE_KNOWN_MASK)) != 0u ||
      !revoked_serials_are_valid(trust->revoked_serials,
                                 trust->revoked_serial_count)) {
    return P2P_ERR_INVALID_ARG;
  }

  memset(provider->revoked_serials, 0, sizeof(provider->revoked_serials));
  if (trust->revoked_serial_count) {
    memcpy(provider->revoked_serials, trust->revoked_serials,
           trust->revoked_serial_count * sizeof(uint64_t));
  }
  provider->minimum_principal_epoch =
      trust->minimum_remote_principal_epoch;
  provider->required_remote_roles = trust->required_remote_roles;
  provider->revoked_serial_count = trust->revoked_serial_count;
  return P2P_OK;
}

void mesh_mgmt_p2p_security_provider_destroy_v2(
    mesh_mgmt_p2p_security_provider_v2_t *provider) {
  if (provider)
    memset(provider, 0, sizeof(*provider));
}

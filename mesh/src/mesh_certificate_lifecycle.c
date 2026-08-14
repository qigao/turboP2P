#include "mesh_certificate_lifecycle.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_secure_file.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>

static int path_valid(const char *path) {
  size_t size;
  if (!path) return 0;
  size = strlen(path);
  if (size == 0u || size >= TURBO_FS_MAX_PATH) return 0;
  if (path[0] == '/') return 1;
  return size >= 3u && path[1] == ':' &&
         (path[2] == '/' || path[2] == '\\');
}

static int serial_revoked(const mesh_certificate_lifecycle_config_v1_t *config,
                          uint64_t serial) {
  size_t index;
  for (index = 0u; index < config->revoked_serial_count; ++index)
    if (config->revoked_serials[index] == serial) return 1;
  return 0;
}

static int serial_value(X509 *certificate, uint64_t *out_serial) {
  BIGNUM *number = NULL;
  uint8_t bytes[8];
  size_t index;
  uint64_t value = 0u;
  int ok = 0;
  number = ASN1_INTEGER_to_BN(X509_get_serialNumber(certificate), NULL);
  if (!number || BN_is_negative(number) || BN_is_zero(number) ||
      BN_num_bits(number) > 64 || BN_bn2binpad(number, bytes, sizeof(bytes)) !=
                                    (int)sizeof(bytes))
    goto cleanup;
  for (index = 0u; index < sizeof(bytes); ++index)
    value = (value << 8u) | bytes[index];
  *out_serial = value;
  ok = 1;
cleanup:
  BN_free(number);
  return ok;
}

static int time_value(const ASN1_TIME *value, uint64_t *out_ms) {
  ASN1_TIME *epoch = NULL;
  int days = 0;
  int seconds = 0;
  uint64_t total_seconds;
  int valid = 0;
  if (!value || !out_ms) return 0;
  epoch = ASN1_TIME_set(NULL, 0);
  if (!epoch || ASN1_TIME_diff(&days, &seconds, epoch, value) != 1 ||
      days < 0 || seconds < 0)
    goto cleanup;
  if ((uint64_t)days > (UINT64_MAX / 1000u - (uint64_t)seconds) /
                           UINT64_C(86400))
    goto cleanup;
  total_seconds = (uint64_t)days * UINT64_C(86400) + (uint64_t)seconds;
  if (total_seconds > UINT64_MAX / 1000u) goto cleanup;
  *out_ms = total_seconds * 1000u;
  valid = 1;
cleanup:
  ASN1_TIME_free(epoch);
  return valid;
}

static int eku_valid(X509 *certificate, mesh_certificate_role_v1_t role) {
  EXTENDED_KEY_USAGE *usage = (EXTENDED_KEY_USAGE *)X509_get_ext_d2i(
      certificate, NID_ext_key_usage, NULL, NULL);
  int required_nid = role == MESH_CERTIFICATE_ROLE_CLIENT_V1
                         ? NID_client_auth
                         : NID_server_auth;
  int valid = 0;
  int index;
  if (!usage) return 0;
  for (index = 0; index < sk_ASN1_OBJECT_num(usage); ++index) {
    if (OBJ_obj2nid(sk_ASN1_OBJECT_value(usage, index)) == required_nid) {
      valid = 1;
      break;
    }
  }
  EXTENDED_KEY_USAGE_free(usage);
  return valid;
}

static int chain_valid(X509 *certificate, const char *ca_file) {
  X509_STORE *store = X509_STORE_new();
  X509_STORE_CTX *context = NULL;
  int valid = 0;
  if (!store || X509_STORE_load_locations(store, ca_file, NULL) != 1)
    goto cleanup;
  context = X509_STORE_CTX_new();
  if (!context || X509_STORE_CTX_init(context, store, certificate, NULL) != 1)
    goto cleanup;
  valid = X509_verify_cert(context) == 1;
cleanup:
  X509_STORE_CTX_free(context);
  X509_STORE_free(store);
  return valid;
}

static mesh_control_result_t load_leaf(
    const mesh_certificate_lifecycle_config_v1_t *config,
    const mesh_certificate_leaf_config_v1_t *source,
    mesh_certificate_leaf_v1_t *out_leaf) {
  FILE *certificate_file = NULL;
  FILE *private_key_file = NULL;
  X509 *certificate = NULL;
  EVP_PKEY *private_key = NULL;
  unsigned int digest_size = 0u;
  mesh_control_result_t result = MESH_CONTROL_INVALID_ARG;
  if (!source || !path_valid(source->certificate_file) || !out_leaf ||
      (config->certificate_only
           ? source->private_key_file != NULL
           : !path_valid(source->private_key_file)))
    return MESH_CONTROL_INVALID_ARG;
  if (!config->certificate_only &&
      config->require_private_key_file_security &&
      mesh_secure_file_validate_private_v1(source->private_key_file) !=
          MESH_SECURE_FILE_OK_V1)
    return MESH_CONTROL_UNAUTHORIZED;
  memset(out_leaf, 0, sizeof(*out_leaf));
  certificate_file = fopen(source->certificate_file, "rb");
  if (!config->certificate_only)
    private_key_file = fopen(source->private_key_file, "rb");
  if (!certificate_file ||
      (!config->certificate_only && !private_key_file))
    goto cleanup;
  certificate = PEM_read_X509(certificate_file, NULL, NULL, NULL);
  if (!config->certificate_only)
    private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
  if (!certificate ||
      (!config->certificate_only &&
       (!private_key || X509_check_private_key(certificate, private_key) != 1)) ||
      !chain_valid(certificate, config->ca_file) ||
      !eku_valid(certificate, config->role) ||
      !serial_value(certificate, &out_leaf->serial) ||
      !time_value(X509_get0_notBefore(certificate), &out_leaf->not_before_ms) ||
      !time_value(X509_get0_notAfter(certificate), &out_leaf->expires_at_ms) ||
      out_leaf->expires_at_ms <= out_leaf->not_before_ms ||
      serial_revoked(config, out_leaf->serial) ||
      X509_digest(certificate, EVP_sha256(), out_leaf->certificate_sha256,
                  &digest_size) != 1 ||
      digest_size != MESH_CONTROL_DIGEST_SIZE)
    goto cleanup;
  memcpy(out_leaf->certificate_file, source->certificate_file,
         strlen(source->certificate_file) + 1u);
  if (!config->certificate_only)
    memcpy(out_leaf->private_key_file, source->private_key_file,
           strlen(source->private_key_file) + 1u);
  out_leaf->configured = 1u;
  out_leaf->valid_now = config->now_ms >= out_leaf->not_before_ms &&
                        config->now_ms < out_leaf->expires_at_ms;
  result = MESH_CONTROL_OK;
cleanup:
  EVP_PKEY_free(private_key);
  X509_free(certificate);
  if (private_key_file) fclose(private_key_file);
  if (certificate_file) fclose(certificate_file);
  if (result != MESH_CONTROL_OK) memset(out_leaf, 0, sizeof(*out_leaf));
  return result;
}

static mesh_control_result_t build_snapshot(
    mesh_certificate_lifecycle_v1_t *snapshot,
    const mesh_certificate_lifecycle_config_v1_t *config) {
  size_t index;
  int has_next;
  if (!snapshot || !config || !path_valid(config->ca_file) ||
      (config->role != MESH_CERTIFICATE_ROLE_CLIENT_V1 &&
       config->role != MESH_CERTIFICATE_ROLE_SERVER_V1) ||
      config->policy_generation == 0u || config->now_ms == 0u ||
      config->revoked_serial_count > MESH_CERTIFICATE_MAX_REVOKED_SERIALS_V1 ||
      (config->revoked_serial_count != 0u && !config->revoked_serials))
    return MESH_CONTROL_INVALID_ARG;
  for (index = 0u; index < config->revoked_serial_count; ++index) {
    size_t prior;
    if (config->revoked_serials[index] == 0u) return MESH_CONTROL_INVALID_ARG;
    for (prior = 0u; prior < index; ++prior)
      if (config->revoked_serials[prior] == config->revoked_serials[index])
        return MESH_CONTROL_INVALID_ARG;
  }
  has_next = config->next.certificate_file || config->next.private_key_file;
  if (has_next &&
      (config->certificate_only
           ? (!config->next.certificate_file ||
              config->next.private_key_file != NULL)
           : (!config->next.certificate_file ||
              !config->next.private_key_file)))
    return MESH_CONTROL_INVALID_ARG;
  memset(snapshot, 0, sizeof(*snapshot));
  memcpy(snapshot->ca_file, config->ca_file, strlen(config->ca_file) + 1u);
  snapshot->role = config->role;
  snapshot->policy_generation = config->policy_generation;
  snapshot->revoked_serial_count = config->revoked_serial_count;
  if (config->revoked_serial_count)
    memcpy(snapshot->revoked_serials, config->revoked_serials,
           config->revoked_serial_count * sizeof(uint64_t));
  if (load_leaf(config, &config->current, &snapshot->current) !=
          MESH_CONTROL_OK ||
      !snapshot->current.valid_now)
    return MESH_CONTROL_UNAUTHORIZED;
  if (has_next) {
    if (load_leaf(config, &config->next, &snapshot->next) != MESH_CONTROL_OK ||
        snapshot->next.serial == snapshot->current.serial ||
        mesh_mgmt_crypto_equal_32(snapshot->next.certificate_sha256,
                                  snapshot->current.certificate_sha256))
      return MESH_CONTROL_CONFLICT;
  }
  snapshot->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_certificate_lifecycle_init_v1(
    mesh_certificate_lifecycle_v1_t *lifecycle,
    const mesh_certificate_lifecycle_config_v1_t *config) {
  if (!lifecycle || lifecycle->initialized) return MESH_CONTROL_INVALID_ARG;
  return build_snapshot(lifecycle, config);
}

mesh_control_result_t mesh_certificate_lifecycle_reload_v1(
    mesh_certificate_lifecycle_v1_t *lifecycle,
    const mesh_certificate_lifecycle_config_v1_t *config) {
  mesh_certificate_lifecycle_v1_t candidate;
  mesh_control_result_t result;
  if (!lifecycle || !lifecycle->initialized || !config ||
      config->policy_generation <= lifecycle->policy_generation)
    return MESH_CONTROL_INVALID_ARG;
  memset(&candidate, 0, sizeof(candidate));
  result = build_snapshot(&candidate, config);
  if (result != MESH_CONTROL_OK) return result;
  *lifecycle = candidate;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_certificate_lifecycle_authorize_v1(
    const mesh_certificate_lifecycle_v1_t *lifecycle,
    const uint8_t digest[MESH_CONTROL_DIGEST_SIZE], uint64_t serial,
    uint64_t now_ms, uint64_t *out_policy_generation) {
  const mesh_certificate_leaf_v1_t *leaf = NULL;
  size_t index;
  if (!lifecycle || !lifecycle->initialized || !digest || serial == 0u ||
      now_ms == 0u || !out_policy_generation)
    return MESH_CONTROL_INVALID_ARG;
  *out_policy_generation = 0u;
  for (index = 0u; index < lifecycle->revoked_serial_count; ++index)
    if (lifecycle->revoked_serials[index] == serial)
      return MESH_CONTROL_UNAUTHORIZED;
  if (lifecycle->current.serial == serial &&
      mesh_mgmt_crypto_equal_32(lifecycle->current.certificate_sha256, digest))
    leaf = &lifecycle->current;
  else if (lifecycle->next.configured && lifecycle->next.serial == serial &&
           mesh_mgmt_crypto_equal_32(lifecycle->next.certificate_sha256, digest))
    leaf = &lifecycle->next;
  if (!leaf || now_ms < leaf->not_before_ms || now_ms >= leaf->expires_at_ms)
    return MESH_CONTROL_UNAUTHORIZED;
  *out_policy_generation = lifecycle->policy_generation;
  return MESH_CONTROL_OK;
}

void mesh_certificate_lifecycle_destroy_v1(
    mesh_certificate_lifecycle_v1_t *lifecycle) {
  if (lifecycle) memset(lifecycle, 0, sizeof(*lifecycle));
}

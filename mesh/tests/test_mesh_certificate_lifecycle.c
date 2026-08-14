#include "mesh_certificate_lifecycle.h"
#include "tinytest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <aclapi.h>
#include <windows.h>
#else
#include <sys/stat.h>
#endif

static int set_private_permissions(const char *path, int allow_everyone) {
#ifdef _WIN32
  BYTE token_user_buffer[512];
  BYTE everyone_buffer[SECURITY_MAX_SID_SIZE];
  HANDLE token = NULL;
  DWORD token_user_size = 0u;
  DWORD everyone_size = sizeof(everyone_buffer);
  TOKEN_USER *token_user;
  EXPLICIT_ACCESSA entries[2];
  PACL acl = NULL;
  DWORD result;
  ULONG entry_count = allow_everyone ? 2u : 1u;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return -1;
  if (!GetTokenInformation(token, TokenUser, token_user_buffer,
                           sizeof(token_user_buffer), &token_user_size)) {
    CloseHandle(token);
    return -1;
  }
  token_user = (TOKEN_USER *)token_user_buffer;
  memset(entries, 0, sizeof(entries));
  entries[0].grfAccessPermissions = GENERIC_ALL;
  entries[0].grfAccessMode = SET_ACCESS;
  entries[0].grfInheritance = NO_INHERITANCE;
  entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
  entries[0].Trustee.ptstrName = (LPSTR)token_user->User.Sid;
  if (allow_everyone) {
    if (!CreateWellKnownSid(WinWorldSid, NULL, everyone_buffer,
                            &everyone_size)) {
      CloseHandle(token);
      return -1;
    }
    entries[1].grfAccessPermissions = GENERIC_READ;
    entries[1].grfAccessMode = SET_ACCESS;
    entries[1].grfInheritance = NO_INHERITANCE;
    entries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    entries[1].Trustee.ptstrName = (LPSTR)everyone_buffer;
  }
  result = SetEntriesInAclA(entry_count, entries, NULL, &acl);
  if (result == ERROR_SUCCESS)
    result = SetNamedSecurityInfoA(
        (LPSTR)path, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, acl, NULL);
  if (acl) LocalFree(acl);
  CloseHandle(token);
  return result == ERROR_SUCCESS ? 0 : -1;
#else
  return chmod(path, allow_everyone ? 0644 : 0600);
#endif
}

static void path(char output[TURBO_FS_MAX_PATH], const char *name) {
  (void)snprintf(output, TURBO_FS_MAX_PATH, "%s/%s",
                 MESH_TEST_CERTIFICATE_DIR, name);
}

static void configure(mesh_certificate_lifecycle_config_v1_t *config,
                      uint64_t generation) {
  static char ca[TURBO_FS_MAX_PATH];
  static char current_cert[TURBO_FS_MAX_PATH];
  static char current_key[TURBO_FS_MAX_PATH];
  static char next_cert[TURBO_FS_MAX_PATH];
  static char next_key[TURBO_FS_MAX_PATH];
  path(ca, "ca.pem");
  path(current_cert, "client-current-cert.pem");
  path(current_key, "client-current-key.pem");
  path(next_cert, "client-next-cert.pem");
  path(next_key, "client-next-key.pem");
  memset(config, 0, sizeof(*config));
  config->ca_file = ca;
  config->role = MESH_CERTIFICATE_ROLE_CLIENT_V1;
  config->current.certificate_file = current_cert;
  config->current.private_key_file = current_key;
  config->next.certificate_file = next_cert;
  config->next.private_key_file = next_key;
  config->policy_generation = generation;
  config->now_ms = UINT64_C(1786690000000);
}

static void test_loads_current_next_and_authorizes_overlap(void) {
  mesh_certificate_lifecycle_v1_t lifecycle = {0};
  mesh_certificate_lifecycle_config_v1_t config;
  uint64_t generation = 0u;
  configure(&config, 1u);
  check_int_eq(mesh_certificate_lifecycle_init_v1(&lifecycle, &config),
               MESH_CONTROL_OK);
  check_int_eq(lifecycle.current.serial, 2001u);
  check_int_eq(lifecycle.next.serial, 2002u);
  check_int_eq(mesh_certificate_lifecycle_authorize_v1(
                   &lifecycle, lifecycle.current.certificate_sha256,
                   lifecycle.current.serial, config.now_ms, &generation),
               MESH_CONTROL_OK);
  check_uint_eq(generation, 1u);
  check_int_eq(mesh_certificate_lifecycle_authorize_v1(
                   &lifecycle, lifecycle.next.certificate_sha256,
                   lifecycle.next.serial, config.now_ms, &generation),
               MESH_CONTROL_OK);
  mesh_certificate_lifecycle_destroy_v1(&lifecycle);
}

static void test_reload_revokes_old_without_corrupting_failed_candidate(void) {
  mesh_certificate_lifecycle_v1_t lifecycle = {0};
  mesh_certificate_lifecycle_config_v1_t config;
  uint8_t old_digest[MESH_CONTROL_DIGEST_SIZE];
  uint64_t revoked = 2001u;
  uint64_t generation = 0u;
  configure(&config, 1u);
  check_int_eq(mesh_certificate_lifecycle_init_v1(&lifecycle, &config),
               MESH_CONTROL_OK);
  memcpy(old_digest, lifecycle.current.certificate_sha256,
         sizeof(old_digest));
  configure(&config, 2u);
  config.current = config.next;
  memset(&config.next, 0, sizeof(config.next));
  config.revoked_serials = &revoked;
  config.revoked_serial_count = 1u;
  check_int_eq(mesh_certificate_lifecycle_reload_v1(&lifecycle, &config),
               MESH_CONTROL_OK);
  check_uint_eq(lifecycle.policy_generation, 2u);
  check_int_eq(mesh_certificate_lifecycle_authorize_v1(
                   &lifecycle, old_digest, revoked, config.now_ms,
                   &generation),
               MESH_CONTROL_UNAUTHORIZED);
  configure(&config, 3u);
  config.current.private_key_file = config.next.private_key_file;
  check_int_ne(mesh_certificate_lifecycle_reload_v1(&lifecycle, &config),
               MESH_CONTROL_OK);
  check_uint_eq(lifecycle.policy_generation, 2u);
  mesh_certificate_lifecycle_destroy_v1(&lifecycle);
}

static void test_rejects_wrong_eku_for_role(void) {
  mesh_certificate_lifecycle_v1_t lifecycle = {0};
  mesh_certificate_lifecycle_config_v1_t config;
  configure(&config, 1u);
  config.role = MESH_CERTIFICATE_ROLE_SERVER_V1;
  check_int_ne(mesh_certificate_lifecycle_init_v1(&lifecycle, &config),
               MESH_CONTROL_OK);
}

static void test_enforces_private_key_file_security_when_required(void) {
  mesh_certificate_lifecycle_v1_t lifecycle = {0};
  mesh_certificate_lifecycle_config_v1_t config;
  char source_path[TURBO_FS_MAX_PATH];
  char *private_key = NULL;
  char *temp_path = tt_make_temp_file("mesh-certificate-private", ".pem");
  size_t private_key_size = 0u;
  check_not_null(temp_path);
  if (!temp_path) return;
  path(source_path, "client-current-key.pem");
  private_key = tt_read_file(source_path, &private_key_size);
  check_not_null(private_key);
  if (!private_key) goto cleanup;
  check_int_eq(tt_write_file(temp_path, private_key, private_key_size), 0);
  check_int_eq(set_private_permissions(temp_path, 0), 0);
  configure(&config, 1u);
  config.current.private_key_file = temp_path;
  memset(&config.next, 0, sizeof(config.next));
  config.require_private_key_file_security = 1u;
  check_int_eq(mesh_certificate_lifecycle_init_v1(&lifecycle, &config),
               MESH_CONTROL_OK);
  mesh_certificate_lifecycle_destroy_v1(&lifecycle);

  check_int_eq(set_private_permissions(temp_path, 1), 0);
  check_int_eq(mesh_certificate_lifecycle_init_v1(&lifecycle, &config),
               MESH_CONTROL_UNAUTHORIZED);

cleanup:
  free(private_key);
  (void)tt_remove_file(temp_path);
  free(temp_path);
}

spec("production certificate lifecycle") {
  describe("verified current/next snapshots") {
    it("loads and authorizes both rotation leaves") {
      test_loads_current_next_and_authorizes_overlap();
    }
    it("atomically reloads and revokes the old leaf") {
      test_reload_revokes_old_without_corrupting_failed_candidate();
    }
    it("rejects a certificate with the wrong EKU") {
      test_rejects_wrong_eku_for_role();
    }
    it("rejects private keys exposed through filesystem permissions") {
      test_enforces_private_key_file_security_when_required();
    }
  }
}

#include <tinytest.h>

#include "meshd_key_file.h"

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

    if (!path || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return -1;
    }
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
    if (result == ERROR_SUCCESS) {
        result = SetNamedSecurityInfoA(
            (LPSTR)path, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, acl, NULL);
    }
    if (acl) {
        LocalFree(acl);
    }
    CloseHandle(token);
    return result == ERROR_SUCCESS ? 0 : -1;
#else
    return chmod(path, allow_everyone ? 0644 : 0600);
#endif
}

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
    size_t index;

    for (index = 0u; index < size; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int write_private_key_file(const char *path,
                                  const uint8_t key[MESHD_PRIVATE_KEY_SIZE],
                                  int trailing_whitespace) {
    static const char HEX[] = "0123456789abcdef";
    char encoded[MESHD_PRIVATE_KEY_SIZE * 2u + 2u];
    size_t index;
    size_t encoded_size = MESHD_PRIVATE_KEY_SIZE * 2u;

    for (index = 0u; index < MESHD_PRIVATE_KEY_SIZE; ++index) {
        encoded[index * 2u] = HEX[key[index] >> 4u];
        encoded[index * 2u + 1u] = HEX[key[index] & 0x0fu];
    }
    if (trailing_whitespace) {
        encoded[encoded_size++] = '\n';
    }
    return tt_write_file(path, encoded, encoded_size);
}

static void test_reads_exact_permission_protected_key(void) {
    uint8_t expected[MESHD_PRIVATE_KEY_SIZE];
    uint8_t output[MESHD_PRIVATE_KEY_SIZE];
    char *path = tt_make_temp_file("meshd-private-valid", ".hex");

    memset(expected, 0x3cu, sizeof(expected));
    memset(output, 0xa5, sizeof(output));
    check_not_null(path);
    if (!path) {
        return;
    }
    check_int_eq(write_private_key_file(path, expected, 1), 0);
    check_int_eq(set_private_permissions(path, 0), 0);
    check_int_eq(meshd_private_key_file_read(path, output),
                 MESHD_KEY_FILE_OK);
    check_int_eq(memcmp(output, expected, sizeof(output)), 0);
    memset(expected, 0, sizeof(expected));
    memset(output, 0, sizeof(output));
    (void)tt_remove_file(path);
    free(path);
}

static void test_rejects_invalid_or_oversized_encoding_and_clears_output(void) {
    uint8_t output[MESHD_PRIVATE_KEY_SIZE];
    char *path = tt_make_temp_file("meshd-private-invalid", ".hex");
    char *oversized_path =
        tt_make_temp_file("meshd-private-oversized", ".hex");
    char oversized[4097];

    memset(output, 0xa5, sizeof(output));
    check_not_null(path);
    check_not_null(oversized_path);
    if (!path || !oversized_path) {
        goto cleanup;
    }
    check_int_eq(tt_write_file(path, "0011-not-a-key\n", 15u), 0);
    check_int_eq(set_private_permissions(path, 0), 0);
    check_int_eq(meshd_private_key_file_read(path, output),
                 MESHD_KEY_FILE_INVALID_ENCODING);
    check_true(bytes_are_zero(output, sizeof(output)));

    memset(oversized, ' ', sizeof(oversized));
    check_int_eq(tt_write_file(oversized_path, oversized, sizeof(oversized)), 0);
    check_int_eq(set_private_permissions(oversized_path, 0), 0);
    memset(output, 0xa5, sizeof(output));
    check_int_eq(meshd_private_key_file_read(oversized_path, output),
                 MESHD_KEY_FILE_INVALID_ENCODING);
    check_true(bytes_are_zero(output, sizeof(output)));

cleanup:
    memset(output, 0, sizeof(output));
    memset(oversized, 0, sizeof(oversized));
    if (path) {
        (void)tt_remove_file(path);
        free(path);
    }
    if (oversized_path) {
        (void)tt_remove_file(oversized_path);
        free(oversized_path);
    }
}

static void test_rejects_broad_permissions_and_non_file(void) {
    uint8_t expected[MESHD_PRIVATE_KEY_SIZE];
    uint8_t output[MESHD_PRIVATE_KEY_SIZE];
    char *path = tt_make_temp_file("meshd-private-broad", ".hex");
    char *directory = tt_make_temp_dir("meshd-private-directory");

    memset(expected, 0x7du, sizeof(expected));
    memset(output, 0xa5, sizeof(output));
    check_not_null(path);
    check_not_null(directory);
    if (!path || !directory) {
        goto cleanup;
    }
    check_int_eq(write_private_key_file(path, expected, 0), 0);
    check_int_eq(set_private_permissions(path, 1), 0);
    check_int_eq(meshd_private_key_file_read(path, output),
                 MESHD_KEY_FILE_UNSAFE_PERMISSIONS);
    check_true(bytes_are_zero(output, sizeof(output)));

    memset(output, 0xa5, sizeof(output));
    check_int_eq(meshd_private_key_file_read(directory, output),
                 MESHD_KEY_FILE_UNSAFE_FILE_TYPE);
    check_true(bytes_are_zero(output, sizeof(output)));

cleanup:
    memset(expected, 0, sizeof(expected));
    memset(output, 0, sizeof(output));
    if (path) {
        (void)tt_remove_file(path);
        free(path);
    }
    if (directory) {
        (void)tt_remove_tree(directory);
        free(directory);
    }
}

spec("meshd private key file") {
    it("reads an exact key from a permission-protected regular file") {
        test_reads_exact_permission_protected_key();
    }
    it("rejects invalid or oversized encoding and clears caller output") {
        test_rejects_invalid_or_oversized_encoding_and_clears_output();
    }
    it("rejects broad permissions and non-file inputs") {
        test_rejects_broad_permissions_and_non_file();
    }
}

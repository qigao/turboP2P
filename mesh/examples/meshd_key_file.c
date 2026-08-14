#include "meshd_key_file.h"

#include "mesh_mgmt_crypto.h"

#include <stddef.h>
#include <string.h>

#define MESHD_KEY_FILE_READ_CHUNK_SIZE 256u
#define MESHD_KEY_FILE_MAX_SIZE 4096u
#define MESHD_KEY_FILE_HEX_NIBBLES (MESHD_PRIVATE_KEY_SIZE * 2u)

#ifdef _WIN32
#include <aclapi.h>
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

typedef struct {
    uint8_t *output;
    size_t nibble_count;
    size_t input_size;
} meshd_key_hex_decoder_t;

static int meshd_key_file_hex_value(unsigned char value) {
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0');
    }
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
        return (int)(value - (unsigned char)'a') + 10;
    }
    if (value >= (unsigned char)'A' && value <= (unsigned char)'F') {
        return (int)(value - (unsigned char)'A') + 10;
    }
    return -1;
}

static int meshd_key_file_is_space(unsigned char value) {
    return value == (unsigned char)' ' || value == (unsigned char)'\t' ||
           value == (unsigned char)'\r' || value == (unsigned char)'\n';
}

static int meshd_key_file_decode_chunk(meshd_key_hex_decoder_t *decoder,
                                       const uint8_t *data,
                                       size_t data_size) {
    size_t index;

    if (data_size > MESHD_KEY_FILE_MAX_SIZE - decoder->input_size) {
        return 0;
    }
    decoder->input_size += data_size;
    for (index = 0u; index < data_size; ++index) {
        int hex_value;
        size_t byte_index;

        if (meshd_key_file_is_space(data[index])) {
            continue;
        }
        hex_value = meshd_key_file_hex_value(data[index]);
        if (hex_value < 0 || decoder->nibble_count >= MESHD_KEY_FILE_HEX_NIBBLES) {
            return 0;
        }
        byte_index = decoder->nibble_count / 2u;
        if ((decoder->nibble_count & 1u) == 0u) {
            decoder->output[byte_index] = (uint8_t)(hex_value << 4);
        } else {
            decoder->output[byte_index] |= (uint8_t)hex_value;
        }
        decoder->nibble_count++;
    }
    return 1;
}

#ifdef _WIN32
static int meshd_key_file_sid_is_allowed(PSID sid,
                                         PSID current_user,
                                         PSID local_system,
                                         PSID administrators) {
    return sid && IsValidSid(sid) &&
           (EqualSid(sid, current_user) || EqualSid(sid, local_system) ||
            EqualSid(sid, administrators));
}

static meshd_key_file_result_t meshd_key_file_validate_windows_handle(
    HANDLE file) {
    BYTE token_user_buffer[512];
    BYTE local_system_buffer[SECURITY_MAX_SID_SIZE];
    BYTE administrators_buffer[SECURITY_MAX_SID_SIZE];
    FILE_ATTRIBUTE_TAG_INFO attributes;
    HANDLE token = NULL;
    DWORD token_user_size = 0u;
    DWORD sid_size;
    TOKEN_USER *token_user;
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    meshd_key_file_result_t result = MESHD_KEY_FILE_SECURITY_CHECK_FAILED;
    DWORD index;

    memset(&attributes, 0, sizeof(attributes));
    if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes,
                                      sizeof(attributes))) {
        return MESHD_KEY_FILE_SECURITY_CHECK_FAILED;
    }
    if ((attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0u) {
        return MESHD_KEY_FILE_UNSAFE_FILE_TYPE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return MESHD_KEY_FILE_SECURITY_CHECK_FAILED;
    }
    if (!GetTokenInformation(token, TokenUser, token_user_buffer,
                             sizeof(token_user_buffer), &token_user_size)) {
        goto cleanup;
    }
    token_user = (TOKEN_USER *)token_user_buffer;

    sid_size = sizeof(local_system_buffer);
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, local_system_buffer,
                            &sid_size)) {
        goto cleanup;
    }
    sid_size = sizeof(administrators_buffer);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL,
                            administrators_buffer, &sid_size)) {
        goto cleanup;
    }

    if (GetSecurityInfo(file, SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &owner, NULL, &dacl, NULL, &descriptor) != ERROR_SUCCESS) {
        goto cleanup;
    }
    if (!meshd_key_file_sid_is_allowed(owner, token_user->User.Sid,
                                       local_system_buffer,
                                       administrators_buffer)) {
        result = MESHD_KEY_FILE_UNSAFE_OWNER;
        goto cleanup;
    }
    if (!dacl) {
        result = MESHD_KEY_FILE_UNSAFE_PERMISSIONS;
        goto cleanup;
    }

    for (index = 0u; index < dacl->AceCount; ++index) {
        void *ace = NULL;
        ACE_HEADER *header;

        if (!GetAce(dacl, index, &ace) || !ace) {
            goto cleanup;
        }
        header = (ACE_HEADER *)ace;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *allowed = (ACCESS_ALLOWED_ACE *)ace;
            PSID sid = (PSID)&allowed->SidStart;
            if (!meshd_key_file_sid_is_allowed(
                    sid, token_user->User.Sid, local_system_buffer,
                    administrators_buffer)) {
                result = MESHD_KEY_FILE_UNSAFE_PERMISSIONS;
                goto cleanup;
            }
        } else if (header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
                   header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE ||
                   header->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE) {
            result = MESHD_KEY_FILE_UNSAFE_PERMISSIONS;
            goto cleanup;
        }
    }
    result = MESHD_KEY_FILE_OK;

cleanup:
    if (descriptor) {
        LocalFree(descriptor);
    }
    if (token) {
        CloseHandle(token);
    }
    return result;
}

static meshd_key_file_result_t meshd_key_file_read_platform(
    const char *path,
    uint8_t output[MESHD_PRIVATE_KEY_SIZE]) {
    HANDLE file;
    uint8_t buffer[MESHD_KEY_FILE_READ_CHUNK_SIZE];
    meshd_key_hex_decoder_t decoder;
    meshd_key_file_result_t result;
    DWORD bytes_read = 0u;

    file = CreateFileA(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                           FILE_FLAG_BACKUP_SEMANTICS |
                           FILE_FLAG_SEQUENTIAL_SCAN,
                       NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return MESHD_KEY_FILE_OPEN_FAILED;
    }

    result = meshd_key_file_validate_windows_handle(file);
    if (result != MESHD_KEY_FILE_OK) {
        CloseHandle(file);
        return result;
    }

    memset(buffer, 0, sizeof(buffer));
    decoder.output = output;
    decoder.nibble_count = 0u;
    decoder.input_size = 0u;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &bytes_read, NULL)) {
            result = MESHD_KEY_FILE_READ_FAILED;
            break;
        }
        if (bytes_read == 0u) {
            result = decoder.nibble_count == MESHD_KEY_FILE_HEX_NIBBLES
                         ? MESHD_KEY_FILE_OK
                         : MESHD_KEY_FILE_INVALID_ENCODING;
            break;
        }
        if (!meshd_key_file_decode_chunk(&decoder, buffer, bytes_read)) {
            result = MESHD_KEY_FILE_INVALID_ENCODING;
            break;
        }
    }
    mesh_mgmt_crypto_wipe(buffer, sizeof(buffer));
    if (!CloseHandle(file) && result == MESHD_KEY_FILE_OK) {
        result = MESHD_KEY_FILE_CLOSE_FAILED;
    }
    return result;
}
#else
static meshd_key_file_result_t meshd_key_file_validate_posix_stat(
    const struct stat *metadata) {
    if (!S_ISREG(metadata->st_mode)) {
        return MESHD_KEY_FILE_UNSAFE_FILE_TYPE;
    }
    if (metadata->st_uid != geteuid()) {
        return MESHD_KEY_FILE_UNSAFE_OWNER;
    }
    if ((metadata->st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return MESHD_KEY_FILE_UNSAFE_PERMISSIONS;
    }
    return MESHD_KEY_FILE_OK;
}

static meshd_key_file_result_t meshd_key_file_read_platform(
    const char *path,
    uint8_t output[MESHD_PRIVATE_KEY_SIZE]) {
    struct stat before;
    struct stat opened;
    uint8_t buffer[MESHD_KEY_FILE_READ_CHUNK_SIZE];
    meshd_key_hex_decoder_t decoder;
    meshd_key_file_result_t result;
    int flags = O_RDONLY;
    int file = -1;
    ssize_t bytes_read;

    if (lstat(path, &before) != 0) {
        return MESHD_KEY_FILE_OPEN_FAILED;
    }
    if (S_ISLNK(before.st_mode)) {
        return MESHD_KEY_FILE_UNSAFE_FILE_TYPE;
    }
    result = meshd_key_file_validate_posix_stat(&before);
    if (result != MESHD_KEY_FILE_OK) {
        return result;
    }
#ifndef O_NOFOLLOW
    return MESHD_KEY_FILE_SECURITY_CHECK_FAILED;
#else
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    file = open(path, flags);
    if (file < 0) {
        return MESHD_KEY_FILE_OPEN_FAILED;
    }
#ifndef O_CLOEXEC
    if (fcntl(file, F_SETFD, FD_CLOEXEC) != 0) {
        result = MESHD_KEY_FILE_SECURITY_CHECK_FAILED;
        goto cleanup;
    }
#endif
    if (fstat(file, &opened) != 0) {
        result = MESHD_KEY_FILE_SECURITY_CHECK_FAILED;
        goto cleanup;
    }
    result = meshd_key_file_validate_posix_stat(&opened);
    if (result != MESHD_KEY_FILE_OK) {
        goto cleanup;
    }
    if (before.st_dev != opened.st_dev || before.st_ino != opened.st_ino) {
        result = MESHD_KEY_FILE_SECURITY_CHECK_FAILED;
        goto cleanup;
    }

    memset(buffer, 0, sizeof(buffer));
    decoder.output = output;
    decoder.nibble_count = 0u;
    decoder.input_size = 0u;
    for (;;) {
        bytes_read = read(file, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = MESHD_KEY_FILE_READ_FAILED;
            break;
        }
        if (bytes_read == 0) {
            result = decoder.nibble_count == MESHD_KEY_FILE_HEX_NIBBLES
                         ? MESHD_KEY_FILE_OK
                         : MESHD_KEY_FILE_INVALID_ENCODING;
            break;
        }
        if (!meshd_key_file_decode_chunk(&decoder, buffer,
                                         (size_t)bytes_read)) {
            result = MESHD_KEY_FILE_INVALID_ENCODING;
            break;
        }
    }
    mesh_mgmt_crypto_wipe(buffer, sizeof(buffer));

cleanup:
    if (close(file) != 0 && result == MESHD_KEY_FILE_OK) {
        result = MESHD_KEY_FILE_CLOSE_FAILED;
    }
    return result;
}
#endif

meshd_key_file_result_t meshd_private_key_file_read(
    const char *path,
    uint8_t output[MESHD_PRIVATE_KEY_SIZE]) {
    meshd_key_file_result_t result;

    if (!output) {
        return MESHD_KEY_FILE_INVALID_ARGUMENT;
    }
    mesh_mgmt_crypto_wipe(output, MESHD_PRIVATE_KEY_SIZE);
    if (!path || path[0] == '\0') {
        return MESHD_KEY_FILE_INVALID_ARGUMENT;
    }
    result = meshd_key_file_read_platform(path, output);
    if (result != MESHD_KEY_FILE_OK) {
        mesh_mgmt_crypto_wipe(output, MESHD_PRIVATE_KEY_SIZE);
    }
    return result;
}

const char *meshd_key_file_result_string(meshd_key_file_result_t result) {
    switch (result) {
        case MESHD_KEY_FILE_OK:
            return "ok";
        case MESHD_KEY_FILE_INVALID_ARGUMENT:
            return "invalid argument";
        case MESHD_KEY_FILE_OPEN_FAILED:
            return "open failed";
        case MESHD_KEY_FILE_UNSAFE_FILE_TYPE:
            return "file is not a regular non-link file";
        case MESHD_KEY_FILE_UNSAFE_OWNER:
            return "file owner is not the daemon account";
        case MESHD_KEY_FILE_UNSAFE_PERMISSIONS:
            return "file permissions expose the private key";
        case MESHD_KEY_FILE_SECURITY_CHECK_FAILED:
            return "file security metadata could not be verified";
        case MESHD_KEY_FILE_READ_FAILED:
            return "file read failed";
        case MESHD_KEY_FILE_INVALID_ENCODING:
            return "expected exactly 64 hexadecimal characters";
        case MESHD_KEY_FILE_CLOSE_FAILED:
            return "file close failed";
        default:
            return "unknown key file error";
    }
}

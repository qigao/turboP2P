#ifndef MESHD_KEY_FILE_H
#define MESHD_KEY_FILE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESHD_PRIVATE_KEY_SIZE 32u

typedef enum {
    MESHD_KEY_FILE_OK = 0,
    MESHD_KEY_FILE_INVALID_ARGUMENT = -1,
    MESHD_KEY_FILE_OPEN_FAILED = -2,
    MESHD_KEY_FILE_UNSAFE_FILE_TYPE = -3,
    MESHD_KEY_FILE_UNSAFE_OWNER = -4,
    MESHD_KEY_FILE_UNSAFE_PERMISSIONS = -5,
    MESHD_KEY_FILE_SECURITY_CHECK_FAILED = -6,
    MESHD_KEY_FILE_READ_FAILED = -7,
    MESHD_KEY_FILE_INVALID_ENCODING = -8,
    MESHD_KEY_FILE_CLOSE_FAILED = -9
} meshd_key_file_result_t;

/**
 * Read one 32-byte private key from a whitespace-delimited hexadecimal file.
 *
 * The file must be a regular, non-link file owned and readable only by the
 * daemon account (plus platform service administrators on Windows). The
 * caller owns output and must erase it after handing the key to mesh_create().
 * On every failure output is erased.
 */
meshd_key_file_result_t meshd_private_key_file_read(
    const char *path,
    uint8_t output[MESHD_PRIVATE_KEY_SIZE]);

const char *meshd_key_file_result_string(meshd_key_file_result_t result);

#ifdef __cplusplus
}
#endif

#endif

#ifndef MESH_SECURE_FILE_H
#define MESH_SECURE_FILE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_SECURE_FILE_OK_V1 = 0,
  MESH_SECURE_FILE_INVALID_ARG_V1 = -1,
  MESH_SECURE_FILE_OPEN_FAILED_V1 = -2,
  MESH_SECURE_FILE_UNSAFE_TYPE_V1 = -3,
  MESH_SECURE_FILE_UNSAFE_OWNER_V1 = -4,
  MESH_SECURE_FILE_UNSAFE_PERMISSIONS_V1 = -5,
  MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1 = -6
} mesh_secure_file_result_v1_t;

/** Validate an ACL-protected regular private file through an OS handle. */
mesh_secure_file_result_v1_t mesh_secure_file_validate_private_v1(
    const char *path);

#ifdef __cplusplus
}
#endif

#endif

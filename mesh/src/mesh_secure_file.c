#include "mesh_secure_file.h"

#ifdef _WIN32
#include <aclapi.h>
#include <windows.h>

static int sid_allowed(PSID sid, PSID current_user, PSID local_system,
                       PSID administrators) {
  return sid && IsValidSid(sid) &&
         (EqualSid(sid, current_user) || EqualSid(sid, local_system) ||
          EqualSid(sid, administrators));
}

static mesh_secure_file_result_v1_t validate_handle(HANDLE file) {
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
  mesh_secure_file_result_v1_t result =
      MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1;
  DWORD index;

  if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes,
                                    sizeof(attributes)))
    return MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1;
  if ((attributes.FileAttributes &
       (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0u)
    return MESH_SECURE_FILE_UNSAFE_TYPE_V1;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1;
  if (!GetTokenInformation(token, TokenUser, token_user_buffer,
                           sizeof(token_user_buffer), &token_user_size))
    goto cleanup;
  token_user = (TOKEN_USER *)token_user_buffer;
  sid_size = sizeof(local_system_buffer);
  if (!CreateWellKnownSid(WinLocalSystemSid, NULL, local_system_buffer,
                          &sid_size))
    goto cleanup;
  sid_size = sizeof(administrators_buffer);
  if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL,
                          administrators_buffer, &sid_size))
    goto cleanup;
  if (GetSecurityInfo(file, SE_FILE_OBJECT,
                      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      &owner, NULL, &dacl, NULL, &descriptor) != ERROR_SUCCESS)
    goto cleanup;
  if (!sid_allowed(owner, token_user->User.Sid, local_system_buffer,
                   administrators_buffer)) {
    result = MESH_SECURE_FILE_UNSAFE_OWNER_V1;
    goto cleanup;
  }
  if (!dacl) {
    result = MESH_SECURE_FILE_UNSAFE_PERMISSIONS_V1;
    goto cleanup;
  }
  for (index = 0u; index < dacl->AceCount; ++index) {
    void *ace = NULL;
    ACE_HEADER *header;
    if (!GetAce(dacl, index, &ace) || !ace) goto cleanup;
    header = (ACE_HEADER *)ace;
    if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
      ACCESS_ALLOWED_ACE *allowed = (ACCESS_ALLOWED_ACE *)ace;
      if (!sid_allowed((PSID)&allowed->SidStart, token_user->User.Sid,
                       local_system_buffer, administrators_buffer)) {
        result = MESH_SECURE_FILE_UNSAFE_PERMISSIONS_V1;
        goto cleanup;
      }
    } else if (header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
               header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE ||
               header->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE) {
      result = MESH_SECURE_FILE_UNSAFE_PERMISSIONS_V1;
      goto cleanup;
    }
  }
  result = MESH_SECURE_FILE_OK_V1;

cleanup:
  if (descriptor) LocalFree(descriptor);
  if (token) CloseHandle(token);
  return result;
}

mesh_secure_file_result_v1_t mesh_secure_file_validate_private_v1(
    const char *path) {
  HANDLE file;
  mesh_secure_file_result_v1_t result;
  if (!path || path[0] == '\0') return MESH_SECURE_FILE_INVALID_ARG_V1;
  file = CreateFileA(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                         FILE_FLAG_BACKUP_SEMANTICS,
                     NULL);
  if (file == INVALID_HANDLE_VALUE) return MESH_SECURE_FILE_OPEN_FAILED_V1;
  result = validate_handle(file);
  if (!CloseHandle(file) && result == MESH_SECURE_FILE_OK_V1)
    result = MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1;
  return result;
}

#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static mesh_secure_file_result_v1_t validate_stat(const struct stat *metadata) {
  if (!S_ISREG(metadata->st_mode)) return MESH_SECURE_FILE_UNSAFE_TYPE_V1;
  if (metadata->st_uid != geteuid()) return MESH_SECURE_FILE_UNSAFE_OWNER_V1;
  if ((metadata->st_mode & (S_IRWXG | S_IRWXO)) != 0)
    return MESH_SECURE_FILE_UNSAFE_PERMISSIONS_V1;
  return MESH_SECURE_FILE_OK_V1;
}

mesh_secure_file_result_v1_t mesh_secure_file_validate_private_v1(
    const char *path) {
  struct stat before;
  struct stat opened;
  mesh_secure_file_result_v1_t result;
  int flags = O_RDONLY;
  int file;
  if (!path || path[0] == '\0') return MESH_SECURE_FILE_INVALID_ARG_V1;
  if (lstat(path, &before) != 0) return MESH_SECURE_FILE_OPEN_FAILED_V1;
  if (S_ISLNK(before.st_mode)) return MESH_SECURE_FILE_UNSAFE_TYPE_V1;
  result = validate_stat(&before);
  if (result != MESH_SECURE_FILE_OK_V1) return result;
#ifndef O_NOFOLLOW
  return MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1;
#else
  flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
  file = open(path, flags);
  if (file < 0) return MESH_SECURE_FILE_OPEN_FAILED_V1;
#ifndef O_CLOEXEC
  if (fcntl(file, F_SETFD, FD_CLOEXEC) != 0) {
    (void)close(file);
    return MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1;
  }
#endif
  if (fstat(file, &opened) != 0)
    result = MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1;
  else {
    result = validate_stat(&opened);
    if (result == MESH_SECURE_FILE_OK_V1 &&
        (before.st_dev != opened.st_dev || before.st_ino != opened.st_ino))
      result = MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1;
  }
  if (close(file) != 0 && result == MESH_SECURE_FILE_OK_V1)
    result = MESH_SECURE_FILE_SECURITY_CHECK_FAILED_V1;
  return result;
}
#endif

#include "meshd_management_epoch.h"

#include <fmt.h>
#include <vstr.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

enum { EPOCH_FILE_LIMIT = 63 };

/* Parse a bounded byte view so embedded NUL cannot hide a corrupt suffix.
 * Preserve legacy decimal, leading '+', and surrounding whitespace syntax. */
static int parse_epoch(vstr bytes, uint64_t *epoch) {
    size_t cursor = 0, begin;
    uint64_t value = 0;
    while (cursor < bytes.len && isspace((unsigned char)bytes.data[cursor])) ++cursor;
    if (cursor < bytes.len && bytes.data[cursor] == '+') ++cursor;
    begin = cursor;
    while (cursor < bytes.len && bytes.data[cursor] >= '0' && bytes.data[cursor] <= '9') {
        const unsigned digit = (unsigned)(bytes.data[cursor++] - '0');
        if (value > (UINT64_MAX - digit) / 10) return -1;
        value = value * 10 + digit;
    }
    if (cursor == begin || value == 0 || value == UINT64_MAX) return -1;
    while (cursor < bytes.len && isspace((unsigned char)bytes.data[cursor])) ++cursor;
    if (cursor != bytes.len) return -1;
    *epoch = value;
    return 0;
}

static int read_epoch(const char *path, uint64_t *epoch) {
    char bytes[EPOCH_FILE_LIMIT + 1];
    size_t length = 0;
    int result = -1;
    cmeta_file_t file = cmeta_fs_open(path, SALTS_FS_O_RDONLY, 0);
    if (file == SALTS_INVALID_FILE) return -1;
    while (length < sizeof(bytes)) {
        const int count = cmeta_fs_read(file, bytes + length, sizeof(bytes) - length);
        if (count < 0) break;
        if (count == 0) {
            result = parse_epoch(vstr_from_buf(bytes, length), epoch);
            break;
        }
        length += (size_t)count;
    }
    /* Always close, including parse/read failures. No unbounded read_file. */
    if (cmeta_fs_close(file) != 0) result = -1;
    return result;
}

static int write_epoch(meshd_management_epoch_state_t *state, uint64_t next) {
    tstr staging = tstr_format("{}.tmp", state->path);
    tstr encoded = tstr_format("{}\n", next);
    cmeta_file_t file = SALTS_INVALID_FILE;
    size_t written = 0;
    int result = -1;
    state->publication = SALTS_FS_REPLACE_NOT_PUBLISHED;
    if (staging == NULL || encoded == NULL ||
        tstr_len(staging) != tstr_len(state->path) + 4 ||
        tstr_len(encoded) < 2 || tstr_len(encoded) > 21) goto done;
    file = cmeta_fs_open(staging, SALTS_FS_O_WRONLY | SALTS_FS_O_CREAT | SALTS_FS_O_TRUNC, 0600);
    if (file == SALTS_INVALID_FILE) goto done;
    while (written < tstr_len(encoded)) {
        const int count = cmeta_fs_write(file, encoded + written, tstr_len(encoded) - written);
        if (count <= 0) goto close_file;
        written += (size_t)count;
    }
    result = 0;
close_file:
    if (cmeta_fs_close(file) != 0) result = -1;
    if (result == 0) {
        /* SDK flushes the staging file and durably publishes its namespace.
         * UNKNOWN means it was renamed but durability could not be confirmed. */
        result = cmeta_fs_replace_durable(staging, state->path, &state->publication);
        if (result == 0 && state->publication != SALTS_FS_REPLACE_PUBLISHED_DURABLE) result = -1;
    }
    if (state->publication == SALTS_FS_REPLACE_NOT_PUBLISHED)
        (void)cmeta_fs_unlink(staging);
done:
    tstr_free(encoded);
    tstr_free(staging);
    return result == 0 ? 0 : -1;
}

int meshd_management_epoch_close(meshd_management_epoch_state_t *state) {
    if (state == NULL) return -1;
    if (state->affinity.owner != NULL && cmeta_thread_affine_check(&state->affinity, state) != SALTS_OK)
        return -1;
    if (state->lock_held) {
        if (cmeta_fs_unlock(state->lock_file, 0, 1) != 0) return -1;
        state->lock_held = 0;
    }
    if (state->lock_file_open) {
        if (cmeta_fs_close(state->lock_file) != 0) return -1;
        state->lock_file_open = 0;
    }
    tstr_free(state->path);
    memset(state, 0, sizeof(*state));
    state->lock_file = SALTS_INVALID_FILE;
    return 0;
}

int meshd_management_epoch_open(meshd_management_epoch_state_t *state,
                                const char *path, uint64_t first_record_epoch) {
    cmeta_fs_stat_t info;
    tstr lock_path = NULL;
    size_t length;
    int result;
    if (state == NULL || path == NULL || path[0] == '\0' ||
        first_record_epoch == 0 || first_record_epoch == UINT64_MAX) return -1;
    length = strlen(path);
    if (length >= SALTS_FS_MAX_PATH || state->affinity.owner != NULL || state->initialized ||
        state->lock_file_open || state->path != NULL) return -1;
    if (cmeta_thread_affine_init(&state->affinity, state) != SALTS_OK) return -1;
    state->lock_file = SALTS_INVALID_FILE;
    state->path = tstr_dup_len(path, length);
    if (state->path == NULL) goto failed;
    lock_path = tstr_format("{}.lock", state->path);
    if (lock_path == NULL || tstr_len(lock_path) != length + 5) goto failed;
    state->lock_file = cmeta_fs_open(lock_path, SALTS_FS_O_RDWR | SALTS_FS_O_CREAT, 0600);
    tstr_freep(&lock_path);
    if (state->lock_file == SALTS_INVALID_FILE) goto failed;
    state->lock_file_open = 1;
    if (cmeta_fs_lock(state->lock_file, SALTS_FS_LOCK_EXCLUSIVE | SALTS_FS_LOCK_NONBLOCK, 0, 1) != 0)
        goto failed;
    state->lock_held = 1;
    result = cmeta_fs_access(state->path, SALTS_FS_ACCESS_EXISTS);
    if (result == -ENOENT) {
        if (write_epoch(state, first_record_epoch) != 0) goto failed;
        state->next_epoch = first_record_epoch;
    } else {
        if (result != 0 || cmeta_fs_stat(state->path, &info) != 0 ||
            !info.is_file || info.size == 0 || info.size > EPOCH_FILE_LIMIT ||
            read_epoch(state->path, &state->next_epoch) != 0) goto failed;
    }
    state->initialized = 1;
    return 0;
failed:
    tstr_free(lock_path);
    (void)meshd_management_epoch_close(state); /* Failed cleanup leaves storage intact. */
    return -1;
}

int meshd_management_epoch_allocate(void *context, uint64_t *out_record_epoch) {
    meshd_management_epoch_state_t *state = context;
    uint64_t epoch;
    if (out_record_epoch == NULL) return -1;
    *out_record_epoch = 0;
    if (state == NULL || !state->initialized ||
        cmeta_thread_affine_check(&state->affinity, state) != SALTS_OK ||
        state->publication == SALTS_FS_REPLACE_DURABILITY_UNKNOWN ||
        state->next_epoch == 0 || state->next_epoch == UINT64_MAX) return -1;
    epoch = state->next_epoch;
    if (cmeta_thread_affine_set_busy(&state->affinity, state, true) != SALTS_OK) return -1;
    const int result = write_epoch(state, epoch + 1);
    (void)cmeta_thread_affine_set_busy(&state->affinity, state, false);
    if (result != 0) return -1;
    state->next_epoch = epoch + 1;
    *out_record_epoch = epoch;
    return 0;
}

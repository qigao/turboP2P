#ifndef MESHD_MANAGEMENT_EPOCH_H
#define MESHD_MANAGEMENT_EPOCH_H

#include <cmeta_fs.h>
#include <salts/thread.h>
#include <tstr.h>

/* Private daemon storage Owner. Zero-initialize; keep address-stable on one
 * thread. path is owned, the lock covers open -> close, and next_epoch is the
 * next unissued value. File format remains decimal next_epoch plus newline.
 * SDK publication state is authoritative when durability is uncertain.
 * The host opens at most one Owner per path in one process: POSIX fcntl locks
 * exclude other processes, not duplicate handles in the same process. */
typedef struct {
    cmeta_thread_affine_state affinity;
    tstr path;
    uint64_t next_epoch;
    cmeta_file_t lock_file;
    int lock_file_open;
    int lock_held;
    int initialized;
    cmeta_fs_replace_state_t publication;
} meshd_management_epoch_state_t;

#ifdef __cplusplus
extern "C" {
#endif
/* Returns 0 or -1. Existing valid files take precedence over the seed. Only
 * ENOENT permits initialization; corrupt/inaccessible state is never reset.
 * Paths retain the existing < SALTS_FS_MAX_PATH limit; input is copied.
 * Failure rolls back the lock/path, unless checked close itself fails. */
int meshd_management_epoch_open(meshd_management_epoch_state_t *state,
                                const char *path, uint64_t first_record_epoch);

/* Publisher callback. Persist next+1 durably BEFORE returning next. Output is
 * zero on every failure. NOT_PUBLISHED may retry; DURABILITY_UNKNOWN rejects
 * further allocation until checked close/reopen reconciles the file. */
int meshd_management_epoch_allocate(void *context, uint64_t *out_record_epoch);

/* Returns 0 or -1. Idempotent after success. Rejects copies/foreign threads.
 * Cleanup failure retains the Owner for diagnosis; callers must not erase its
 * lock/path storage or blindly retry an ambiguous native close failure. */
int meshd_management_epoch_close(meshd_management_epoch_state_t *state);
#ifdef __cplusplus
}
#endif
#endif

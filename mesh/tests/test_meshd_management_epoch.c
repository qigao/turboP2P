#include "meshd_management_epoch.h"
#include <tinytest.h>
#include <fmt.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

static meshd_management_epoch_state_t state, second;
static char *path, *contents;
static tstr staging, lock_path, extra_lock, source_path;
static int staging_directory;
static cmeta_thread_t thread;
static struct { int close, allocate; uint64_t epoch; } foreign;
#ifdef MESH_MGMT_EPOCH_TEST_WRAP
static int uncertain;
static unsigned replacements;
int __real_cmeta_fs_replace_durable(const char *, const char *, cmeta_fs_replace_state_t *);
int __wrap_cmeta_fs_replace_durable(const char *staging_path, const char *destination,
                                   cmeta_fs_replace_state_t *publication) {
    const int result = __real_cmeta_fs_replace_durable(staging_path, destination, publication);
    ++replacements;
    if (uncertain && result == 0) {
        /* Formal fault injection after real namespace publication. This is
         * not evidence of an actual disk fault or crash/power-loss test. */
        *publication = SALTS_FS_REPLACE_DURABILITY_UNKNOWN;
        return -EIO;
    }
    return result;
}
#endif
static void foreign_use(void *context) {
    (void)context;
    foreign.close = meshd_management_epoch_close(&state);
    foreign.allocate = meshd_management_epoch_allocate(&state, &foreign.epoch);
}
static void expect_file(const char *expected, size_t size) {
    size_t actual_size = 0;
    free(contents);
    contents = tt_read_file(path, &actual_size);
    check_not_null(contents);
    check_equal(actual_size, size);
    check_equal(contents, expected, size);
}

suite("meshd durable management record epochs") {
    before_each() {
        memset(&state, 0, sizeof(state));
        memset(&second, 0, sizeof(second));
        memset(&foreign, 0, sizeof(foreign));
        thread = NULL;
        contents = NULL;
        staging_directory = 0;
        extra_lock = source_path = NULL;
#ifdef MESH_MGMT_EPOCH_TEST_WRAP
        uncertain = 0;
        replacements = 0;
#endif
        path = tt_make_temp_file("meshd-epochs", ".txt");
        check_not_null(path);
        check_equal(tt_remove_file(path), 0);
        staging = tstr_format("{}.tmp", path);
        lock_path = tstr_format("{}.lock", path);
        check_not_null(staging);
        check_not_null(lock_path);
    }
    after_each() {
        if (thread != NULL) check_equal(cmeta_thread_join(&thread), 0);
        check_equal(meshd_management_epoch_close(&second), 0);
        check_equal(meshd_management_epoch_close(&state), 0);
        if (staging_directory) check_equal(cmeta_fs_rmdir(staging), 0);
        else if (staging != NULL) (void)tt_remove_file(staging);
        if (lock_path != NULL) (void)tt_remove_file(lock_path);
        if (extra_lock != NULL) (void)tt_remove_file(extra_lock);
        if (path != NULL) (void)tt_remove_file(path);
        free(contents);
        free(path);
        tstr_free(staging);
        tstr_free(lock_path);
        tstr_freep(&extra_lock);
        tstr_freep(&source_path);
        contents = path = NULL;
        staging = lock_path = NULL;
    }
    it("commits the next epoch before issuing a value and resumes after restart") {
        uint64_t epoch = 0;
        source_path = tstr_dup(path);
        check_not_null(source_path);
        check_equal(meshd_management_epoch_open(&state, source_path, 100), 0);
        tstr_freep(&source_path); /* Owner must keep an independent path. */
        expect_file("100\n", 4);
        check_equal(meshd_management_epoch_allocate(&state, &epoch), 0);
        check_equal(epoch, UINT64_C(100));
        expect_file("101\n", 4);
        check_equal(state.publication, SALTS_FS_REPLACE_PUBLISHED_DURABLE);
        check_equal(meshd_management_epoch_close(&state), 0);
        check_equal(meshd_management_epoch_open(&state, path, 1), 0);
        check_equal(state.next_epoch, UINT64_C(101));
        check_equal(meshd_management_epoch_allocate(&state, &epoch), 0);
        check_equal(epoch, UINT64_C(101));
        expect_file("102\n", 4);
    }
    it("preserves legacy decimal syntax and uses the stored value instead of a new seed") {
        uint64_t epoch = 0;
        static const char bytes[] = " \t+00042\r\n";
        check_equal(tt_write_file(path, bytes, sizeof(bytes) - 1), 0);
        check_equal(meshd_management_epoch_open(&state, path, 1000), 0);
        check_equal(meshd_management_epoch_allocate(&state, &epoch), 0);
        check_equal(epoch, UINT64_C(42));
        expect_file("43\n", 3);
    }
    it("rejects corrupt, negative, overflowing and NUL-containing files without resetting them") {
        static const struct { const char *bytes; size_t size; } invalid[] = {
            {"", 0}, {"0\n", 2}, {"-2\n", 3}, {"+\n", 2},
            {"not-an-epoch\n", 13}, {"12x\n", 4}, {"12\0garbage", 10},
            {"18446744073709551615\n", 21}, {"18446744073709551616\n", 21}
        };
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
            check_equal(tt_write_file(path, invalid[i].bytes, invalid[i].size), 0);
            check_equal(meshd_management_epoch_open(&state, path, 1), -1);
            check_false(state.initialized);
            check_false(state.lock_file_open);
            check_null(state.path);
            expect_file(invalid[i].bytes, invalid[i].size);
        }
        char oversized[64];
        memset(oversized, '1', sizeof(oversized));
        check_equal(tt_write_file(path, oversized, sizeof(oversized)), 0);
        check_equal(meshd_management_epoch_open(&state, path, 1), -1);
        expect_file(oversized, sizeof(oversized));
    }
    it("rejects live reinit and copied Owners without releasing the original file lock") {
        meshd_management_epoch_state_t copy;
        uint64_t epoch = 99;
        check_equal(meshd_management_epoch_open(&state, path, 10), 0);
        copy = state;
        check_equal(meshd_management_epoch_open(&state, path, 1), -1);
        check_equal(meshd_management_epoch_close(&copy), -1);
        check_equal(meshd_management_epoch_allocate(&copy, &epoch), -1);
        check_equal(epoch, UINT64_C(0));
        check_equal(meshd_management_epoch_allocate(&state, &epoch), 0);
        check_equal(epoch, UINT64_C(10));
    }
    it("rejects foreign-thread mutation and preserves the Owner's next value") {
        uint64_t epoch = 0;
        check_equal(meshd_management_epoch_open(&state, path, 10), 0);
        foreign.epoch = 99;
        check_equal(cmeta_thread_create(&thread, foreign_use, NULL), 0);
        check_equal(cmeta_thread_join(&thread), 0);
        check_equal(foreign.close, -1);
        check_equal(foreign.allocate, -1);
        check_equal(foreign.epoch, UINT64_C(0));
        check_equal(meshd_management_epoch_allocate(&state, &epoch), 0);
        check_equal(epoch, UINT64_C(10));
    }
    it("does not issue or advance an epoch when staging cannot be opened, then retries safely") {
        uint64_t epoch = 99;
        check_equal(meshd_management_epoch_open(&state, path, 20), 0);
        check_equal(cmeta_fs_mkdir(staging, 0700), 0);
        staging_directory = 1;
        check_equal(meshd_management_epoch_allocate(&state, &epoch), -1);
        check_equal(epoch, UINT64_C(0));
        check_equal(state.next_epoch, UINT64_C(20));
        check_equal(state.publication, SALTS_FS_REPLACE_NOT_PUBLISHED);
        expect_file("20\n", 3);
        check_equal(cmeta_fs_rmdir(staging), 0);
        staging_directory = 0;
        check_equal(meshd_management_epoch_allocate(&state, &epoch), 0);
        check_equal(epoch, UINT64_C(20));
        expect_file("21\n", 3);
    }
    it("persists exhaustion without wrapping or resetting the exhausted file on reopen") {
        uint64_t epoch = 0;
        check_equal(meshd_management_epoch_open(&state, path, UINT64_MAX - 1), 0);
        check_equal(meshd_management_epoch_allocate(&state, &epoch), 0);
        check_equal(epoch, UINT64_MAX - 1);
        epoch = 99;
        check_equal(meshd_management_epoch_allocate(&state, &epoch), -1);
        check_equal(epoch, UINT64_C(0));
        check_equal(meshd_management_epoch_close(&state), 0);
        check_equal(meshd_management_epoch_open(&state, path, 1), -1);
        expect_file("18446744073709551615\n", 21);
    }
    it("rejects invalid seeds/outputs and non-file storage while clearing epoch outputs") {
        uint64_t epoch = 99;
        check_equal(meshd_management_epoch_allocate(NULL, &epoch), -1);
        check_equal(epoch, UINT64_C(0));
        check_equal(meshd_management_epoch_allocate(&state, NULL), -1);
        check_equal(meshd_management_epoch_allocate(&state, &epoch), -1);
        check_equal(meshd_management_epoch_open(&state, path, 0), -1);
        check_equal(meshd_management_epoch_open(&state, path, UINT64_MAX), -1);
        check_equal(meshd_management_epoch_open(&state, "", 1), -1);
        check_equal(cmeta_fs_mkdir(staging, 0700), 0);
        staging_directory = 1;
        check_equal(meshd_management_epoch_open(&state, staging, 1), -1);
        check_false(state.initialized);
        /* The rejected directory path creates a distinct lock owned by this fixture. */
        extra_lock = tstr_format("{}.lock", staging);
        check_not_null(extra_lock);
        check_equal(tt_remove_file(extra_lock), 0);
        tstr_freep(&extra_lock);
    }
    it("holds the exclusive OS lock through open and releases it on checked close") {
        check_equal(meshd_management_epoch_open(&state, path, 10), 0);
#ifdef _WIN32
        check_equal(meshd_management_epoch_open(&second, path, 1), -1);
        check_false(second.initialized);
#else
        /* POSIX fcntl locks are per-process, so a second same-process handle
         * cannot prove exclusion. Use a real child process for that boundary. */
        const pid_t child = fork();
        check_greater_equal(child, 0);
        if (child == 0) {
            meshd_management_epoch_state_t child_state = {0};
            _exit(meshd_management_epoch_open(&child_state, path, 1) == -1 ? 0 : 1);
        }
        int status = 0;
        check_equal(waitpid(child, &status, 0), child);
        check_true(WIFEXITED(status));
        check_equal(WEXITSTATUS(status), 0);
#endif
        check_equal(meshd_management_epoch_close(&state), 0);
        check_equal(meshd_management_epoch_open(&second, path, 1), 0);
        check_equal(second.next_epoch, UINT64_C(10));
    }
#ifdef MESH_MGMT_EPOCH_TEST_WRAP
    it("withholds an uncertain reservation and fences allocation until checked reopen") {
        uint64_t epoch = 99;
        check_equal(meshd_management_epoch_open(&state, path, 30), 0);
        replacements = 0;
        uncertain = 1;
        check_equal(meshd_management_epoch_allocate(&state, &epoch), -1);
        check_equal(epoch, UINT64_C(0));
        check_equal(state.publication, SALTS_FS_REPLACE_DURABILITY_UNKNOWN);
        expect_file("31\n", 3);
        check_equal(meshd_management_epoch_allocate(&state, &epoch), -1);
        check_equal(replacements, 1u);
        check_equal(meshd_management_epoch_close(&state), 0);
        uncertain = 0;
        check_equal(meshd_management_epoch_open(&state, path, 1), 0);
        check_equal(meshd_management_epoch_allocate(&state, &epoch), 0);
        check_equal(epoch, UINT64_C(31));
        expect_file("32\n", 3);
    }
#endif
}

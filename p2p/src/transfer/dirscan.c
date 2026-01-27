#include "dirscan.h"
#include <tlog.h>
#include <platform.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stb_sprintf.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>

#endif

static int compute_file_hash(const char *filepath, uint8_t hash[P2P_SHA256_DIGEST_SIZE]) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return P2P_ERR_IO;

    p2p_sha256_ctx_t ctx;
    p2p_sha256_init(&ctx);

    uint8_t buf[8192];
    size_t bytes;
    while ((bytes = fread(buf, 1, sizeof(buf), fp)) > 0) {
        p2p_sha256_update(&ctx, buf, bytes);
    }

    fclose(fp);
    p2p_sha256_final(&ctx, hash);
    return P2P_OK;
}

static p2p_dir_entry_t* create_entry(const char *relative_path, size_t file_size) {
    p2p_dir_entry_t *entry = (p2p_dir_entry_t *)calloc(1, sizeof(p2p_dir_entry_t));
    if (!entry) return NULL;

    strncpy(entry->relative_path, relative_path, sizeof(entry->relative_path) - 1);
    entry->file_size = file_size;
    return entry;
}

#ifdef _WIN32
static int scan_dir_recursive(const char *base_path, const char *rel_prefix,
                               p2p_dir_scan_t *scan) {
    char search_path[P2P_MAX_FILEPATH];
    stbsp_snprintf(search_path, sizeof(search_path), "%s\\*", base_path);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return P2P_ERR_IO;
    }

    do {
        if (fd.cFileName[0] == '.') continue;

        char full_path[P2P_MAX_FILEPATH];
        char rel_path[P2P_MAX_RELATIVE_PATH];

        if (rel_prefix[0]) {
            stbsp_snprintf(full_path, sizeof(full_path), "%s\\%s", base_path, fd.cFileName);
            stbsp_snprintf(rel_path, sizeof(rel_path), "%s/%s", rel_prefix, fd.cFileName);
        } else {
            stbsp_snprintf(full_path, sizeof(full_path), "%s\\%s", base_path, fd.cFileName);
            strncpy(rel_path, fd.cFileName, sizeof(rel_path) - 1);
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recurse into subdirectory */
            scan_dir_recursive(full_path, rel_path, scan);
        } else {
            /* Regular file */
            if (scan->file_count >= P2P_MAX_DIR_FILES) {
                TLOG_WARN("[DirScan] Max files reached, stopping");
                break;
            }

            LARGE_INTEGER size;
            size.LowPart = fd.nFileSizeLow;
            size.HighPart = fd.nFileSizeHigh;

            p2p_dir_entry_t *entry = create_entry(rel_path, (size_t)size.QuadPart);
            if (entry) {
                compute_file_hash(full_path, entry->file_hash);
                entry->next = scan->files;
                scan->files = entry;
                scan->file_count++;
                scan->total_size += entry->file_size;
            }
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return P2P_OK;
}
#else
static int scan_dir_recursive(const char *base_path, const char *rel_prefix,
                               p2p_dir_scan_t *scan) {
    DIR *dir = opendir(base_path);
    if (!dir) return P2P_ERR_IO;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char full_path[P2P_MAX_FILEPATH];
        char rel_path[P2P_MAX_RELATIVE_PATH];

        if (rel_prefix[0]) {
            stbsp_snprintf(full_path, sizeof(full_path), "%s/%s", base_path, ent->d_name);
            stbsp_snprintf(rel_path, sizeof(rel_path), "%s/%s", rel_prefix, ent->d_name);
        } else {
            stbsp_snprintf(full_path, sizeof(full_path), "%s/%s", base_path, ent->d_name);
            strncpy(rel_path, ent->d_name, sizeof(rel_path) - 1);
        }

        struct stat st;
        if (stat(full_path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            scan_dir_recursive(full_path, rel_path, scan);
        } else if (S_ISREG(st.st_mode)) {
            if (scan->file_count >= P2P_MAX_DIR_FILES) {
                TLOG_WARN("[DirScan] Max files reached, stopping");
                break;
            }

            p2p_dir_entry_t *entry = create_entry(rel_path, (size_t)st.st_size);
            if (entry) {
                compute_file_hash(full_path, entry->file_hash);
                entry->next = scan->files;
                scan->files = entry;
                scan->file_count++;
                scan->total_size += entry->file_size;
            }
        }
    }

    closedir(dir);
    return P2P_OK;
}
#endif

int p2p_dir_scan(const char *dirpath, p2p_dir_scan_t *scan) {
    if (!dirpath || !scan) return P2P_ERR_INVALID_ARG;

    memset(scan, 0, sizeof(*scan));
    strncpy(scan->base_path, dirpath, sizeof(scan->base_path) - 1);

    /* Extract directory name */
    const char *name = strrchr(dirpath, '/');
    const char *name_bs = strrchr(dirpath, '\\');
    if (name_bs > name) name = name_bs;
    name = name ? name + 1 : dirpath;
    strncpy(scan->dir_name, name, sizeof(scan->dir_name) - 1);

    TLOG_INFO("[DirScan] Scanning directory: {}", dirpath);

    int rc = scan_dir_recursive(dirpath, "", scan);
    if (rc == P2P_OK) {
        TLOG_INFO("[DirScan] Found {} files, total {} bytes",
                 scan->file_count, scan->total_size);
    }

    return rc;
}

void p2p_dir_scan_free(p2p_dir_scan_t *scan) {
    if (!scan) return;

    p2p_dir_entry_t *entry = scan->files;
    while (entry) {
        p2p_dir_entry_t *next = entry->next;
        free(entry);
        entry = next;
    }
    scan->files = NULL;
    scan->file_count = 0;
    scan->total_size = 0;
}

uint8_t* p2p_dir_scan_serialize(const p2p_dir_scan_t *scan, size_t *out_len) {
    if (!scan || !out_len) return NULL;

    /* Calculate buffer size */
    size_t size = 4 + 8;  /* count + total_size */
    p2p_dir_entry_t *entry = scan->files;
    while (entry) {
        size += 2 + strlen(entry->relative_path) + 8 + P2P_SHA256_DIGEST_SIZE;
        entry = entry->next;
    }

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return NULL;

    uint8_t *p = buf;

    /* Write header */
    uint32_t count = scan->file_count;
    memcpy(p, &count, 4); p += 4;

    uint64_t total = (uint64_t)scan->total_size;
    memcpy(p, &total, 8); p += 8;

    /* Write entries */
    entry = scan->files;
    while (entry) {
        uint16_t path_len = (uint16_t)strlen(entry->relative_path);
        memcpy(p, &path_len, 2); p += 2;
        memcpy(p, entry->relative_path, path_len); p += path_len;

        uint64_t fsize = (uint64_t)entry->file_size;
        memcpy(p, &fsize, 8); p += 8;

        memcpy(p, entry->file_hash, P2P_SHA256_DIGEST_SIZE);
        p += P2P_SHA256_DIGEST_SIZE;

        entry = entry->next;
    }

    *out_len = size;
    return buf;
}

int p2p_dir_scan_deserialize(const uint8_t *data, size_t len, p2p_dir_scan_t *scan) {
    if (!data || !scan || len < 12) return P2P_ERR_INVALID_ARG;

    memset(scan, 0, sizeof(*scan));

    const uint8_t *p = data;
    const uint8_t *end = data + len;

    /* Read header */
    uint32_t count;
    memcpy(&count, p, 4); p += 4;

    uint64_t total;
    memcpy(&total, p, 8); p += 8;

    scan->total_size = (size_t)total;

    /* Read entries */
    p2p_dir_entry_t **tail = &scan->files;
    for (uint32_t i = 0; i < count && p < end; i++) {
        if (p + 2 > end) break;

        uint16_t path_len;
        memcpy(&path_len, p, 2); p += 2;

        if (p + path_len + 8 + P2P_SHA256_DIGEST_SIZE > end) break;
        if (path_len >= P2P_MAX_RELATIVE_PATH) break;

        p2p_dir_entry_t *entry = (p2p_dir_entry_t *)calloc(1, sizeof(p2p_dir_entry_t));
        if (!entry) break;

        memcpy(entry->relative_path, p, path_len);
        entry->relative_path[path_len] = '\0';
        p += path_len;

        uint64_t fsize;
        memcpy(&fsize, p, 8); p += 8;
        entry->file_size = (size_t)fsize;

        memcpy(entry->file_hash, p, P2P_SHA256_DIGEST_SIZE);
        p += P2P_SHA256_DIGEST_SIZE;

        *tail = entry;
        tail = &entry->next;
        scan->file_count++;
    }

    return P2P_OK;
}

p2p_dir_entry_t* p2p_dir_scan_get_entry(p2p_dir_scan_t *scan, uint32_t index) {
    if (!scan) return NULL;

    p2p_dir_entry_t *entry = scan->files;
    for (uint32_t i = 0; entry && i < index; i++) {
        entry = entry->next;
    }
    return entry;
}

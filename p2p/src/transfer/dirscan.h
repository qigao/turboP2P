/**
 * P2P Directory Scanner
 *
 * Recursively scans directories for file transfer.
 */
#ifndef P2P_DIRSCAN_H
#define P2P_DIRSCAN_H

#include <stdint.h>
#include <stddef.h>
#include "sha256.h"
#include "../core/types.h"

#define P2P_MAX_FILEPATH        512
#define P2P_MAX_RELATIVE_PATH   256
#define P2P_MAX_DIR_FILES       10000

/**
 * Directory entry (file info)
 */
typedef struct p2p_dir_entry_s {
    char relative_path[P2P_MAX_RELATIVE_PATH];
    size_t file_size;
    uint8_t file_hash[P2P_SHA256_DIGEST_SIZE];
    struct p2p_dir_entry_s *next;
} p2p_dir_entry_t;

/**
 * Directory scan result
 */
typedef struct {
    char base_path[P2P_MAX_FILEPATH];
    char dir_name[256];
    p2p_dir_entry_t *files;
    uint32_t file_count;
    size_t total_size;
} p2p_dir_scan_t;

/**
 * Scan directory recursively
 */
int p2p_dir_scan(const char *dirpath, p2p_dir_scan_t *scan);

/**
 * Free scan result
 */
void p2p_dir_scan_free(p2p_dir_scan_t *scan);

/**
 * Serialize scan result to buffer
 * Returns allocated buffer, caller must free
 */
uint8_t* p2p_dir_scan_serialize(const p2p_dir_scan_t *scan, size_t *out_len);

/**
 * Deserialize scan result from buffer
 */
int p2p_dir_scan_deserialize(const uint8_t *data, size_t len, p2p_dir_scan_t *scan);

/**
 * Get entry by index
 */
p2p_dir_entry_t* p2p_dir_scan_get_entry(p2p_dir_scan_t *scan, uint32_t index);

#endif /* P2P_DIRSCAN_H */

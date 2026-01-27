/**
 * file.c - P2P File Management implementation
 * Professional version based on Kademlia DHT
 */

#include "file.h"
#include "../internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* =============================================================================
 * File Lifecycle
 * ============================================================================= */

p2p_file_t* p2p_file_create(const char *key, const char *filepath) {
    if (!key || !filepath) return NULL;

    p2p_file_t *file = (p2p_file_t*)calloc(1, sizeof(p2p_file_t));
    if (!file) return NULL;

    strncpy(file->filename, key, sizeof(file->filename) - 1);
    strncpy(file->filepath, filepath, sizeof(file->filepath) - 1);
    
    /* Generate ID from filename */
    kad_id_from_data(key, strlen(key), (kad_id_t*)file->id);

    return file;
}

void p2p_file_free(p2p_file_t *file) {
    free(file);
}

/* =============================================================================
 * File Management
 * ============================================================================= */

p2p_file_t* p2p_file_find(p2p_node_t *node, const char *key) {
    if (!node || !key) return NULL;

    /* Check local files */
    p2p_file_t *file = node->local_files;
    while (file) {
        if (strcmp(file->filename, key) == 0) {
            return file;
        }
        file = file->next;
    }

    return NULL;
}

int p2p_file_download(p2p_node_t *node, p2p_file_t *file, const char *output_path) {
    if (!node || !file || !output_path) return -1;

    /* Professional implementation would use CHUNK_REQUEST messages.
     * Simple file copy for local stub compatibility. */
    FILE *src = fopen(file->filepath, "rb");
    if (!src) return -1;

    FILE *dst = fopen(output_path, "wb");
    if (!dst) {
        fclose(src);
        return -1;
    }

    char buffer[8192];
    size_t bytes;
    int result = 0;

    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes, dst) != bytes) {
            result = -1;
            break;
        }
    }

    fclose(src);
    fclose(dst);

    return result;
}

/* =============================================================================
 * List Management
 * ============================================================================= */

p2p_file_t* p2p_file_find_by_id(p2p_file_t *list, const p2p_id_t id) {
    p2p_file_t *cur = list;
    while (cur) {
        if (memcmp(cur->id, id, P2P_HASH_SIZE) == 0) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}

p2p_file_t* p2p_file_find_by_path(p2p_file_t *list, const char *filepath) {
    p2p_file_t *cur = list;
    while (cur) {
        if (strcmp(cur->filepath, filepath) == 0) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}

int p2p_file_list_add(p2p_file_t **list, p2p_file_t *file) {
    if (!list || !file) return -1;

    file->next = *list;
    *list = file;
    return 0;
}

int p2p_file_list_remove(p2p_file_t **list, const p2p_id_t id) {
    if (!list || !*list) return -1;

    p2p_file_t *prev = NULL;
    p2p_file_t *cur = *list;

    while (cur) {
        if (memcmp(cur->id, id, P2P_HASH_SIZE) == 0) {
            if (prev) {
                prev->next = cur->next;
            } else {
                *list = cur->next;
            }
            p2p_file_free(cur);
            return 0;
        }
        prev = cur;
        cur = cur->next;
    }
    return -1;
}

void p2p_file_list_destroy(p2p_file_t *list) {
    p2p_file_t *cur = list;
    while (cur) {
        p2p_file_t *next = cur->next;
        p2p_file_free(cur);
        cur = next;
    }
}
/* =============================================================================
 * File Network Operations (Centralized)
 * ============================================================================= */

int p2p_file_announce(p2p_node_t *node, p2p_file_t *file) {
    if (!node || !file) return -1;

    /* For now, just add to local DHT list */
    p2p_file_list_add(&node->dht_files, file);

    /* Professional Kademlia: Announce to K closest nodes to file->hash */
    kad_id_t file_id;
    memcpy(file_id.bytes, file->id, KADEMLIA_ID_BYTES);
    
    /* Simulate DHT STORE to neighborhood */
    return p2p_dht_lookup_start(node, file_id.bytes, P2P_MSG_DHT_PUT);
}

int p2p_file_search(p2p_node_t *node, const char *filename,
                    p2p_file_t **results, int max_results) {
    if (!node || !filename || !results) return -1;

    int count = 0;
    p2p_file_t *file = node->dht_files;

    while (file && count < max_results) {
        if (strcmp(file->filename, filename) == 0) {
            results[count++] = file;
        }
        file = file->next;
    }

    return count;
}

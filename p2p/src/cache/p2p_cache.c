#include "p2p_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <tlog.h>
#include <stb_sprintf.h>

#ifdef _WIN32
#include <sys/stat.h>
#include <windows.h>
#include <direct.h>
#else
#include <unistd.h>
#endif

/* Add CXX_C_API prefix to functions */
#ifndef CXX_C_API
#define CXX_C_API
#endif

/* 默认配置 */
#define DEFAULT_CACHE_SIZE_MB 100
#define DEFAULT_MAX_ENTRIES 1000
#define CACHE_INDEX_FILE "cache_index.dat"
#define MAX_KEY_LEN 256
#define MAX_PATH_LEN 512

/* =============================================================================
 * 工具函数
 * ============================================================================= */

static uint64_t get_file_size(const char *filepath) {
#ifdef _WIN32
    struct _stat64 st;
    if (_stat64(filepath, &st) == 0) {
        return st.st_size;
    }
#else
    struct stat st;
    if (stat(filepath, &st) == 0) {
        return st.st_size;
    }
#endif
    return 0;
}

static int create_directory(const char *path) {
#ifdef _WIN32
    /* On Windows, _mkdir() only creates the final directory */
    /* We need to create parent directories first */
    char path_copy[MAX_PATH_LEN];
    strncpy(path_copy, path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    /* Replace forward slashes with backslashes */
    for (char *p = path_copy; *p; p++) {
        if (*p == '/') *p = '\\';
    }

    /* Create parent directories */
    for (char *p = path_copy + 1; *p; p++) {
        if (*p == '\\') {
            *p = '\0';
            if (strlen(path_copy) > 0 && _mkdir(path_copy) != 0 && errno != EEXIST) {
                /* Ignore if directory already exists */
            }
            *p = '\\';
        }
    }

    /* Create the final directory */
    return _mkdir(path_copy);
#else
    return mkdir(path, 0755);
#endif
}

static time_t get_current_time(void) {
    return time(NULL);
}

/* =============================================================================
 * 缓存管理
 * ============================================================================= */

CXX_C_API int p2p_cache_impl_init(p2p_cache_t *cache, const char *cache_dir, uint64_t max_size_mb) {
    if (!cache || !cache_dir) return -1;

    memset(cache, 0, sizeof(p2p_cache_t));

    /* 设置缓存目录 */
    strncpy(cache->cache_dir, cache_dir, sizeof(cache->cache_dir) - 1);

    /* 设置大小限制 */
    cache->max_size = max_size_mb * 1024 * 1024;  /* 转换为bytes */
    if (cache->max_size == 0) {
        cache->max_size = DEFAULT_CACHE_SIZE_MB * 1024 * 1024;
    }

    /* 设置最大条目数 */
    cache->max_entries = DEFAULT_MAX_ENTRIES;
    cache->entry_count = 0;
    cache->current_size = 0;

    /* 分配条目数组 */
    cache->entries = (p2p_cache_entry_t*)calloc(cache->max_entries, sizeof(p2p_cache_entry_t));
    if (!cache->entries) return -1;

    /* 创建缓存目录 */
    create_directory(cache_dir);

    /* 加载现有缓存索引 */
    p2p_cache_impl_load(cache);

    return 0;
}

CXX_C_API void p2p_cache_impl_destroy(p2p_cache_t *cache) {
    if (!cache) return;

    /* 保存缓存索引 */
    p2p_cache_impl_save(cache);

    /* 释放资源 */
    free(cache->entries);
    memset(cache, 0, sizeof(p2p_cache_t));
}

/* =============================================================================
 * LRU缓存操作
 * ============================================================================= */

/* 找到最少使用的条目 */
static int find_lru_entry(p2p_cache_t *cache) {
    int lru_idx = -1;
    time_t oldest_time = get_current_time();
    int min_access = INT_MAX;

    for (int i = 0; i < cache->entry_count; i++) {
        if (cache->entries[i].access_count < min_access) {
            min_access = cache->entries[i].access_count;
            oldest_time = cache->entries[i].last_access;
            lru_idx = i;
        } else if (cache->entries[i].access_count == min_access &&
                   cache->entries[i].last_access < oldest_time) {
            oldest_time = cache->entries[i].last_access;
            lru_idx = i;
        }
    }

    return lru_idx;
}

/* 移除缓存条目 */
static void remove_cache_entry(p2p_cache_t *cache, int index) {
    if (index < 0 || index >= cache->entry_count) return;

    /* 更新当前大小 */
    cache->current_size -= cache->entries[index].size;

    /* 移动后续元素 */
    memmove(&cache->entries[index], &cache->entries[index + 1],
            (cache->entry_count - index - 1) * sizeof(p2p_cache_entry_t));

    cache->entry_count--;
}

/* 确保有空间添加新条目 */
static void make_space(p2p_cache_t *cache, uint64_t needed_size) {
    /* 如果有足够空间，直接返回 */
    if (cache->current_size + needed_size <= cache->max_size &&
        cache->entry_count < cache->max_entries) {
        return;
    }

    /* 移除最少使用的条目直到有足够空�?*/
    while ((cache->current_size + needed_size > cache->max_size ||
            cache->entry_count >= cache->max_entries) &&
           cache->entry_count > 0) {
        int lru_idx = find_lru_entry(cache);
        if (lru_idx >= 0) {
            remove_cache_entry(cache, lru_idx);
        } else {
            break;
        }
    }
}

/* =============================================================================
 * 公共API
 * ============================================================================= */

CXX_C_API int p2p_cache_get(p2p_cache_t *cache, const char *key, char *filepath, size_t max_len) {
    if (!cache || !key || !filepath) return -1;

    /* 查找缓存条目 */
    for (int i = 0; i < cache->entry_count; i++) {
        if (strcmp(cache->entries[i].key, key) == 0) {
            /* 找到，更新访问信�?*/
            cache->entries[i].last_access = get_current_time();
            cache->entries[i].access_count++;

            /* 返回文件路径 */
            strncpy(filepath, cache->entries[i].filepath, max_len - 1);
            filepath[max_len - 1] = '\0';
            return 0;
        }
    }

    return -1;  /* 未找�?*/
}

CXX_C_API int p2p_cache_put(p2p_cache_t *cache, const char *key, const char *filepath,
                  uint64_t size, int is_local) {
    if (!cache || !key || !filepath) return -1;

    TLOG_DEBUG("[CACHE] p2p_cache_put called: key={}, filepath={}", key, filepath);

    /* 检查文件是否存�?*/
    uint64_t file_size = size;
    if (file_size == 0) {
        file_size = get_file_size(filepath);
        if (file_size == 0) {
            TLOG_DEBUG("[CACHE] File not found: {}", filepath);
            return -1;
        }
    }
    TLOG_DEBUG("[CACHE] File size: {} bytes", (unsigned long long)file_size);

    /* 确保有空�?*/
    make_space(cache, file_size);

    /* 如果缓存已满，移除最少使用的条目 */
    if (cache->entry_count >= cache->max_entries) {
        int lru_idx = find_lru_entry(cache);
        if (lru_idx >= 0) {
            remove_cache_entry(cache, lru_idx);
        }
    }

    /* 添加新条�?*/
    if (cache->entry_count < cache->max_entries) {
        p2p_cache_entry_t *entry = &cache->entries[cache->entry_count];

        strncpy(entry->key, key, sizeof(entry->key) - 1);
        strncpy(entry->filepath, filepath, sizeof(entry->filepath) - 1);
        entry->size = file_size;
        entry->last_access = get_current_time();
        entry->access_count = 1;
        entry->is_local = is_local;

        cache->entry_count++;
        cache->current_size += file_size;
        cache->dirty = 1;

        TLOG_DEBUG("[CACHE] Entry added successfully: entry_count={}, current_size={}, dirty={}",
               cache->entry_count, (unsigned long long)cache->current_size, cache->dirty);

        return 0;
    }

    return -1;
}

CXX_C_API int p2p_cache_remove(p2p_cache_t *cache, const char *key) {
    if (!cache || !key) return -1;

    for (int i = 0; i < cache->entry_count; i++) {
        if (strcmp(cache->entries[i].key, key) == 0) {
            remove_cache_entry(cache, i);
            cache->dirty = 1;
            return 0;
        }
    }

    return -1;
}

CXX_C_API int p2p_cache_has(p2p_cache_t *cache, const char *key) {
    if (!cache || !key) return 0;

    for (int i = 0; i < cache->entry_count; i++) {
        if (strcmp(cache->entries[i].key, key) == 0) {
            return 1;
        }
    }

    return 0;
}

CXX_C_API int p2p_cache_cleanup(p2p_cache_t *cache, time_t max_age) {
    if (!cache) return 0;

    time_t now = get_current_time();
    int removed = 0;

    for (int i = cache->entry_count - 1; i >= 0; i--) {
        if (now - cache->entries[i].last_access > max_age) {
            remove_cache_entry(cache, i);
            removed++;
        }
    }

    if (removed > 0) {
        cache->dirty = 1;
    }

    return removed;
}

CXX_C_API void p2p_cache_impl_get_stats(p2p_cache_t *cache, p2p_cache_stats_t *stats) {
    if (!cache || !stats) return;

    memset(stats, 0, sizeof(p2p_cache_stats_t));

    stats->total_size = cache->current_size;
    stats->entry_count = cache->entry_count;

    /* 计算命中率（简化版本） */
    uint64_t total_accesses = 0;
    for (int i = 0; i < cache->entry_count; i++) {
        total_accesses += cache->entries[i].access_count;
    }

    /* For now, we treat all accesses as hits since we don't track misses */
    stats->hit_count = total_accesses;
    stats->miss_count = 0;  /* Not tracked in current implementation */

    if (total_accesses > 0) {
        stats->hit_rate = 100;  /* All accesses are hits in current impl */
    }
}

CXX_C_API void p2p_cache_impl_clear(p2p_cache_t *cache) {
    if (!cache) return;

    /* Save current state before clearing */
    p2p_cache_impl_save(cache);

    cache->entry_count = 0;
    cache->current_size = 0;
    cache->dirty = 1;
}

CXX_C_API int p2p_cache_impl_save(p2p_cache_t *cache) {
    if (!cache) return -1;

    TLOG_DEBUG("[CACHE] Save called, dirty={}, entry_count={}", cache->dirty, cache->entry_count);

    if (!cache->dirty) {
        TLOG_DEBUG("[CACHE] Skipping save (not dirty)");
        return 0;
    }

    char index_path[MAX_PATH_LEN];
    snprintf(index_path, sizeof(index_path), "%s/%s",
             cache->cache_dir, CACHE_INDEX_FILE);

    FILE *f = fopen(index_path, "wb");
    if (!f) return -1;

    /* 写入头部 */
    fprintf(f, "P2P_CACHE_v1\n");
    fprintf(f, "count=%d\n", cache->entry_count);
    fprintf(f, "size=%llu\n", (unsigned long long)cache->current_size);

    /* 写入条目 */
    for (int i = 0; i < cache->entry_count; i++) {
        p2p_cache_entry_t *e = &cache->entries[i];
        fprintf(f, "%s|%s|%llu|%lld|%d|%d\n",
                e->key,
                e->filepath,
                (unsigned long long)e->size,
                (long long)e->last_access,
                e->access_count,
                e->is_local);
    }

    fclose(f);
    cache->dirty = 0;

    return 0;
}

CXX_C_API int p2p_cache_impl_load(p2p_cache_t *cache) {
    if (!cache) return -1;

    TLOG_DEBUG("[CACHE] Loading cache from: {}", cache->cache_dir);

    char index_path[MAX_PATH_LEN];
    snprintf(index_path, sizeof(index_path), "%s/%s",
             cache->cache_dir, CACHE_INDEX_FILE);

    TLOG_DEBUG("[CACHE] Index file path: {}", index_path);

    FILE *f = fopen(index_path, "rb");
    if (!f) {
        TLOG_DEBUG("[CACHE] No existing index file (this is normal on first run)");
        return 0;  /* 没有索引文件，正?*/
    }

    char line[1024];
    int loaded = 0;

    /* 读取头部 */
    if (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "P2P_CACHE_v1", 12) != 0) {
            fclose(f);
            return -1;
        }
    }

    /* 读取条目 */
    while (fgets(line, sizeof(line), f) && loaded < cache->max_entries) {
        p2p_cache_entry_t *e = &cache->entries[loaded];
        long long last_access_ll;

        if (sscanf(line, "%[^|]|%[^|]|%llu|%lld|%d|%d",
                   e->key, e->filepath,
                   (unsigned long long*)&e->size,
                   &last_access_ll,
                   &e->access_count,
                   &e->is_local) == 6) {
            e->last_access = (time_t)last_access_ll;
            TLOG_DEBUG("[CACHE] Loaded entry: key={}, path={}, size={}",
                   e->key, e->filepath, (unsigned long long)e->size);
            loaded++;
            cache->current_size += e->size;
        } else {
            TLOG_DEBUG("[CACHE] Failed to parse line: {}", line);
        }
    }

    fclose(f);
    cache->entry_count = loaded;
    cache->dirty = 0;  /* 从磁盘加载后是干净?*/

    TLOG_DEBUG("[CACHE] Loaded {} entries, current_size={}",
           loaded, (unsigned long long)cache->current_size);

    return 0;
}

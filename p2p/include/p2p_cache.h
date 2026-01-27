#ifndef P2P_CACHE_H
#define P2P_CACHE_H
 

/* Maximum key and path lengths */
#define P2P_CACHE_MAX_KEY 256

#include "p2p_types.h"
#include <time.h>
#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 缓存条目 */
typedef struct {
    char key[256];           /* 缓存键 */
    char filepath[512];      /* 缓存文件路径 */
    uint64_t size;           /* 文件大小 */
    time_t last_access;      /* 最后访问时间 */
    int access_count;        /* 访问次数 */
    int is_local;            /* 是否为本地文件 */
} p2p_cache_entry_t;

/* 缓存管理器 */
typedef struct {
    char cache_dir[512];     /* 缓存目录 */
    uint64_t max_size;       /* 最大缓存大小 (bytes) */
    uint64_t current_size;   /* 当前缓存大小 */
    int max_entries;         /* 最大条目数 */
    int entry_count;         /* 当前条目数 */
    p2p_cache_entry_t *entries;  /* 缓存条目数组 */
    int dirty;               /* 是否需要持久化 */
} p2p_cache_t;

/* 缓存统计信息 */
typedef struct {
    uint64_t hit_count;      /* 缓存命中次数 */
    uint64_t miss_count;     /* 缓存未命中次数 */
    uint64_t hit_rate;       /* 命中率 (0-100) */
    uint64_t total_size;     /* 缓存总大小 */
    int entry_count;         /* 缓存条目数 */
} p2p_cache_stats_t;

/* =============================================================================
 * 缓存管理
 * ============================================================================= */

/**
 * 初始化缓存管理器
 * @param cache 缓存管理器
 * @param cache_dir 缓存目录
 * @param max_size 最大缓存大小 (MB)
 * @return 0 成功, -1 失败
 */
CXX_C_API int p2p_cache_impl_init(p2p_cache_t *cache, const char *cache_dir, uint64_t max_size_mb);

/**
 * 销毁缓存管理器
 * @param cache 缓存管理器
 */
CXX_C_API void p2p_cache_impl_destroy(p2p_cache_t *cache);

/**
 * 获取缓存文件
 * @param cache 缓存管理器
 * @param key 文件键
 * @param filepath 输出：文件路径
 * @param max_len 路径缓冲区长度
 * @return 0 找到, -1 未找到
 */
CXX_C_API int p2p_cache_get(p2p_cache_t *cache, const char *key, char *filepath, size_t max_len);

/**
 * 添加文件到缓存
 * @param cache 缓存管理器
 * @param key 文件键
 * @param filepath 文件路径
 * @param size 文件大小
 * @param is_local 是否为本地文件
 * @return 0 成功, -1 失败
 */
CXX_C_API int p2p_cache_put(p2p_cache_t *cache, const char *key, const char *filepath,
                  uint64_t size, int is_local);

/**
 * 从缓存中移除文件
 * @param cache 缓存管理器
 * @param key 文件键
 * @return 0 成功, -1 未找到
 */
CXX_C_API int p2p_cache_remove(p2p_cache_t *cache, const char *key);

/**
 * 检查缓存是否包含文件
 * @param cache 缓存管理器
 * @param key 文件键
 * @return 1 存在, 0 不存在
 */
CXX_C_API int p2p_cache_has(p2p_cache_t *cache, const char *key);

/**
 * 清理过期缓存条目
 * @param cache 缓存管理器
 * @param max_age 最大年龄 (秒)
 * @return 清理的条目数
 */
CXX_C_API int p2p_cache_cleanup(p2p_cache_t *cache, time_t max_age);

/**
 * 获取缓存统计信息
 * @param cache 缓存管理器
 * @param stats 统计信息输出
 */
CXX_C_API void p2p_cache_impl_get_stats(p2p_cache_t *cache, p2p_cache_stats_t *stats);

/**
 * 清空缓存
 * @param cache 缓存管理器
 */
CXX_C_API void p2p_cache_impl_clear(p2p_cache_t *cache);

/**
 * 保存缓存索引到磁盘
 * @param cache 缓存管理器
 * @return 0 成功, -1 失败
 */
CXX_C_API int p2p_cache_impl_save(p2p_cache_t *cache);

/**
 * 从磁盘加载缓存索引
 * @param cache 缓存管理器
 * @return 0 成功, -1 失败
 */
CXX_C_API int p2p_cache_impl_load(p2p_cache_t *cache);

#ifdef __cplusplus
}
#endif

#endif /* P2P_CACHE_H */

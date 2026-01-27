#ifndef P2P_FILE_H
#define P2P_FILE_H

#include "types.h"

/* File functions */
p2p_file_t* p2p_file_create(const char *key, const char *filepath);
p2p_file_t* p2p_file_find(p2p_node_t *node, const char *key);
int p2p_file_download(p2p_node_t *node, p2p_file_t *file, const char *output_path);
void p2p_file_free(p2p_file_t *file);
p2p_file_t* p2p_file_find_by_id(p2p_file_t *list, const p2p_id_t id);
p2p_file_t* p2p_file_find_by_path(p2p_file_t *list, const char *filepath);
int p2p_file_list_add(p2p_file_t **list, p2p_file_t *file);
int p2p_file_list_remove(p2p_file_t **list, const p2p_id_t id);
int p2p_file_announce(p2p_node_t *node, p2p_file_t *file);
int p2p_file_search(p2p_node_t *node, const char *filename, p2p_file_t **results, int max_results);

#endif /* P2P_FILE_H */

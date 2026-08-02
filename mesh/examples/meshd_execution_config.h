#ifndef MESH_EXAMPLES_MESHD_EXECUTION_CONFIG_H
#define MESH_EXAMPLES_MESHD_EXECUTION_CONFIG_H

#include "mesh_mgmt_execution_node.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESHD_EXECUTION_MAX_DEPLOYMENTS 32u
#define MESHD_EXECUTION_CONFIG_LINE_MAX 1024u

typedef enum {
  MESHD_EXECUTION_MODE_DISABLED = 0,
  MESHD_EXECUTION_MODE_PRESTAGED_WASM = 1
} meshd_execution_mode_t;

typedef struct {
  meshd_execution_mode_t mode;
  char store_file[TURBO_FS_MAX_PATH];
  size_t worker_queue_capacity;
  size_t egress_capacity;
  uint32_t capabilities;
  mesh_mgmt_execution_limits_v1_t limits;
  mesh_mgmt_execution_deployment_v1_t
      deployments[MESHD_EXECUTION_MAX_DEPLOYMENTS];
  char deployment_paths[MESHD_EXECUTION_MAX_DEPLOYMENTS][TURBO_FS_MAX_PATH];
  size_t deployment_count;
  uint32_t seen_fields;
} meshd_execution_config_t;

void meshd_execution_config_init(meshd_execution_config_t *config);

int meshd_execution_config_parse(meshd_execution_config_t *config,
                                 const char *yaml,
                                 size_t yaml_size);

int meshd_execution_config_load(meshd_execution_config_t *config,
                                const char *path);

int meshd_execution_config_validate(
    const meshd_execution_config_t *config);

int meshd_execution_config_build_node(
    const meshd_execution_config_t *config,
    const uint8_t local_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t result_private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t grant_issuer_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    mesh_mgmt_execution_clock_v1_fn clock_now_ms,
    void *clock_context,
    mesh_mgmt_execution_node_config_v1_t *out_config);

#ifdef __cplusplus
}
#endif

#endif

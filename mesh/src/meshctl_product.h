#ifndef MESHCTL_PRODUCT_H
#define MESHCTL_PRODUCT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <turbo_selector.h>
#include "meshctl_controller_http.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  MESHCTL_PRODUCT_SELECTOR_CAPACITY =
      TURBO_SELECTOR_MAX_CANONICAL_BYTES_V1 + 1
};

typedef enum {
  MESHCTL_PRODUCT_PARSE_OK = 0,
  MESHCTL_PRODUCT_PARSE_HELP,
  MESHCTL_PRODUCT_PARSE_VERSION,
  MESHCTL_PRODUCT_PARSE_INVALID,
  MESHCTL_PRODUCT_PARSE_NO_MEMORY
} meshctl_product_parse_status_t;

typedef enum {
  MESHCTL_PRODUCT_COMMAND_NODES_LIST = 1,
  MESHCTL_PRODUCT_COMMAND_NODES_GET,
  MESHCTL_PRODUCT_COMMAND_OPERATIONS_GET,
  MESHCTL_PRODUCT_COMMAND_PLACEMENTS_PLAN,
  MESHCTL_PRODUCT_COMMAND_NETWORKS_LIST,
  MESHCTL_PRODUCT_COMMAND_NETWORKS_GET,
  MESHCTL_PRODUCT_COMMAND_NETWORKS_PLAN,
  MESHCTL_PRODUCT_COMMAND_NETWORKS_APPLY,
  MESHCTL_PRODUCT_COMMAND_NETWORKS_DELETE
} meshctl_product_command_kind_t;

typedef struct {
  meshctl_product_command_kind_t kind;
  meshctl_product_common_options_t common;
  union {
    struct {
      char node_id[MESHCTL_PRODUCT_ID_CAPACITY];
    } nodes_get;
    struct {
      char operation_id[MESHCTL_PRODUCT_ID_CAPACITY];
    } operations_get;
    struct {
      char subject[MESHCTL_PRODUCT_SUBJECT_CAPACITY];
      uint32_t selector_language_version;
      char selector[MESHCTL_PRODUCT_SELECTOR_CAPACITY];
    } placements_plan;
    struct {
      char network[MESHCTL_PRODUCT_ID_CAPACITY];
    } networks_get;
    struct {
      char file[MESHCTL_PRODUCT_PATH_CAPACITY];
    } networks_mutation;
    struct {
      char network[MESHCTL_PRODUCT_ID_CAPACITY];
      uint32_t drain_timeout_ms;
    } networks_delete;
  } args;
} meshctl_product_command_t;

typedef struct {
  meshctl_product_parse_status_t status;
  char error_code[64];
  char message[MESHCTL_PRODUCT_DIAGNOSTIC_CAPACITY];
} meshctl_product_parse_diagnostic_t;

/** Parse argv into an owned, bounded command. No output is written. */
int meshctl_product_parse(int argc, char **argv,
                          meshctl_product_command_t *out_command,
                          meshctl_product_parse_diagnostic_t *out_diagnostic);

/** Return non-zero only for top-level resource names owned by this module. */
int meshctl_product_is_command(const char *name);

typedef struct {
  uint64_t started_ms;
  uint64_t deadline_ms;
} meshctl_deadline_t;

int meshctl_deadline_init_at(meshctl_deadline_t *deadline, uint64_t now_ms,
                             uint32_t timeout_ms);
uint32_t meshctl_deadline_remaining_at(const meshctl_deadline_t *deadline,
                                       uint64_t now_ms);

/** Execute one typed command through an injected Controller client. */
int meshctl_product_execute(const meshctl_product_command_t *command,
                            const meshctl_controller_client_t *client,
                            FILE *out, FILE *err);

/** Parse, execute, render and return the stable product-command exit code. */
int meshctl_product_run(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif

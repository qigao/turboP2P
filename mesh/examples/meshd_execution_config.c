#include "meshd_execution_config.h"

#include <turbo_fs.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum {
  MESHD_EXECUTION_FIELD_MODE = 1u << 0,
  MESHD_EXECUTION_FIELD_STORE = 1u << 1,
  MESHD_EXECUTION_FIELD_WORKER_QUEUE = 1u << 2,
  MESHD_EXECUTION_FIELD_EGRESS = 1u << 3,
  MESHD_EXECUTION_FIELD_CAPABILITIES = 1u << 4,
  MESHD_EXECUTION_FIELD_MODULE_BYTES = 1u << 5,
  MESHD_EXECUTION_FIELD_STACK_BYTES = 1u << 6,
  MESHD_EXECUTION_FIELD_LINEAR_MEMORY_BYTES = 1u << 7,
  MESHD_EXECUTION_FIELD_TIMEOUT_MS = 1u << 8,
  MESHD_EXECUTION_FIELD_CONTROL_FLOW_STEPS = 1u << 9,
  MESHD_EXECUTION_FIELD_HOST_CALLS = 1u << 10,
  MESHD_EXECUTION_FIELD_COPIED_GUEST_BYTES = 1u << 11,
  MESHD_EXECUTION_FIELD_INPUT_BYTES = 1u << 12,
  MESHD_EXECUTION_FIELD_STDOUT_BYTES = 1u << 13,
  MESHD_EXECUTION_FIELD_STDERR_BYTES = 1u << 14,
  MESHD_EXECUTION_FIELD_DEPLOYMENTS = 1u << 15,
  MESHD_EXECUTION_FIELD_WORKER_PROGRAM = 1u << 16,
  MESHD_EXECUTION_FIELD_WORKER_SHA256 = 1u << 17,
  MESHD_EXECUTION_FIELD_SANDBOX_PROGRAM = 1u << 18,
  MESHD_EXECUTION_FIELD_SANDBOX_SHA256 = 1u << 19,
  MESHD_EXECUTION_FIELD_MAX_WORKER_BYTES = 1u << 20,
  MESHD_EXECUTION_FIELD_MAX_OUTPUT_BYTES = 1u << 21,
  MESHD_EXECUTION_FIELD_SANDBOX_ARGS = 1u << 22
};

#define MESHD_EXECUTION_REQUIRED_FIELDS \
  ((1u << 22) - 1u)
#define MESHD_EXECUTION_KNOWN_FIELDS ((1u << 23) - 1u)
#define MESHD_EXECUTION_WORKER_GENERATION 1u

static char *trim(char *text) {
  char *end;

  while (*text && isspace((unsigned char)*text))
    ++text;
  end = text + strlen(text);
  while (end > text && isspace((unsigned char)end[-1]))
    --end;
  *end = '\0';
  return text;
}

static char *strip_quotes(char *text) {
  size_t size = strlen(text);

  if (size >= 2u &&
      ((text[0] == '"' && text[size - 1u] == '"') ||
       (text[0] == '\'' && text[size - 1u] == '\''))) {
    text[size - 1u] = '\0';
    return text + 1;
  }
  return text;
}

static int parse_u64(const char *text, uint64_t *out_value) {
  char *end = NULL;
  unsigned long long value;

  if (!text || !out_value || text[0] == '\0' || text[0] == '-')
    return -1;
  errno = 0;
  value = strtoull(text, &end, 10);
  if (errno != 0 || !end || *end != '\0')
    return -1;
  *out_value = (uint64_t)value;
  return 0;
}

static int parse_size(const char *text, size_t *out_value) {
  uint64_t value = 0u;

  if (parse_u64(text, &value) != 0 || value > SIZE_MAX)
    return -1;
  *out_value = (size_t)value;
  return 0;
}

static int parse_u32(const char *text, uint32_t *out_value) {
  uint64_t value = 0u;

  if (parse_u64(text, &value) != 0 || value > UINT32_MAX)
    return -1;
  *out_value = (uint32_t)value;
  return 0;
}

static int hex_value(char value) {
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'a' && value <= 'f')
    return value - 'a' + 10;
  if (value >= 'A' && value <= 'F')
    return value - 'A' + 10;
  return -1;
}

static int decode_hex_exact(const char *text, uint8_t *output,
                            size_t output_size) {
  size_t index;

  if (!text || !output || output_size == 0u ||
      output_size > SIZE_MAX / 2u || strlen(text) != output_size * 2u)
    return -1;
  for (index = 0u; index < output_size; ++index) {
    int high = hex_value(text[index * 2u]);
    int low = hex_value(text[index * 2u + 1u]);
    if (high < 0 || low < 0)
      return -1;
    output[index] = (uint8_t)((high << 4) | low);
  }
  return 0;
}

static int parse_capabilities(char *text, uint32_t *out_capabilities) {
  uint32_t capabilities = 0u;
  char *cursor = text;

  while (cursor && *cursor) {
    char *comma = strchr(cursor, ',');
    char *name;

    if (comma)
      *comma = '\0';
    name = trim(cursor);
    if (strcmp(name, "core") == 0)
      capabilities |= MESH_MGMT_EXECUTION_CAP_CORE;
    else if (strcmp(name, "utils") == 0)
      capabilities |= MESH_MGMT_EXECUTION_CAP_UTILS;
    else if (strcmp(name, "app") == 0)
      capabilities |= MESH_MGMT_EXECUTION_CAP_APP;
    else
      return -1;
    cursor = comma ? comma + 1 : NULL;
  }
  if (capabilities == 0u)
    return -1;
  *out_capabilities = capabilities;
  return 0;
}

static int parse_sandbox_args(meshd_execution_config_t *config, char *text) {
  char *cursor = strip_quotes(trim(text));
  if (!cursor[0]) return -1;
  while (cursor) {
    char *comma = strchr(cursor, ',');
    char *argument;
    size_t size;
    if (comma) *comma = '\0';
    argument = trim(cursor);
    size = strlen(argument);
    if (size == 0u ||
        size >= MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARG_SIZE_V1 ||
        config->sandbox_arg_count >=
            MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARGS_V1)
      return -1;
    memcpy(config->sandbox_arg_storage[config->sandbox_arg_count], argument,
           size + 1u);
    config->sandbox_args[config->sandbox_arg_count] =
        config->sandbox_arg_storage[config->sandbox_arg_count];
    config->sandbox_arg_count++;
    cursor = comma ? comma + 1 : NULL;
  }
  return 0;
}

static int parse_deployment(meshd_execution_config_t *config, char *text) {
  mesh_mgmt_execution_deployment_v1_t *deployment;
  char *fields[7];
  char *cursor;
  size_t field_count = 1u;
  size_t field_offset = 0u;
  size_t index;

  if (config->deployment_count >= MESHD_EXECUTION_MAX_DEPLOYMENTS)
    return -1;
  cursor = strip_quotes(trim(text));
  for (index = 0u; index < 6u; ++index) {
    char *comma = strchr(cursor, ',');
    if (!comma) break;
    *comma = '\0';
    fields[index] = trim(cursor);
    cursor = comma + 1;
    field_count++;
  }
  if (field_count != 4u && field_count != 5u && field_count != 7u)
    return -1;
  fields[field_count - 1u] = trim(cursor);
  if (strchr(fields[field_count - 1u], ',') ||
      fields[field_count - 1u][0] == '\0' ||
      strlen(fields[field_count - 1u]) >= TURBO_FS_MAX_PATH ||
      !turbo_fs_path_is_absolute(fields[field_count - 1u]))
    return -1;

  deployment = &config->deployments[config->deployment_count];
  memset(deployment, 0, sizeof(*deployment));
  if (field_count == 5u || field_count == 7u) {
    if (strcmp(fields[0], "wasm") == 0)
      deployment->runtime = MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1;
    else if (strcmp(fields[0], "native") == 0)
      deployment->runtime =
          MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1;
    else
      return -1;
    field_offset = 1u;
  }
  if (decode_hex_exact(fields[field_offset], deployment->deployment_id,
                       sizeof(deployment->deployment_id)) != 0 ||
      parse_u64(fields[field_offset + 1u], &deployment->generation) != 0 ||
      deployment->generation == 0u ||
      decode_hex_exact(fields[field_offset + 2u], deployment->module_digest,
                       sizeof(deployment->module_digest)) != 0)
    return -1;
  if (field_count == 7u) {
    if (decode_hex_exact(
            fields[field_offset + 3u],
            config->deployment_config_digests[config->deployment_count],
            MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0 ||
        decode_hex_exact(
            fields[field_offset + 4u],
            config->deployment_network_policy_digests
                [config->deployment_count],
            MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0)
      return -1;
    config->deployment_has_control_binding[config->deployment_count] = 1u;
    field_offset += 2u;
  }
  memcpy(config->deployment_paths[config->deployment_count],
         fields[field_offset + 3u], strlen(fields[field_offset + 3u]) + 1u);
  deployment->module_path =
      config->deployment_paths[config->deployment_count];
  config->deployment_count++;
  return 0;
}

static int set_once(meshd_execution_config_t *config, uint32_t field) {
  if ((config->seen_fields & field) != 0u)
    return -1;
  config->seen_fields |= field;
  return 0;
}

static int parse_scalar(meshd_execution_config_t *config,
                        const char *key,
                        char *value) {
  uint32_t field = 0u;

  value = strip_quotes(trim(value));
  if (strcmp(key, "mgmt_execution_mode") == 0) {
    field = MESHD_EXECUTION_FIELD_MODE;
    if (strcmp(value, "disabled") == 0)
      config->mode = MESHD_EXECUTION_MODE_DISABLED;
    else if (strcmp(value, "prestaged_wasm") == 0)
      config->mode = MESHD_EXECUTION_MODE_PRESTAGED_WASM;
    else if (strcmp(value, "prestaged_isolated") == 0)
      config->mode = MESHD_EXECUTION_MODE_PRESTAGED_ISOLATED;
    else
      return -1;
  } else if (strcmp(key, "mgmt_execution_store_file") == 0) {
    field = MESHD_EXECUTION_FIELD_STORE;
    if (value[0] == '\0' || strlen(value) >= sizeof(config->store_file))
      return -1;
    memcpy(config->store_file, value, strlen(value) + 1u);
  } else if (strcmp(key, "mgmt_execution_worker_program") == 0) {
    field = MESHD_EXECUTION_FIELD_WORKER_PROGRAM;
    if (!turbo_fs_path_is_absolute(value) ||
        strlen(value) >= sizeof(config->worker_program))
      return -1;
    memcpy(config->worker_program, value, strlen(value) + 1u);
  } else if (strcmp(key, "mgmt_execution_worker_sha256") == 0) {
    field = MESHD_EXECUTION_FIELD_WORKER_SHA256;
    if (decode_hex_exact(value, config->worker_sha256,
                         sizeof(config->worker_sha256)) != 0) return -1;
  } else if (strcmp(key, "mgmt_execution_sandbox_program") == 0) {
    field = MESHD_EXECUTION_FIELD_SANDBOX_PROGRAM;
    if (!turbo_fs_path_is_absolute(value) ||
        strlen(value) >= sizeof(config->sandbox_program))
      return -1;
    memcpy(config->sandbox_program, value, strlen(value) + 1u);
  } else if (strcmp(key, "mgmt_execution_sandbox_sha256") == 0) {
    field = MESHD_EXECUTION_FIELD_SANDBOX_SHA256;
    if (decode_hex_exact(value, config->sandbox_sha256,
                         sizeof(config->sandbox_sha256)) != 0) return -1;
  } else if (strcmp(key, "mgmt_execution_sandbox_args") == 0) {
    field = MESHD_EXECUTION_FIELD_SANDBOX_ARGS;
    if (parse_sandbox_args(config, value) != 0) return -1;
  } else if (strcmp(key, "mgmt_execution_max_worker_bytes") == 0) {
    field = MESHD_EXECUTION_FIELD_MAX_WORKER_BYTES;
    if (parse_u32(value, &config->maximum_worker_bytes) != 0) return -1;
  } else if (strcmp(key, "mgmt_execution_max_output_bytes") == 0) {
    field = MESHD_EXECUTION_FIELD_MAX_OUTPUT_BYTES;
    if (parse_size(value, &config->maximum_output_bytes) != 0) return -1;
  } else if (strcmp(key, "mgmt_execution_worker_queue_capacity") == 0) {
    field = MESHD_EXECUTION_FIELD_WORKER_QUEUE;
    if (parse_size(value, &config->worker_queue_capacity) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_egress_capacity") == 0) {
    field = MESHD_EXECUTION_FIELD_EGRESS;
    if (parse_size(value, &config->egress_capacity) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_capabilities") == 0) {
    field = MESHD_EXECUTION_FIELD_CAPABILITIES;
    if (parse_capabilities(value, &config->capabilities) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_module_bytes") == 0) {
    field = MESHD_EXECUTION_FIELD_MODULE_BYTES;
    if (parse_u32(value, &config->limits.module_bytes) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_stack_bytes") == 0) {
    field = MESHD_EXECUTION_FIELD_STACK_BYTES;
    if (parse_u32(value, &config->limits.stack_bytes) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_linear_memory_bytes") == 0) {
    field = MESHD_EXECUTION_FIELD_LINEAR_MEMORY_BYTES;
    if (parse_u32(value, &config->limits.linear_memory_bytes) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_timeout_ms") == 0) {
    field = MESHD_EXECUTION_FIELD_TIMEOUT_MS;
    if (parse_u64(value, &config->limits.timeout_ms) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_control_flow_steps") == 0) {
    field = MESHD_EXECUTION_FIELD_CONTROL_FLOW_STEPS;
    if (parse_u64(value, &config->limits.control_flow_steps) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_host_calls") == 0) {
    field = MESHD_EXECUTION_FIELD_HOST_CALLS;
    if (parse_u32(value, &config->limits.host_calls) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_copied_guest_bytes") == 0) {
    field = MESHD_EXECUTION_FIELD_COPIED_GUEST_BYTES;
    if (parse_u64(value, &config->limits.copied_guest_bytes) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_input_bytes") == 0) {
    field = MESHD_EXECUTION_FIELD_INPUT_BYTES;
    if (parse_u64(value, &config->limits.input_bytes) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_stdout_bytes") == 0) {
    field = MESHD_EXECUTION_FIELD_STDOUT_BYTES;
    if (parse_u64(value, &config->limits.stdout_bytes) != 0)
      return -1;
  } else if (strcmp(key, "mgmt_execution_stderr_bytes") == 0) {
    field = MESHD_EXECUTION_FIELD_STDERR_BYTES;
    if (parse_u64(value, &config->limits.stderr_bytes) != 0)
      return -1;
  } else if (strncmp(key, "mgmt_execution_", 15u) == 0) {
    return -1;
  } else {
    return 1;
  }
  return set_once(config, field);
}

void meshd_execution_config_init(meshd_execution_config_t *config) {
  if (config)
    memset(config, 0, sizeof(*config));
}

int meshd_execution_config_parse(meshd_execution_config_t *config,
                                 const char *yaml,
                                 size_t yaml_size) {
  const char *cursor = yaml;
  const char *end = yaml + yaml_size;
  int in_deployments = 0;

  if (!config || (!yaml && yaml_size != 0u))
    return -1;
  meshd_execution_config_init(config);
  while (cursor < end) {
    char line[MESHD_EXECUTION_CONFIG_LINE_MAX];
    const char *line_end = memchr(cursor, '\n', (size_t)(end - cursor));
    size_t line_size = line_end ? (size_t)(line_end - cursor)
                                : (size_t)(end - cursor);
    char *content;
    char *comment;
    char *colon;

    if (line_size >= sizeof(line))
      return -1;
    memcpy(line, cursor, line_size);
    line[line_size] = '\0';
    cursor = line_end ? line_end + 1 : end;
    if (line_size > 0u && line[line_size - 1u] == '\r')
      line[line_size - 1u] = '\0';
    comment = strchr(line, '#');
    if (comment)
      *comment = '\0';
    content = trim(line);
    if (*content == '\0')
      continue;
    if (in_deployments && content[0] == '-') {
      if (parse_deployment(config, content + 1) != 0)
        return -1;
      continue;
    }
    in_deployments = 0;
    colon = strchr(content, ':');
    if (!colon)
      continue;
    *colon = '\0';
    content = trim(content);
    if (strcmp(content, "mgmt_execution_deployments") == 0) {
      char *value = trim(colon + 1);
      if (set_once(config, MESHD_EXECUTION_FIELD_DEPLOYMENTS) != 0 ||
          (*value != '\0' && strcmp(value, "[]") != 0))
        return -1;
      in_deployments = 1;
      continue;
    }
    if (parse_scalar(config, content, colon + 1) < 0)
      return -1;
  }
  return meshd_execution_config_validate(config);
}

int meshd_execution_config_load(meshd_execution_config_t *config,
                                const char *path) {
  turbo_fs_buf_t buffer = {0};
  int result;

  if (!config || !path || path[0] == '\0')
    return -1;
  if (turbo_fs_read_file(path, &buffer) != 0)
    return -1;
  result = meshd_execution_config_parse(
      config, (const char *)buffer.base, buffer.len);
  turbo_fs_buf_free(&buffer);
  return result;
}

int meshd_execution_config_validate(
    const meshd_execution_config_t *config) {
  if (!config)
    return -1;
  if (config->mode == MESHD_EXECUTION_MODE_DISABLED)
    return config->seen_fields == 0u ||
                   config->seen_fields == MESHD_EXECUTION_FIELD_MODE
               ? 0
               : -1;
  if ((config->mode != MESHD_EXECUTION_MODE_PRESTAGED_WASM &&
       config->mode != MESHD_EXECUTION_MODE_PRESTAGED_ISOLATED) ||
      (config->seen_fields & MESHD_EXECUTION_REQUIRED_FIELDS) !=
          MESHD_EXECUTION_REQUIRED_FIELDS ||
      (config->seen_fields & ~MESHD_EXECUTION_KNOWN_FIELDS) != 0u ||
      config->store_file[0] == '\0' ||
      config->worker_program[0] == '\0' ||
      config->sandbox_program[0] == '\0' ||
      config->maximum_worker_bytes == 0u ||
      config->maximum_output_bytes < 440u ||
      config->worker_queue_capacity == 0u ||
      config->worker_queue_capacity >
          MESH_MGMT_EXECUTION_WORKER_MAX_QUEUE_CAPACITY ||
      config->egress_capacity == 0u ||
      config->egress_capacity > MESH_MGMT_EXECUTION_EGRESS_MAX_CAPACITY ||
      config->capabilities == 0u ||
      (config->capabilities &
       ~MESH_MGMT_EXECUTION_NODE_RAW_CAPABILITIES) != 0u ||
      config->limits.module_bytes == 0u ||
      config->limits.stack_bytes == 0u ||
      config->limits.linear_memory_bytes == 0u ||
      config->limits.timeout_ms == 0u ||
      config->limits.control_flow_steps == 0u ||
      config->limits.host_calls == 0u ||
      config->limits.copied_guest_bytes == 0u ||
      config->limits.input_bytes == 0u ||
      config->limits.stdout_bytes == 0u ||
      config->limits.stderr_bytes == 0u ||
      config->deployment_count == 0u)
    return -1;
  {
    size_t index;
    for (index = 0u; index < config->deployment_count; ++index)
      if (config->deployments[index].runtime ==
              MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1 &&
          config->capabilities !=
              MESH_MGMT_EXECUTION_RAW_WASM_CAPABILITIES_V1)
        return -1;
  }
  return 0;
}

int meshd_execution_config_build_node(
    const meshd_execution_config_t *config,
    const uint8_t local_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t result_private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t grant_issuer_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    mesh_mgmt_execution_clock_v1_fn clock_now_ms,
    void *clock_context,
    mesh_mgmt_execution_process_v1_t *execution_process,
    mesh_mgmt_execution_node_config_v1_t *out_config) {
  if (!config || !local_node_id || !result_private_key ||
      !grant_issuer_key || !clock_now_ms || !execution_process || !out_config ||
      (config->mode != MESHD_EXECUTION_MODE_PRESTAGED_WASM &&
       config->mode != MESHD_EXECUTION_MODE_PRESTAGED_ISOLATED) ||
      meshd_execution_config_validate(config) != 0)
    return -1;
  if (meshd_execution_config_build_process(config, execution_process) != 0)
    return -1;
  memset(out_config, 0, sizeof(*out_config));
  out_config->store_path = config->store_file;
  out_config->store_capacity = config->worker_queue_capacity;
  out_config->deployment_capacity = config->deployment_count;
  out_config->worker_queue_capacity = config->worker_queue_capacity;
  out_config->egress_capacity = config->egress_capacity;
  out_config->deployments = config->deployments;
  out_config->deployment_count = config->deployment_count;
  memcpy(out_config->local_node_id, local_node_id,
         sizeof(out_config->local_node_id));
  memcpy(out_config->result_private_key, result_private_key,
         sizeof(out_config->result_private_key));
  memcpy(out_config->grant_issuer_key, grant_issuer_key,
         sizeof(out_config->grant_issuer_key));
  out_config->host_capabilities = config->capabilities;
  out_config->hard_capabilities =
      MESH_MGMT_EXECUTION_NODE_RAW_CAPABILITIES;
  out_config->host_limits = config->limits;
  out_config->hard_limits = config->limits;
  out_config->worker_generation = MESHD_EXECUTION_WORKER_GENERATION;
  out_config->clock_now_ms = clock_now_ms;
  out_config->clock_context = clock_context;
  out_config->execute_runner = mesh_mgmt_execution_process_run_v1;
  out_config->execute_runner_context = execution_process;
  return 0;
}

int meshd_execution_config_build_process(
    const meshd_execution_config_t *config,
    mesh_mgmt_execution_process_v1_t *execution_process) {
  mesh_mgmt_execution_process_config_v1_t process_config;
  if (!config || !execution_process || execution_process->initialized ||
      (config->mode != MESHD_EXECUTION_MODE_PRESTAGED_WASM &&
       config->mode != MESHD_EXECUTION_MODE_PRESTAGED_ISOLATED) ||
      meshd_execution_config_validate(config) != 0)
    return -1;
  memset(&process_config, 0, sizeof(process_config));
  process_config.worker_program = config->worker_program;
  memcpy(process_config.worker_sha256, config->worker_sha256,
         sizeof(process_config.worker_sha256));
  process_config.maximum_worker_bytes = config->maximum_worker_bytes;
  process_config.sandbox_program = config->sandbox_program;
  memcpy(process_config.sandbox_sha256, config->sandbox_sha256,
         sizeof(process_config.sandbox_sha256));
  process_config.sandbox_args = config->sandbox_args;
  process_config.sandbox_arg_count = config->sandbox_arg_count;
  process_config.maximum_output_bytes = config->maximum_output_bytes;
  process_config.native_capabilities = config->capabilities;
  return mesh_mgmt_execution_process_init_v1(execution_process,
                                              &process_config) ==
                 MESH_MGMT_EXECUTION_RUNNER_OK
             ? 0
             : -1;
}

#ifndef TURBO_P2P_MESH_MGMT_SERVICE_CONFIG_H
#define TURBO_P2P_MESH_MGMT_SERVICE_CONFIG_H

#include "mesh_mgmt_service_publisher.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_SERVICE_CONFIG_VERSION 1u
#define MESH_MGMT_SERVICE_CONFIG_MAX_JSON_BYTES 4096u

typedef enum mesh_mgmt_service_config_result {
  MESH_MGMT_SERVICE_CONFIG_OK = 0,
  MESH_MGMT_SERVICE_CONFIG_INVALID_ARG = -1,
  MESH_MGMT_SERVICE_CONFIG_SCHEMA_FAILED = -2,
  MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED = -3,
  MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID = -4
} mesh_mgmt_service_config_result_t;

/* Owned, address-stable startup configuration. It contains no DataBind lease,
 * string reference, module pointer or network endpoint. Only RPC/IPv4 is
 * admitted in v1; unsupported service families must fail before publish. */
typedef struct mesh_mgmt_service_config_v1 {
  size_t size;
  uint32_t version;
  uint8_t address_family;
  uint8_t virtual_address[16];
  uint16_t port;
  char dns_name[MESH_MGMT_SERVICE_DNS_NAME_MAX + 1u];
} mesh_mgmt_service_config_v1_t;

/* ACE host Configurator: parse a bounded, strict, versioned DataBind 4.3 JSON
 * record and validate it against the canonical signed MMP service encoder.
 * Schema/ValidationPlan/record are released before this call returns.
 * No partial result survives a failure. No network, DHT or MMP publish.
 * Required fields: schema_version=1, address_family=4, octet0..3 [0..255],
 * port [1..65535], dns_name (canonical lowercase or empty).
 */
mesh_mgmt_service_config_result_t mesh_mgmt_service_config_from_json_v1(
    const char *json, size_t json_length,
    mesh_mgmt_service_config_v1_t *out_config);

/* Produce one synchronous publish call view. The returned dns_name pointer
 * borrows from owner; owner must remain at a stable address and immutable
 * until mesh_mgmt_agent_runtime_publish_cached_service_v1 returns.
 * Copy the owned config before invoking this function, not afterward.
 * Revalidates canonical service fields at the admission boundary. */
mesh_mgmt_service_config_result_t mesh_mgmt_service_config_publish_view_v1(
    const mesh_mgmt_service_config_v1_t *owner,
    mesh_mgmt_service_publish_v1_t *out_service);

#ifdef __cplusplus
}
#endif

#endif

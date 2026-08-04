#include "mesh_stream_discovery.h"

#include <ctype.h>
#include <string.h>

/* P6: discovery registry. The mgmt service record stays the fact source; the
 * registry is a derived, bounded view keyed by (node_id, service_type,
 * service_id) with epoch fencing (older announcements are rejected) and TTL
 * expiry. Lookups list every live node serving a stream or object. */

static int is_hex(const char *s, size_t len) {
  if (len == 0u || len > MESH_STREAM_DISCOVERY_ID_HEX_SIZE - 1u)
    return 0;
  for (size_t i = 0u; i < len; i++) {
    if (!isxdigit((unsigned char)s[i]))
      return 0;
  }
  return 1;
}

/* dns labels are capped at 63 chars, so ids longer than 32 hex chars are
 * split into two labels with a '.'. */
#define DISCOVERY_LABEL_MAX_HEX 32u

static int same_entry(const mesh_stream_discovery_entry_v1_t *a,
                      const mesh_stream_discovery_entry_v1_t *b) {
  return a->service_type == b->service_type &&
         memcmp(a->node_id, b->node_id, sizeof(a->node_id)) == 0 &&
         strcmp(a->service_id, b->service_id) == 0;
}

mesh_stream_discovery_result_t mesh_stream_discovery_dns_name_build_v1(
    mesh_stream_discovery_service_type_t type, const char *service_id_hex,
    char *out, size_t out_capacity) {
  const char *prefix;
  size_t prefix_len;
  size_t id_len;

  if (!service_id_hex || !out)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  if (type == MESH_STREAM_DISCOVERY_SERVICE_STREAM) {
    prefix = "mesh-stream-";
    prefix_len = 12u;
  } else if (type == MESH_STREAM_DISCOVERY_SERVICE_SYNC) {
    prefix = "mesh-sync-";
    prefix_len = 10u;
  } else {
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  }
  id_len = strlen(service_id_hex);
  if (!is_hex(service_id_hex, id_len) || prefix_len + id_len + 1u > out_capacity)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  memcpy(out, prefix, prefix_len);
  if (id_len <= DISCOVERY_LABEL_MAX_HEX) {
    memcpy(out + prefix_len, service_id_hex, id_len);
    out[prefix_len + id_len] = '\0';
  } else {
    /* Split into two DNS labels to respect the 63-char label bound. */
    memcpy(out + prefix_len, service_id_hex, DISCOVERY_LABEL_MAX_HEX);
    out[prefix_len + DISCOVERY_LABEL_MAX_HEX] = '.';
    memcpy(out + prefix_len + DISCOVERY_LABEL_MAX_HEX + 1u,
           service_id_hex + DISCOVERY_LABEL_MAX_HEX, id_len - DISCOVERY_LABEL_MAX_HEX);
    out[prefix_len + id_len + 1u] = '\0';
  }
  return MESH_STREAM_DISCOVERY_OK;
}

mesh_stream_discovery_result_t mesh_stream_discovery_dns_name_parse_v1(
    const char *dns_name, size_t name_len,
    mesh_stream_discovery_service_type_t *out_type, char *out_service_id_hex,
    size_t service_id_capacity) {
  const char *prefix;
  size_t prefix_len;
  mesh_stream_discovery_service_type_t type;
  size_t written = 0u;

  if (!dns_name || !out_type || !out_service_id_hex)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  if (name_len >= 10u && memcmp(dns_name, "mesh-sync-", 10u) == 0) {
    prefix = "mesh-sync-";
    prefix_len = 10u;
    type = MESH_STREAM_DISCOVERY_SERVICE_SYNC;
  } else if (name_len >= 12u && memcmp(dns_name, "mesh-stream-", 12u) == 0) {
    prefix = "mesh-stream-";
    prefix_len = 12u;
    type = MESH_STREAM_DISCOVERY_SERVICE_STREAM;
  } else {
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  }
  /* Hex runs separated by '.' (the two-label split form); '.' is skipped. */
  for (size_t i = prefix_len; i < name_len; i++) {
    char value = dns_name[i];

    if (value == '.')
      continue;
    if (!isxdigit((unsigned char)value) || written + 1u >= service_id_capacity)
      return MESH_STREAM_DISCOVERY_INVALID_ARG;
    out_service_id_hex[written++] = (char)(value >= 'A' && value <= 'Z'
                                               ? value + ('a' - 'A')
                                               : value);
  }
  if (written == 0u)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  out_service_id_hex[written] = '\0';
  *out_type = type;
  return MESH_STREAM_DISCOVERY_OK;
}

mesh_stream_discovery_result_t mesh_stream_discovery_from_announcement_v1(
    const mesh_mgmt_service_announcement_v1_t *announcement,
    mesh_stream_discovery_entry_v1_t *out_entry) {
  mesh_stream_discovery_service_type_t type;
  size_t name_len;

  if (!announcement || !out_entry)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  name_len = strlen(announcement->dns_name);
  if (name_len > MESH_MGMT_SERVICE_DNS_NAME_MAX)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  {
    mesh_stream_discovery_result_t rc = mesh_stream_discovery_dns_name_parse_v1(
        announcement->dns_name, name_len, &type, out_entry->service_id,
        sizeof(out_entry->service_id));

    if (rc != MESH_STREAM_DISCOVERY_OK)
      return rc;
  }
  if (announcement->address_family != MESH_MGMT_SERVICE_ADDRESS_IPV4)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  memset(out_entry->node_id, 0, sizeof(out_entry->node_id));
  memcpy(out_entry->node_id, announcement->owner_node_id,
         sizeof(out_entry->node_id));
  out_entry->service_type = type;
  out_entry->virtual_ip =
      ((uint32_t)announcement->virtual_address[0] << 24u) |
      ((uint32_t)announcement->virtual_address[1] << 16u) |
      ((uint32_t)announcement->virtual_address[2] << 8u) |
      (uint32_t)announcement->virtual_address[3];
  out_entry->port = announcement->port;
  out_entry->epoch = announcement->record_epoch;
  out_entry->expires_at_ms = announcement->expires_at_ms;
  return MESH_STREAM_DISCOVERY_OK;
}

mesh_stream_discovery_result_t mesh_stream_discovery_to_announcement_v1(
    const mesh_stream_discovery_entry_v1_t *entry,
    mesh_mgmt_service_announcement_v1_t *out_announcement) {
  mesh_stream_discovery_result_t rc;

  if (!entry || !out_announcement)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  memset(out_announcement, 0, sizeof(*out_announcement));
  rc = mesh_stream_discovery_dns_name_build_v1(
      entry->service_type, entry->service_id, out_announcement->dns_name,
      sizeof(out_announcement->dns_name));
  if (rc != MESH_STREAM_DISCOVERY_OK)
    return rc;
  memcpy(out_announcement->owner_node_id, entry->node_id,
         sizeof(out_announcement->owner_node_id));
  out_announcement->service_type = MESH_MGMT_SERVICE_RPC;
  out_announcement->address_family = MESH_MGMT_SERVICE_ADDRESS_IPV4;
  out_announcement->virtual_address[0] = (uint8_t)(entry->virtual_ip >> 24u);
  out_announcement->virtual_address[1] = (uint8_t)(entry->virtual_ip >> 16u);
  out_announcement->virtual_address[2] = (uint8_t)(entry->virtual_ip >> 8u);
  out_announcement->virtual_address[3] = (uint8_t)entry->virtual_ip;
  out_announcement->port = entry->port;
  out_announcement->record_epoch = entry->epoch;
  out_announcement->expires_at_ms = entry->expires_at_ms;
  return MESH_STREAM_DISCOVERY_OK;
}

mesh_stream_discovery_result_t mesh_stream_discovery_upsert_v1(
    mesh_stream_discovery_v1_t *registry,
    const mesh_stream_discovery_entry_v1_t *entry, uint64_t now_ms) {
  size_t slot = SIZE_MAX;

  if (!registry || !entry)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  if (entry->expires_at_ms <= now_ms)
    return MESH_STREAM_DISCOVERY_INVALID_ARG; /* already expired */
  for (size_t i = 0u; i < registry->count; i++) {
    if (same_entry(&registry->entries[i], entry)) {
      if (entry->epoch <= registry->entries[i].epoch)
        return MESH_STREAM_DISCOVERY_STALE_EPOCH;
      slot = i;
      break;
    }
  }
  if (slot == SIZE_MAX) {
    if (registry->count >= MESH_STREAM_DISCOVERY_MAX_ENTRIES)
      return MESH_STREAM_DISCOVERY_RESOURCE_EXHAUSTED;
    slot = registry->count;
    registry->count++;
  }
  registry->entries[slot] = *entry;
  return MESH_STREAM_DISCOVERY_OK;
}

void mesh_stream_discovery_expire_v1(mesh_stream_discovery_v1_t *registry,
                                     uint64_t now_ms) {
  size_t write = 0u;

  if (!registry)
    return;
  for (size_t i = 0u; i < registry->count; i++) {
    if (registry->entries[i].expires_at_ms > now_ms) {
      if (write != i)
        registry->entries[write] = registry->entries[i];
      write++;
    }
  }
  registry->count = write;
}

mesh_stream_discovery_result_t mesh_stream_discovery_lookup_v1(
    const mesh_stream_discovery_v1_t *registry,
    mesh_stream_discovery_service_type_t type, const char *service_id_hex,
    uint64_t now_ms, mesh_stream_discovery_entry_v1_t *out_entries,
    size_t out_capacity, size_t *out_count) {
  size_t found = 0u;

  if (!registry || !service_id_hex || !out_entries || !out_count)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  if (out_capacity == 0u)
    return MESH_STREAM_DISCOVERY_INVALID_ARG;
  for (size_t i = 0u; i < registry->count; i++) {
    const mesh_stream_discovery_entry_v1_t *e = &registry->entries[i];

    if (e->service_type == type && strcmp(e->service_id, service_id_hex) == 0 &&
        e->expires_at_ms > now_ms) {
      if (found < out_capacity)
        out_entries[found] = *e;
      found++;
    }
  }
  *out_count = found;
  return found > 0u ? MESH_STREAM_DISCOVERY_OK : MESH_STREAM_DISCOVERY_NOT_FOUND;
}

size_t mesh_stream_discovery_count(const mesh_stream_discovery_v1_t *registry) {
  return registry ? registry->count : 0u;
}
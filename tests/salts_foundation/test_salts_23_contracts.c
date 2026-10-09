#include <cnet/owner_placement.h>
#include <cnet/destination_policy.h>
#include <cnet/recovery_policy.h>
#include <cnet/manager.h>
#include <cnet/client_pool.h>
#include <cnet/managed_dial.h>
#include <data_bind.h>
#include <data_bind_validation_plan.h>
#include <cmeta/function.h>
#include <salts/error_codes.h>

#include <stdint.h>
#include <stdio.h>

#define VERIFY(expr) do { \
  if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s failed\\n", __FILE__, __LINE__, #expr); \
    return 1; \
  } \
} while (0)

static int check_server_owner(void) {
  const cnet_owner_placement_hint owners[] = {
    {true, 0u}, {true, 1u}
  };
  cnet_owner_placement_input selection = {0};
  size_t chosen = SIZE_MAX;
  cnet_owner_placement_hint no_capacity[2] = {owners[0], owners[1]};

  selection.size = sizeof(selection);
  selection.version = CNET_OWNER_PLACEMENT_VERSION;
  selection.kind = CNET_OWNER_PLACE_EXPLICIT;
  selection.owners = owners;
  selection.owner_count = 2u;
  selection.explicit_owner = 1u;
  VERIFY(cnet_owner_placement_choose(&selection, &chosen) == SALTS_OK);
  VERIFY(chosen == 1u);

  no_capacity[1].eligible = false;
  selection.owners = no_capacity;
  VERIFY(cnet_owner_placement_choose(&selection, &chosen) == SALTS_ENOBUFS);
  VERIFY(chosen == SIZE_MAX); /* A configured owner must never silently change. */

  selection.owners = owners;
  selection.version++;
  VERIFY(cnet_owner_placement_choose(&selection, &chosen) == SALTS_EINVAL);
  return 0;
}

static int check_client_destination(void) {
  cnet_destination_hint peers[3] = {
    {11u, 1u, 0u, true}, {22u, 1u, 0u, true}, {33u, 1u, 0u, true}
  };
  cnet_destination_hint retained[2];
  cnet_destination_selection selection = {0};
  cnet_destination_result chosen = {0}, after = {0};
  size_t index = 0u;

  selection.size = sizeof(selection);
  selection.version = CNET_DESTINATION_POLICY_VERSION;
  selection.kind = CNET_DESTINATION_STRICT_KEY;
  selection.endpoints = peers;
  selection.endpoint_count = 3u;
  selection.snapshot_generation = 7u;
  selection.expires_at_ms = UINT64_MAX;
  selection.now_ms = 100u;
  selection.key_known = true;
  selection.key_hash = UINT64_C(0x53ab);
  VERIFY(cnet_destination_choose(&selection, &chosen) == SALTS_OK);
  VERIFY(chosen.endpoint_id != 0u);

  /* Remove a different member: rendezvous chooses stable endpoint identity,
   * not an array index that moves when membership changes. */
  for (size_t i = 0; i < 3u; ++i) {
    if (peers[i].endpoint_id != chosen.endpoint_id || index == 0u)
      retained[index++] = peers[i];
    if (index == 2u) break;
  }
  VERIFY(index == 2u);
  selection.endpoints = retained;
  selection.endpoint_count = 2u;
  selection.snapshot_generation = 8u;
  VERIFY(cnet_destination_choose(&selection, &after) == SALTS_OK);
  VERIFY(after.endpoint_id == chosen.endpoint_id);
  VERIFY(after.snapshot_generation == 8u);

  /* Strict identity is an authority constraint, not a hint to pick any
   * neighboring healthy peer when the winner is ineligible. */
  retained[after.index].eligible = false;
  VERIFY(cnet_destination_choose(&selection, &after) == SALTS_ENOBUFS);
  VERIFY(after.index == SIZE_MAX);

  selection.kind = CNET_DESTINATION_EXPLICIT;
  selection.explicit_endpoint_id = chosen.endpoint_id;
  VERIFY(cnet_destination_choose(&selection, &after) == SALTS_ENOBUFS);
  selection.explicit_endpoint_id = 99u;
  VERIFY(cnet_destination_choose(&selection, &after) == SALTS_ENOENT);

  selection.kind = CNET_DESTINATION_ROUND_ROBIN;
  selection.snapshot_generation = 0u;
  VERIFY(cnet_destination_choose(&selection, &after) == SALTS_EINVAL);
  return 0;
}

static int check_retry_gate(void) {
  cnet_retry_input attempt = {0};
  cnet_retry_result decision = {0};
  attempt.size = sizeof(attempt);
  attempt.version = CNET_RECOVERY_POLICY_VERSION;
  attempt.attempts_used = 1u;
  attempt.max_attempts = 2u;
  attempt.now_ms = 100u;
  attempt.deadline_ms = 1000u;
  attempt.request_body_bytes = 64u;
  attempt.remaining_retry_byte_budget = 64u;
  attempt.explicitly_enabled = true;
  attempt.owned_replayable_body = true;
  attempt.protocol_proves_not_executed = true;

  VERIFY(cnet_retry_evaluate(&attempt, &decision) == SALTS_OK);
  VERIFY(decision.allowed && decision.reason == CNET_RETRY_ALLOWED);
  attempt.protocol_proves_not_executed = false;
  VERIFY(cnet_retry_evaluate(&attempt, &decision) == SALTS_OK);
  VERIFY(!decision.allowed && decision.reason == CNET_RETRY_UNAUTHORIZED);
  attempt.protocol_proves_not_executed = true;
  attempt.one_attempt_contract = true;
  VERIFY(cnet_retry_evaluate(&attempt, &decision) == SALTS_OK);
  VERIFY(!decision.allowed && decision.reason == CNET_RETRY_ONE_ATTEMPT);
  attempt.one_attempt_contract = false;
  attempt.security_failure = true;
  VERIFY(cnet_retry_evaluate(&attempt, &decision) == SALTS_OK);
  VERIFY(!decision.allowed && decision.reason == CNET_RETRY_SECURITY);
  return 0;
}

static int check_databind_contract(void) {
  DataBindSchemaField field = DATA_BIND_SCHEMA_FIELD_INIT;
  DataBindService service = DATA_BIND_SERVICE_INIT;
  DataBindError error = DATA_BIND_ERROR_INIT;
  const cmeta_data_desc placeholder = {0};
  const cmeta_data_desc *out = &placeholder;

  VERIFY(DATA_BIND_ABI_VERSION >= 10);
  VERIFY(field.size == sizeof(field));
  VERIFY(service.size == sizeof(service));
  field.has_cmeta_kind = 1;
  field.cmeta_kind = CMETA_DATA_SEQUENCE;
  field.cmeta_data = &placeholder;
  VERIFY(data_bind_schema_field_cmeta_data(NULL, "MeshCapability", 0u, &out, &error)
         == DATA_BIND_ERR_INVALID_ARG);
  VERIFY(error.code == DATA_BIND_ERR_INVALID_ARG);
  VERIFY(out == &placeholder);
  VERIFY(data_bind_service_at(NULL, 0u, &service) == 0);
  VERIFY(data_bind_validation_plan_type_name(NULL) == NULL);
  return 0;
}

int main(void) {
  if (check_server_owner()) return 1;
  if (check_client_destination()) return 1;
  if (check_retry_gate()) return 1;
  if (check_databind_contract()) return 1;
  return 0;
}

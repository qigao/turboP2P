#include "mesh_task_execution_guard.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

static const uint8_t WORKER_IDENTITY_DOMAIN[] = {
    'm', 'e', 's', 'h', '/', 't', 'a', 's', 'k', '/', 'w', 'o', 'r', 'k', 'e',
    'r', '/', 'v', '1'};

static int bytes_equal(const uint8_t *lhs, const uint8_t *rhs, size_t size) {
  uint8_t difference = 0u;
  size_t index;
  for (index = 0u; index < size; ++index) {
    difference |= (uint8_t)(lhs[index] ^ rhs[index]);
  }
  return difference == 0u;
}

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  uint8_t value = 0u;
  size_t index;
  for (index = 0u; index < size; ++index) {
    value |= bytes[index];
  }
  return value == 0u;
}

mesh_task_execution_guard_result_t mesh_task_worker_identity_v1(
    const uint8_t node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t worker_generation,
    uint8_t out_identity[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  uint8_t canonical[sizeof(WORKER_IDENTITY_DOMAIN) +
                    MESH_MGMT_EXECUTION_DIGEST_SIZE + sizeof(uint64_t)];
  size_t offset = 0u;
  size_t index;

  if (!node_id || bytes_are_zero(node_id, MESH_MGMT_EXECUTION_DIGEST_SIZE) ||
      worker_generation == 0u || !out_identity) {
    return MESH_TASK_EXECUTION_GUARD_INVALID_ARG;
  }
  memcpy(canonical + offset, WORKER_IDENTITY_DOMAIN,
         sizeof(WORKER_IDENTITY_DOMAIN));
  offset += sizeof(WORKER_IDENTITY_DOMAIN);
  memcpy(canonical + offset, node_id, MESH_MGMT_EXECUTION_DIGEST_SIZE);
  offset += MESH_MGMT_EXECUTION_DIGEST_SIZE;
  for (index = 0u; index < sizeof(worker_generation); ++index) {
    canonical[offset + index] =
        (uint8_t)(worker_generation >> ((sizeof(worker_generation) - index -
                                         1u) *
                                        8u));
  }
  if (mesh_mgmt_blake2b_256(canonical, sizeof(canonical), out_identity) !=
      MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
    return MESH_TASK_EXECUTION_GUARD_CRYPTO_FAILED;
  }
  mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
  return MESH_TASK_EXECUTION_GUARD_OK;
}

mesh_task_execution_guard_result_t mesh_task_execution_guard_v1(
    const mesh_task_lease_store_v1_t *store,
    const uint8_t local_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const mesh_task_execution_claim_v1_t *claim,
    const mesh_task_execution_proof_v1_t *proof,
    mesh_task_lease_entry_v1_t *out_lease) {
  mesh_task_lease_entry_v1_t lease;
  uint8_t worker_identity[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  mesh_task_execution_guard_result_t identity_result;
  mesh_task_lease_result_t lease_result;

  if (out_lease) {
    memset(out_lease, 0, sizeof(*out_lease));
  }
  if (!store || !store->open || !local_node_id || !claim || !proof ||
      !out_lease || proof->fencing_token == 0u ||
      proof->worker_generation == 0u || proof->quorum_read_index == 0u ||
      proof->local_applied_index == 0u || proof->observed_now_ms == 0u ||
      bytes_are_zero(claim->command_id, sizeof(claim->command_id)) ||
      bytes_are_zero(claim->request_digest, sizeof(claim->request_digest)) ||
      bytes_are_zero(claim->target_node_id, sizeof(claim->target_node_id)) ||
      claim->task_deadline_ms == 0u) {
    return MESH_TASK_EXECUTION_GUARD_INVALID_ARG;
  }
  if (!bytes_equal(local_node_id, claim->target_node_id,
                   MESH_MGMT_EXECUTION_DIGEST_SIZE)) {
    return MESH_TASK_EXECUTION_GUARD_IDENTITY_CONFLICT;
  }
  lease_result = mesh_task_lease_get_v1(store, claim->command_id, &lease);
  if (lease_result == MESH_TASK_LEASE_NOT_FOUND) {
    return MESH_TASK_EXECUTION_GUARD_NOT_FOUND;
  }
  if (lease_result != MESH_TASK_LEASE_OK) {
    return MESH_TASK_EXECUTION_GUARD_INVALID_ARG;
  }
  if (!bytes_equal(lease.request_digest, claim->request_digest,
                   sizeof(lease.request_digest)) ||
      lease.task_deadline_ms != claim->task_deadline_ms) {
    return MESH_TASK_EXECUTION_GUARD_IDENTITY_CONFLICT;
  }
  if (lease.state != MESH_TASK_STATE_LEASED) {
    return MESH_TASK_EXECUTION_GUARD_NOT_LEASED;
  }
  identity_result = mesh_task_worker_identity_v1(
      local_node_id, proof->worker_generation, worker_identity);
  if (identity_result != MESH_TASK_EXECUTION_GUARD_OK) {
    return identity_result;
  }
  if (!bytes_equal(worker_identity, lease.holder_node_id,
                   sizeof(worker_identity)) ||
      proof->fencing_token != lease.fencing_token) {
    return MESH_TASK_EXECUTION_GUARD_FENCED;
  }
  if (proof->local_applied_index < proof->quorum_read_index ||
      proof->quorum_read_index < lease.mutation_index) {
    return MESH_TASK_EXECUTION_GUARD_STALE_READ;
  }
  if (proof->observed_now_ms >= lease.lease_expires_at_ms ||
      proof->observed_now_ms >= lease.task_deadline_ms) {
    return MESH_TASK_EXECUTION_GUARD_EXPIRED;
  }
  *out_lease = lease;
  return MESH_TASK_EXECUTION_GUARD_OK;
}

#include "mesh_task_execution_guard.h"
#include "tinytest.h"

#include <string.h>

static void test_guard_requires_current_worker_fence_and_quorum_read(void) {
  mesh_task_lease_store_v1_t store;
  mesh_task_execution_claim_v1_t claim;
  mesh_task_execution_proof_v1_t proof;
  mesh_task_lease_entry_v1_t lease;
  uint8_t node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t worker_identity[MESH_MGMT_EXECUTION_DIGEST_SIZE];

  memset(&store, 0, sizeof(store));
  memset(&claim, 0, sizeof(claim));
  memset(&proof, 0, sizeof(proof));
  memset(node_id, 0x31, sizeof(node_id));
  memset(claim.command_id, 0x11, sizeof(claim.command_id));
  memset(claim.request_digest, 0x21, sizeof(claim.request_digest));
  memcpy(claim.target_node_id, node_id, sizeof(node_id));
  claim.task_deadline_ms = 1000u;
  proof.worker_generation = 7u;
  check_int_eq(mesh_task_worker_identity_v1(node_id, proof.worker_generation,
                                            worker_identity),
               MESH_TASK_EXECUTION_GUARD_OK);
  check_int_eq(mesh_task_lease_store_init_v1(&store, 2u, 200u),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_task_lease_register_v1(
                   &store, 10u, claim.command_id, claim.request_digest,
                   claim.task_deadline_ms, &lease),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_task_lease_acquire_v1(
                   &store, 11u, claim.command_id, claim.request_digest,
                   worker_identity, 100u, 250u, &lease),
               MESH_TASK_LEASE_OK);

  proof.fencing_token = 11u;
  proof.quorum_read_index = 12u;
  proof.local_applied_index = 12u;
  proof.observed_now_ms = 150u;
  check_int_eq(mesh_task_execution_guard_v1(&store, node_id, &claim, &proof,
                                             &lease),
               MESH_TASK_EXECUTION_GUARD_OK);

  proof.fencing_token = 10u;
  check_int_eq(mesh_task_execution_guard_v1(&store, node_id, &claim, &proof,
                                             &lease),
               MESH_TASK_EXECUTION_GUARD_FENCED);
  proof.fencing_token = 11u;
  proof.local_applied_index = 11u;
  check_int_eq(mesh_task_execution_guard_v1(&store, node_id, &claim, &proof,
                                             &lease),
               MESH_TASK_EXECUTION_GUARD_STALE_READ);
  proof.local_applied_index = 12u;
  proof.observed_now_ms = 250u;
  check_int_eq(mesh_task_execution_guard_v1(&store, node_id, &claim, &proof,
                                             &lease),
               MESH_TASK_EXECUTION_GUARD_EXPIRED);

  mesh_task_lease_store_destroy_v1(&store);
}

static void test_worker_generation_changes_holder_identity(void) {
  uint8_t node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t first[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t second[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  memset(node_id, 0x41, sizeof(node_id));
  check_int_eq(mesh_task_worker_identity_v1(node_id, 1u, first),
               MESH_TASK_EXECUTION_GUARD_OK);
  check_int_eq(mesh_task_worker_identity_v1(node_id, 2u, second),
               MESH_TASK_EXECUTION_GUARD_OK);
  check_true(memcmp(first, second, sizeof(first)) != 0);
}

spec("mesh task execution lease guard") {
  it("requires a current worker fence and quorum read") {
    test_guard_requires_current_worker_fence_and_quorum_read();
  }
  it("binds holder identity to worker generation") {
    test_worker_generation_changes_holder_identity();
  }
}

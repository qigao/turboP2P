#include "mesh_task_lease.h"

#include <tinytest.h>

#include <string.h>

static void fill(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static void init_store(mesh_task_lease_store_v1_t *store, size_t capacity) {
  memset(store, 0, sizeof(*store));
  check_int_eq(mesh_task_lease_store_init_v1(store, capacity, 100u),
               MESH_TASK_LEASE_OK);
}

static void test_renewal_fences_old_worker(void) {
  mesh_task_lease_store_v1_t store;
  mesh_task_lease_entry_v1_t entry;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t worker[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t first_token;

  fill(command_id, sizeof(command_id), 0x11u);
  fill(digest, sizeof(digest), 0x22u);
  fill(worker, sizeof(worker), 0x33u);
  init_store(&store, 2u);
  check_int_eq(mesh_task_lease_register_v1(&store, 1u, command_id, digest,
                                            1000u, &entry),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_task_lease_acquire_v1(&store, 2u, command_id, digest,
                                           worker, 100u, 150u, &entry),
               MESH_TASK_LEASE_OK);
  first_token = entry.fencing_token;
  check_long_eq(first_token, 2u);
  check_int_eq(mesh_task_lease_renew_v1(&store, 3u, command_id, digest,
                                         worker, first_token, 120u, 200u,
                                         &entry),
               MESH_TASK_LEASE_OK);
  check_long_eq(entry.fencing_token, 3u);
  check_int_eq(mesh_task_lease_complete_v1(
                   &store, 4u, command_id, digest, worker, first_token, 130u,
                   MESH_TASK_STATE_SUCCEEDED, 0, &entry),
               MESH_TASK_LEASE_FENCED);
  check_long_eq(store.applied_index, 3u);
  check_int_eq(mesh_task_lease_complete_v1(
                   &store, 4u, command_id, digest, worker, 3u, 130u,
                   MESH_TASK_STATE_SUCCEEDED, 0, &entry),
               MESH_TASK_LEASE_OK);
  check_int_eq(entry.state, MESH_TASK_STATE_SUCCEEDED);
  check_long_eq(entry.mutation_index, 4u);
  mesh_task_lease_store_destroy_v1(&store);
}

static void apply_replay(mesh_task_lease_store_v1_t *store,
                         const uint8_t *command_id, const uint8_t *digest,
                         const uint8_t *first_worker,
                         const uint8_t *second_worker) {
  mesh_task_lease_entry_v1_t entry;

  check_int_eq(mesh_task_lease_register_v1(store, 10u, command_id, digest,
                                            1000u, &entry),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_task_lease_acquire_v1(store, 11u, command_id, digest,
                                           first_worker, 100u, 150u, &entry),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_task_lease_expire_v1(store, 12u, command_id, digest, 11u,
                                          150u, &entry),
               MESH_TASK_LEASE_OK);
  check_int_eq(entry.state, MESH_TASK_STATE_READY);
  check_int_eq(mesh_task_lease_acquire_v1(store, 13u, command_id, digest,
                                           second_worker, 160u, 220u, &entry),
               MESH_TASK_LEASE_OK);
}

static void test_expiry_reassignment_replays_deterministically(void) {
  mesh_task_lease_store_v1_t first;
  mesh_task_lease_store_v1_t replay;
  mesh_task_lease_entry_v1_t first_entry;
  mesh_task_lease_entry_v1_t replay_entry;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t first_worker[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t second_worker[MESH_MGMT_EXECUTION_DIGEST_SIZE];

  fill(command_id, sizeof(command_id), 0x41u);
  fill(digest, sizeof(digest), 0x42u);
  fill(first_worker, sizeof(first_worker), 0x43u);
  fill(second_worker, sizeof(second_worker), 0x44u);
  init_store(&first, 1u);
  init_store(&replay, 1u);
  apply_replay(&first, command_id, digest, first_worker, second_worker);
  apply_replay(&replay, command_id, digest, first_worker, second_worker);
  check_int_eq(mesh_task_lease_get_v1(&first, command_id, &first_entry),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_task_lease_get_v1(&replay, command_id, &replay_entry),
               MESH_TASK_LEASE_OK);
  check_mem_eq(&first_entry, &replay_entry, sizeof(first_entry));
  check_long_eq(first_entry.lease_generation, 2u);
  check_long_eq(first_entry.fencing_token, 13u);
  check_mem_eq(first_entry.holder_node_id, second_worker,
               sizeof(first_entry.holder_node_id));
  check_int_eq(mesh_task_lease_complete_v1(
                   &first, 14u, command_id, digest, first_worker, 11u, 170u,
                   MESH_TASK_STATE_SUCCEEDED, 0, &first_entry),
               MESH_TASK_LEASE_FENCED);
  mesh_task_lease_store_destroy_v1(&first);
  mesh_task_lease_store_destroy_v1(&replay);
}

static void test_identity_conflict_deadline_and_capacity_fail_closed(void) {
  mesh_task_lease_store_v1_t store;
  mesh_task_lease_entry_v1_t entry;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t second_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t other_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t worker[MESH_MGMT_EXECUTION_DIGEST_SIZE];

  fill(command_id, sizeof(command_id), 0x61u);
  fill(second_id, sizeof(second_id), 0x62u);
  fill(digest, sizeof(digest), 0x63u);
  fill(other_digest, sizeof(other_digest), 0x64u);
  fill(worker, sizeof(worker), 0x65u);
  init_store(&store, 1u);
  check_int_eq(mesh_task_lease_register_v1(&store, 1u, command_id, digest,
                                            200u, &entry),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_task_lease_register_v1(&store, 2u, command_id,
                                            other_digest, 200u, &entry),
               MESH_TASK_LEASE_CONFLICT);
  check_int_eq(mesh_task_lease_register_v1(&store, 2u, second_id, digest,
                                            200u, &entry),
               MESH_TASK_LEASE_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_task_lease_acquire_v1(&store, 2u, command_id, digest,
                                           worker, 190u, 210u, &entry),
               MESH_TASK_LEASE_INVALID_ARG);
  check_int_eq(mesh_task_lease_expire_v1(&store, 2u, command_id, digest, 0u,
                                          200u, &entry),
               MESH_TASK_LEASE_OK);
  check_int_eq(entry.state, MESH_TASK_STATE_EXPIRED);
  check_long_eq(store.applied_index, 2u);
  mesh_task_lease_store_destroy_v1(&store);
}

spec("mesh execution task lease state machine") {
  it("publishes a new fencing token on renewal") {
    test_renewal_fences_old_worker();
  }
  it("reassigns only after committed expiry and replays deterministically") {
    test_expiry_reassignment_replays_deterministically();
  }
  it("fails closed on identity conflict, deadline, and capacity") {
    test_identity_conflict_deadline_and_capacity_fail_closed();
  }
}

#include <tinytest.h>

#include "mesh_mgmt_replay.h"

#include <stdint.h>
#include <string.h>

#define TEST_NOW_MS UINT64_C(1000)

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t value) {
    memset(bytes, value, length);
}

static void prepare_gate(mesh_mgmt_replay_gate_v1_t *gate,
                         size_t capacity,
                         uint64_t ttl_ms) {
    mesh_mgmt_replay_config_v1_t config;
    mesh_mgmt_replay_binding_v1_t binding;

    memset(&config, 0, sizeof(config));
    config.capacity = capacity;
    config.ttl_ms = ttl_ms;
    check_int_eq(mesh_mgmt_replay_init_v1(gate, &config),
                 MESH_MGMT_REPLAY_OK);
    memset(&binding, 0, sizeof(binding));
    fill_bytes(binding.principal_key, sizeof(binding.principal_key), 0x31);
    binding.principal_epoch = 7u;
    binding.incarnation = 3u;
    fill_bytes(binding.session_id, sizeof(binding.session_id), 0x41);
    check_int_eq(mesh_mgmt_replay_bind_v1(gate, &binding),
                 MESH_MGMT_REPLAY_OK);
}

static void prepare_header(mesh_mgmt_header_v1_t *header,
                           uint64_t sequence,
                           uint8_t message_byte,
                           uint64_t issued_at_ms,
                           uint64_t expires_at_ms) {
    memset(header, 0, sizeof(*header));
    fill_bytes(header->origin_principal_key,
               sizeof(header->origin_principal_key), 0x31);
    header->principal_epoch = 7u;
    header->incarnation = 3u;
    fill_bytes(header->session_id, sizeof(header->session_id), 0x41);
    header->origin_sequence = sequence;
    fill_bytes(header->message_id, sizeof(header->message_id), message_byte);
    header->issued_at_ms = issued_at_ms;
    header->expires_at_ms = expires_at_ms;
}

static mesh_mgmt_replay_result_t prepare_and_commit(
    mesh_mgmt_replay_gate_v1_t *gate,
    const mesh_mgmt_header_v1_t *header,
    uint64_t now_ms) {
    mesh_mgmt_replay_preparation_v1_t preparation;
    mesh_mgmt_replay_result_t result = mesh_mgmt_replay_prepare_v1(
        gate, header, now_ms, &preparation);

    if (result != MESH_MGMT_REPLAY_OK) return result;
    return mesh_mgmt_replay_commit_v1(gate, &preparation);
}

static void test_accepts_newer_sequence_and_rejects_replay(void) {
    mesh_mgmt_replay_gate_v1_t gate;
    mesh_mgmt_header_v1_t header;

    prepare_gate(&gate, 4u, 100u);
    prepare_header(&header, 10u, 0x51, 900u, 2000u);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_OK);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_REPLAYED);

    prepare_header(&header, 12u, 0x52, 900u, 2000u);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_OK);
    prepare_header(&header, 11u, 0x53, 900u, 2000u);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_REPLAYED);
    prepare_header(&header, 13u, 0x51, 900u, 2000u);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_REPLAYED);
    mesh_mgmt_replay_destroy_v1(&gate);
}

static void test_uses_rfc1982_wrap_and_session_binding(void) {
    mesh_mgmt_replay_gate_v1_t gate;
    mesh_mgmt_header_v1_t header;

    prepare_gate(&gate, 4u, 100u);
    prepare_header(&header, UINT64_MAX, 0x61, 900u, 2000u);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_OK);
    prepare_header(&header, 0u, 0x62, 900u, 2000u);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_OK);
    prepare_header(&header, 1u, 0x63, 900u, 2000u);
    header.incarnation++;
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_BINDING_MISMATCH);
    mesh_mgmt_replay_destroy_v1(&gate);
}

static void test_fails_closed_at_capacity_then_reuses_expired_slot(void) {
    mesh_mgmt_replay_gate_v1_t gate;
    mesh_mgmt_header_v1_t header;

    prepare_gate(&gate, 2u, 100u);
    prepare_header(&header, 1u, 0x71, 900u, 5000u);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_OK);
    prepare_header(&header, 2u, 0x72, 900u, 5000u);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_OK);
    prepare_header(&header, 3u, 0x73, 900u, 5000u);
    check_int_eq(prepare_and_commit(&gate, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_RESOURCE_EXHAUSTED);
    check_hex64_eq(gate.last_sequence, 2u);

    prepare_header(&header, 3u, 0x73, 900u, 5000u);
    check_int_eq(prepare_and_commit(&gate, &header, 1101u),
                 MESH_MGMT_REPLAY_OK);
    check_hex64_eq(gate.last_sequence, 3u);
    mesh_mgmt_replay_destroy_v1(&gate);
}

static void test_prepare_is_nonmutating_and_commit_rejects_stale_token(void) {
    mesh_mgmt_replay_gate_v1_t gate;
    mesh_mgmt_header_v1_t first;
    mesh_mgmt_header_v1_t second;
    mesh_mgmt_replay_preparation_v1_t first_preparation;
    mesh_mgmt_replay_preparation_v1_t second_preparation;

    prepare_gate(&gate, 2u, 100u);
    prepare_header(&first, 1u, 0x81, 900u, 2000u);
    prepare_header(&second, 2u, 0x82, 900u, 2000u);
    check_int_eq(mesh_mgmt_replay_prepare_v1(
                     &gate, &first, TEST_NOW_MS, &first_preparation),
                 MESH_MGMT_REPLAY_OK);
    check_false(gate.has_sequence);
    check_int_eq(mesh_mgmt_replay_prepare_v1(
                     &gate, &second, TEST_NOW_MS, &second_preparation),
                 MESH_MGMT_REPLAY_OK);
    check_int_eq(mesh_mgmt_replay_commit_v1(&gate, &first_preparation),
                 MESH_MGMT_REPLAY_OK);
    check_int_eq(mesh_mgmt_replay_commit_v1(&gate, &second_preparation),
                 MESH_MGMT_REPLAY_STALE_PREPARATION);
    check_hex64_eq(gate.last_sequence, 1u);
    mesh_mgmt_replay_destroy_v1(&gate);
}

static void test_checkpoint_round_trip_preserves_sequence_and_live_ids(void) {
    mesh_mgmt_replay_gate_v1_t source;
    mesh_mgmt_replay_gate_v1_t restored;
    mesh_mgmt_header_v1_t header;
    mesh_mgmt_replay_entry_v1_t entries[4];
    mesh_mgmt_replay_snapshot_v1_t snapshot;

    prepare_gate(&source, 4u, 100u);
    prepare_header(&header, 1u, 0x91, 900u, 5000u);
    check_int_eq(prepare_and_commit(&source, &header, 1000u),
                 MESH_MGMT_REPLAY_OK);
    prepare_header(&header, 2u, 0x92, 900u, 5000u);
    check_int_eq(prepare_and_commit(&source, &header, 1050u),
                 MESH_MGMT_REPLAY_OK);
    check_int_eq(mesh_mgmt_replay_export_v1(
                     &source, entries, 4u, &snapshot),
                 MESH_MGMT_REPLAY_OK);
    check_size_eq(snapshot.entry_count, 2u);

    prepare_gate(&restored, 4u, 100u);
    check_int_eq(mesh_mgmt_replay_import_v1(
                     &restored, &snapshot, entries, 1120u),
                 MESH_MGMT_REPLAY_OK);
    check_true(restored.has_sequence);
    check_hex64_eq(restored.last_sequence, 2u);
    check_true(restored.generation > snapshot.generation);
    check_true(restored.entries[0].occupied);
    check_false(restored.entries[1].occupied);
    prepare_header(&header, 2u, 0x93, 1100u, 2000u);
    check_int_eq(prepare_and_commit(&restored, &header, 1120u),
                 MESH_MGMT_REPLAY_REPLAYED);
    prepare_header(&header, 3u, 0x92, 1100u, 2000u);
    check_int_eq(prepare_and_commit(&restored, &header, 1120u),
                 MESH_MGMT_REPLAY_REPLAYED);
    prepare_header(&header, 3u, 0x94, 1100u, 2000u);
    check_int_eq(prepare_and_commit(&restored, &header, 1120u),
                 MESH_MGMT_REPLAY_OK);
    mesh_mgmt_replay_destroy_v1(&restored);
    mesh_mgmt_replay_destroy_v1(&source);
}

static void test_checkpoint_import_rejects_duplicate_ids_atomically(void) {
    mesh_mgmt_replay_gate_v1_t source;
    mesh_mgmt_replay_gate_v1_t restored;
    mesh_mgmt_header_v1_t header;
    mesh_mgmt_replay_entry_v1_t entries[2];
    mesh_mgmt_replay_snapshot_v1_t snapshot;

    prepare_gate(&source, 2u, 100u);
    prepare_header(&header, 1u, 0xa1, 900u, 5000u);
    check_int_eq(prepare_and_commit(&source, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_OK);
    prepare_header(&header, 2u, 0xa2, 900u, 5000u);
    check_int_eq(prepare_and_commit(&source, &header, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_OK);
    check_int_eq(mesh_mgmt_replay_export_v1(
                     &source, entries, 2u, &snapshot),
                 MESH_MGMT_REPLAY_OK);
    memcpy(entries[1].message_id, entries[0].message_id,
           sizeof(entries[1].message_id));
    prepare_gate(&restored, 2u, 100u);
    check_int_eq(mesh_mgmt_replay_import_v1(
                     &restored, &snapshot, entries, TEST_NOW_MS),
                 MESH_MGMT_REPLAY_INVALID_SCHEMA);
    check_false(restored.has_sequence);
    check_false(restored.entries[0].occupied);
    check_false(restored.entries[1].occupied);
    mesh_mgmt_replay_destroy_v1(&restored);
    mesh_mgmt_replay_destroy_v1(&source);
}

spec("mesh management replay gate") {
    describe("bounded per-session replay state") {
        it("accepts only newer sequences and unique message IDs") {
            test_accepts_newer_sequence_and_rejects_replay();
        }
        it("uses RFC 1982 wrap and rejects a changed session binding") {
            test_uses_rfc1982_wrap_and_session_binding();
        }
        it("does not evict live IDs when capacity is exhausted") {
            test_fails_closed_at_capacity_then_reuses_expired_slot();
        }
        it("does not mutate during prepare and rejects stale commits") {
            test_prepare_is_nonmutating_and_commit_rejects_stale_token();
        }
        it("restores sequence state and omits expired cached IDs") {
            test_checkpoint_round_trip_preserves_sequence_and_live_ids();
        }
        it("rejects duplicate checkpoint IDs without partial import") {
            test_checkpoint_import_rejects_duplicate_ids_atomically();
        }
    }
}

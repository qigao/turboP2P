#define TEST_SEND_BYTES (2 * 1024 * 1024)
#include "p2p_cnet_node_fixture.h"

enum { FILE_TEST_BYTES = P2P_DEFAULT_CHUNK_SIZE * 9 + 37, FILE_READ_BYTES = 4093 };
typedef struct {
    pair_t pair;
    char source[128], output[128], key[65];
    int completed, success, stop_on_complete;
    uint32_t transfer_id;
} file_fixture_t;

static void completed(p2p_transfer_t *transfer, int success, const char *error, void *context) {
    file_fixture_t *fixture = context;
    fixture->completed++;
    fixture->success = success;
    fixture->transfer_id = transfer->id;
    check_true(success ? error == NULL : error != NULL);
    check_true(transfer->manager->outstanding_refs > 0);
    if (fixture->stop_on_complete) {
        check_equal(P2P_ERR_INVALID_STATE, p2p_node_cnet_destroy(fixture->pair.client.owner));
        check_equal(P2P_OK, p2p_node_cnet_stop(fixture->pair.client.owner));
        fixture->pair.client.stopped = 1;
    }
}
static unsigned char file_byte(size_t offset) { return (unsigned char)(offset * 17 + offset / 251); }
static void setup_files(file_fixture_t *fixture, size_t bytes) {
    uint64_t stamp = salts_hrtime();
    snprintf(fixture->source, sizeof(fixture->source), "p2p-cnet-%llu-source.tmp", (unsigned long long)stamp);
    snprintf(fixture->output, sizeof(fixture->output), "p2p-cnet-%llu-output.tmp", (unsigned long long)stamp);
    FILE *source = fopen(fixture->source, "wbx");
    check_not_null(source);
    for (size_t i = 0; i < bytes; ++i) check_true(fputc(file_byte(i), source) != EOF);
    check_equal(0, fclose(source));
    FILE *output = fopen(fixture->output, "wbx");
    check_not_null(output);
    check_equal(0, fclose(output));
    setup(&fixture->pair, FILE_READ_BYTES, 0);
    connect_pair(&fixture->pair);
    wait_ready(&fixture->pair);
    check_equal(P2P_OK, p2p_put_file(fixture->pair.server.node, fixture->source, fixture->key));
}
static void start_download(file_fixture_t *fixture) {
    check_equal(P2P_OK, p2p_get_file_async(fixture->pair.client.node, fixture->key,
        fixture->output, completed, fixture));
}
static void wait_complete(file_fixture_t *fixture) {
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!fixture->completed && salts_monotonic_ms() < deadline) pump(&fixture->pair);
    check_equal(1, fixture->completed);
}
static void check_file(const char *path, size_t bytes) {
    FILE *file = fopen(path, "rb");
    check_not_null(file);
    for (size_t i = 0; i < bytes; ++i) check_equal((int)file_byte(i), fgetc(file));
    check_equal(EOF, fgetc(file));
    check_equal(0, fclose(file));
}
static void teardown_files(file_fixture_t *fixture) {
    teardown(&fixture->pair);
    check_equal(0, remove(fixture->source));
    check_equal(0, remove(fixture->output));
}
static void test_file_roundtrip(size_t bytes, int parallel) {
    file_fixture_t fixture = {0};
    setup_files(&fixture, bytes);
    start_download(&fixture);
    p2p_transfer_enable_parallel(fixture.pair.client.node->transfers->active, parallel);
    wait_complete(&fixture);
    check_equal(1, fixture.success);
    check_file(fixture.output, bytes);
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (fixture.pair.server.node->transfers->count && salts_monotonic_ms() < deadline)
        pump(&fixture.pair);
    check_equal(0u, fixture.pair.server.node->transfers->count);
    p2p_transfer_status_t status = {0};
    check_equal(P2P_OK, p2p_transfer_mgr_get_status(fixture.pair.client.node->transfers,
        fixture.transfer_id, &status));
    check_equal(P2P_TRANSFER_COMPLETED, status.state);
    check_equal(bytes, status.bytes_transferred);
    check_equal(bytes, status.file_size);
    check_equal(1, fixture.completed);
    check_not_null(fixture.pair.client.node->local_files);
    check_equal(0, strcmp(fixture.key, fixture.pair.client.node->local_files->hash));
    teardown_files(&fixture);
}
static void test_missing_file(void) {
    file_fixture_t fixture = {0};
    setup_files(&fixture, 0);
    memset(fixture.key, '0', sizeof(fixture.key) - 1);
    start_download(&fixture);
    wait_complete(&fixture);
    check_equal(0, fixture.success);
    check_file(fixture.output, 0);
    check_equal(0u, fixture.pair.server.node->transfers->count);
    teardown_files(&fixture);
}
static void test_changed_source(void) {
    file_fixture_t fixture = {0};
    setup_files(&fixture, FILE_READ_BYTES);
    /* Ordinary source mutation after registration must fail content validation. */
    FILE *source = fopen(fixture.source, "r+b");
    check_not_null(source);
    check_true(fputc(file_byte(0) ^ 1, source) != EOF);
    check_equal(0, fclose(source));
    start_download(&fixture);
    wait_complete(&fixture);
    check_equal(0, fixture.success);
    check_true(fixture.pair.client.node->local_files == NULL);
    teardown_files(&fixture);
}
static void test_completion_stop(void) {
    file_fixture_t fixture = {0};
    setup_files(&fixture, FILE_READ_BYTES);
    fixture.stop_on_complete = 1;
    start_download(&fixture);
    wait_complete(&fixture);
    check_equal(1, fixture.success);
    check_file(fixture.output, FILE_READ_BYTES);
    check_true(fixture.pair.client.node->transfers == NULL);
    check_true(fixture.pair.client.node->peers_table == NULL);
    teardown_files(&fixture);
}
static void test_pending_stop(void) {
    file_fixture_t fixture = {0};
    setup_files(&fixture, FILE_READ_BYTES);
    start_download(&fixture);
    check_equal(P2P_OK, p2p_node_cnet_stop(fixture.pair.client.owner));
    check_true(fixture.pair.client.node->transfers == NULL);
    check_equal(0, fixture.completed);
    teardown_files(&fixture);
}
static void test_live_transfer_lease(void) {
    file_fixture_t fixture = {0};
    setup_files(&fixture, FILE_READ_BYTES);
    start_download(&fixture);
    p2p_transfer_manager_t *manager = fixture.pair.client.node->transfers;
    p2p_transfer_t *lease = p2p_transfer_find_by_id(manager, manager->active->id);
    check_not_null(lease);
    p2p_transfer_destroy(manager, lease);
    check_equal(0u, manager->count);
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_cnet_destroy(fixture.pair.client.owner));
    check_true(fixture.pair.client.node->transfers == manager);
    check_true(fixture.pair.client.node->network_context == fixture.pair.client.owner);
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_state_destroy(fixture.pair.client.node));
    check_true(p2p_transfer_create(manager, P2P_TRANSFER_DIR_DOWNLOAD) == NULL);
    check_true(p2p_transfer_find_by_id(manager, lease->id) == NULL);
    check_equal((size_t)1, manager->outstanding_refs);
    p2p_transfer_release(lease);
    check_equal((size_t)0, manager->outstanding_refs);
    teardown_files(&fixture);
}
static void test_peer_disconnect(void) {
    file_fixture_t fixture = {0};
    setup_files(&fixture, FILE_TEST_BYTES);
    start_download(&fixture);
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!fixture.pair.server.node->transfers->count && salts_monotonic_ms() < deadline)
        pump(&fixture.pair);
    check_equal(1u, fixture.pair.server.node->transfers->count);
    p2p_peer_t *peer = fixture.pair.server.peer;
    check_true(fixture.pair.server.node->transfers->active->held_peers[0] == peer);
    p2p_peer_disconnect(peer);
    check_equal(P2P_OK, p2p_node_cnet_poll(fixture.pair.server.owner));
    check_true(peer->destroying);
    check_true(peer->callback_refs > 0);
    check_true(fixture.pair.server.node->peers_table == NULL);
    teardown_files(&fixture);
}

#ifdef P2P_FILES_TEST_WRAP
static int fail_chunk_request_at, chunk_request_calls;
int __real_p2p_peer_send(p2p_peer_t *, const p2p_message_t *);
int __wrap_p2p_peer_send(p2p_peer_t *peer, const p2p_message_t *message) {
    if (fail_chunk_request_at && message->header.type == P2P_MSG_CHUNK_REQUEST &&
        ++chunk_request_calls == fail_chunk_request_at)
        return P2P_ERR_RESOURCE_EXHAUSTED;
    return __real_p2p_peer_send(peer, message);
}
static void test_request_backpressure(void) {
    file_fixture_t fixture = {0};
    setup_files(&fixture, FILE_TEST_BYTES);
    chunk_request_calls = 0;
    fail_chunk_request_at = 2;
    start_download(&fixture);
    wait_complete(&fixture);
    fail_chunk_request_at = 0;
    check_equal(0, fixture.success);
    check_equal(2, chunk_request_calls);
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (fixture.pair.server.node->transfers->count && salts_monotonic_ms() < deadline)
        pump(&fixture.pair);
    check_equal(0u, fixture.pair.server.node->transfers->count);
    check_equal(1, fixture.completed);
    teardown_files(&fixture);
}
#endif

spec("P2P file transfer over production CNet nodes") {
    it("downloads and seeds nine chunks plus a tail through fragmented CNet reads") { test_file_roundtrip(FILE_TEST_BYTES, 0); }
    it("reuses in-flight slots across parallel request windows and releases uploads on ACK") { test_file_roundtrip(FILE_TEST_BYTES, 1); }
    it("transfers an empty object with the existing one-chunk wire convention") { test_file_roundtrip(0, 0); }
    it("reports an unavailable object once without writing the destination") { test_missing_file(); }
    it("rejects source content changed after registration without seeding it") { test_changed_source(); }
    it("defers stop from file completion until the handler releases its transfer") { test_completion_stop(); }
    it("closes pending transfers before releasing their peers") { test_pending_stop(); }
    it("retains manager and node until a detached transfer lease is released") { test_live_transfer_lease(); }
    it("keeps an upload peer alive after disconnect until transfer teardown") { test_peer_disconnect(); }
#ifdef P2P_FILES_TEST_WRAP
    it("reports request backpressure once and releases the upload through a negative ACK") { test_request_backpressure(); }
#endif
}

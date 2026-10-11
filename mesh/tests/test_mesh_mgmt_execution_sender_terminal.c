#include <tinytest.h>

#include "mesh_mgmt_execution_sender.h"
#include "mesh_mgmt_execution_wire.h"

#include <string.h>

/* Deliberate transport-terminal fault injector. Sender, SPSC Egress,
 * canonical STATUS wire codec and typed identity contract are PRODUCTION
 * code. Only the native callback dispatch is controlled here to force
 * branches that are timing-dependent on a real physical TCP close.
 * The real 2/4 SG Final native-success integration is tested separately. */
typedef struct {
  mesh_mgmt_execution_egress_v1_t egress;
  mesh_mgmt_execution_sender_pending_v5_t sender;
  mesh_mgmt_agent_runtime_v1_t runtime;
  mesh_mgmt_peer_signer_config_v1_t signer;
  unsigned admissions;
  uint64_t next_ticket;
  uint8_t reject;
  mesh_mgmt_agent_command_terminal_fn_v4 complete;
  void *complete_context;
  uint64_t callback_ticket;
  uint8_t last_kind;
  uint8_t last_target[32];
} sender_terminal_fixture_t;

static sender_terminal_fixture_t *active_fixture;

/* A rejected native admission MUST NOT call complete. An accepted send is
 * retained until the test drives an explicit real-shape P2P terminal. */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_send_execution_response_terminal_v5(
    mesh_mgmt_agent_runtime_v1_t *runtime, uint8_t kind,
    const uint8_t target_node_id[32],
    const uint8_t *payload, size_t payload_len,
    mesh_mgmt_agent_command_terminal_fn_v4 complete,
    void *context, uint64_t *out_ticket) {
  sender_terminal_fixture_t *fixture = active_fixture;
  if (out_ticket) *out_ticket = 0u;
  if (!fixture || runtime != &fixture->runtime || !target_node_id ||
      !payload || payload_len == 0u || !complete || !out_ticket)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  ++fixture->admissions;
  fixture->last_kind = kind;
  memcpy(fixture->last_target, target_node_id,
         sizeof(fixture->last_target));
  if (fixture->reject)
    return MESH_MGMT_AGENT_RUNTIME_SEND_FAILED;
  fixture->complete = complete;
  fixture->complete_context = context;
  fixture->callback_ticket = ++fixture->next_ticket;
  *out_ticket = fixture->callback_ticket;
  return MESH_MGMT_AGENT_RUNTIME_OK;
}

static void fixture_init(sender_terminal_fixture_t *fixture) {
  mesh_mgmt_execution_shadow_command_v1_t command = {0};
  mesh_mgmt_execution_result_v1_t result = {0};
  memset(fixture, 0, sizeof(*fixture));
  memset(fixture->signer.hello.managed_node_id, 0x31,
         sizeof(fixture->signer.hello.managed_node_id));
  fixture->runtime.router.signer_template = &fixture->signer;
  memset(command.reply_node_id, 0x41, sizeof(command.reply_node_id));
  memset(command.request.command_id, 0x51,
         sizeof(command.request.command_id));
  memset(command.request.correlation_id, 0x61,
         sizeof(command.request.correlation_id));
  memset(command.request_digest, 0x71,
         sizeof(command.request_digest));
  memcpy(command.grant.target_node_id,
         fixture->signer.hello.managed_node_id,
         sizeof(command.grant.target_node_id));
  check_equal(MESH_MGMT_EXECUTION_EGRESS_OK,
      mesh_mgmt_execution_egress_init_v1(&fixture->egress, 2u));
  check_equal(MESH_MGMT_EXECUTION_EGRESS_OK,
      mesh_mgmt_execution_egress_try_push_v1(
          &fixture->egress, &command, MESH_MGMT_EXECUTION_SERVICE_BUSY,
          NULL, 0u, &result));
  active_fixture = fixture;
}

static void fixture_close(sender_terminal_fixture_t *fixture,
                          int explicit_reconciled_failure) {
  mesh_mgmt_execution_egress_stats_v1_t stats = {0};
  check_equal(MESH_MGMT_EXECUTION_EGRESS_OK,
      mesh_mgmt_execution_egress_get_stats_v1(&fixture->egress, &stats));
  if (explicit_reconciled_failure) {
    /* Test owner explicitly reconciles the failed send and discards its
     * head only AFTER checking that the no-retry failure was observable.
     * Production never silently does this inside a send callback. */
    check_equal((size_t)1u, stats.pending);
    check_equal(MESH_MGMT_EXECUTION_EGRESS_OK,
        mesh_mgmt_execution_egress_consume_v1(&fixture->egress));
  } else {
    check_equal((size_t)0u, stats.pending);
  }
  check_equal(MESH_MGMT_EXECUTION_EGRESS_OK,
      mesh_mgmt_execution_egress_close_v1(&fixture->egress));
  mesh_mgmt_execution_egress_destroy_v1(&fixture->egress);
  active_fixture = NULL;
}

/* Admission is NOT a terminal, and a doubled native completion cannot
 * release a second head or generate a second callback ticket. */
static void test_one_wire_terminal_commits_once(void) {
  sender_terminal_fixture_t fixture;
  mesh_mgmt_execution_egress_stats_v1_t stats = {0};
  fixture_init(&fixture);
  check_equal(MESH_MGMT_EXECUTION_SENDER_IN_FLIGHT,
      mesh_mgmt_execution_sender_send_next_runtime_v5(
          &fixture.sender, &fixture.egress, &fixture.runtime));
  check_equal((unsigned)1u, fixture.admissions);
  check_equal(MESH_MGMT_KIND_COMMAND_STATUS, fixture.last_kind);
  check_equal(MESH_MGMT_EXECUTION_SEND_IN_FLIGHT, fixture.sender.state);
  check_equal(MESH_MGMT_EXECUTION_SENDER_IN_FLIGHT,
      mesh_mgmt_execution_sender_send_next_runtime_v5(
          &fixture.sender, &fixture.egress, &fixture.runtime));
  check_equal((unsigned)1u, fixture.admissions);
  check_equal(MESH_MGMT_EXECUTION_EGRESS_OK,
      mesh_mgmt_execution_egress_get_stats_v1(&fixture.egress, &stats));
  check_equal((size_t)1u, stats.pending);
  check_equal((uint64_t)0u, stats.consumed);

  check_not_null(fixture.complete);
  fixture.complete(fixture.complete_context, fixture.callback_ticket, P2P_OK);
  check_equal(MESH_MGMT_EXECUTION_SEND_WIRE_OK, fixture.sender.state);
  fixture.complete(fixture.complete_context, fixture.callback_ticket, P2P_OK);
  check_equal(MESH_MGMT_EXECUTION_SEND_WIRE_OK, fixture.sender.state);
  check_equal(MESH_MGMT_EXECUTION_EGRESS_OK,
      mesh_mgmt_execution_egress_get_stats_v1(&fixture.egress, &stats));
  check_equal((size_t)1u, stats.pending); /* no callback-side commit */

  check_equal(MESH_MGMT_EXECUTION_SENDER_OK,
      mesh_mgmt_execution_sender_send_next_runtime_v5(
          &fixture.sender, &fixture.egress, &fixture.runtime));
  check_equal(MESH_MGMT_EXECUTION_SEND_IDLE, fixture.sender.state);
  check_equal(P2P_OK, fixture.sender.terminal_status);
  check_equal((uint64_t)1u, fixture.sender.last_terminal_ticket);
  check_equal(MESH_MGMT_EXECUTION_SENDER_EMPTY,
      mesh_mgmt_execution_sender_send_next_runtime_v5(
          &fixture.sender, &fixture.egress, &fixture.runtime));
  check_equal((unsigned)1u, fixture.admissions);
  fixture_close(&fixture, 0);
}

/* The native terminal may report a failed encrypted write AFTER admission.
 * It MUST preserve Egress and fail closed across repeated owner turns. */
static void test_wire_failure_is_sticky_without_replay(void) {
  sender_terminal_fixture_t fixture;
  fixture_init(&fixture);
  check_equal(MESH_MGMT_EXECUTION_SENDER_IN_FLIGHT,
      mesh_mgmt_execution_sender_send_next_runtime_v5(
          &fixture.sender, &fixture.egress, &fixture.runtime));
  fixture.complete(fixture.complete_context, fixture.callback_ticket,
                   P2P_ERR_NETWORK);
  check_equal(MESH_MGMT_EXECUTION_SEND_WIRE_FAILED, fixture.sender.state);
  check_equal(P2P_ERR_NETWORK, fixture.sender.terminal_status);
  for (unsigned i = 0u; i < 3u; ++i)
    check_equal(MESH_MGMT_EXECUTION_SENDER_TERMINAL_FAILED,
        mesh_mgmt_execution_sender_send_next_runtime_v5(
            &fixture.sender, &fixture.egress, &fixture.runtime));
  check_equal((unsigned)1u, fixture.admissions);
  fixture_close(&fixture, 1);
}

static void test_rejected_admission_retains_egress(void) {
  sender_terminal_fixture_t fixture;
  fixture_init(&fixture);
  fixture.reject = 1u;
  check_equal(MESH_MGMT_EXECUTION_SENDER_SEND_FAILED,
      mesh_mgmt_execution_sender_send_next_runtime_v5(
          &fixture.sender, &fixture.egress, &fixture.runtime));
  check_equal(MESH_MGMT_EXECUTION_SEND_ADMISSION_FAILED,
              fixture.sender.state);
  check_true(fixture.complete == NULL); /* no native callback on rejection */
  for (unsigned i = 0u; i < 3u; ++i)
    check_equal(MESH_MGMT_EXECUTION_SENDER_SEND_FAILED,
        mesh_mgmt_execution_sender_send_next_runtime_v5(
            &fixture.sender, &fixture.egress, &fixture.runtime));
  check_equal((unsigned)1u, fixture.admissions);
  fixture_close(&fixture, 1);
}

static void test_stale_terminal_ticket_is_denied(void) {
  sender_terminal_fixture_t fixture;
  fixture_init(&fixture);
  check_equal(MESH_MGMT_EXECUTION_SENDER_IN_FLIGHT,
      mesh_mgmt_execution_sender_send_next_runtime_v5(
          &fixture.sender, &fixture.egress, &fixture.runtime));
  fixture.complete(fixture.complete_context,
                   fixture.callback_ticket + 1u, P2P_OK);
  check_equal(MESH_MGMT_EXECUTION_SEND_WIRE_FAILED, fixture.sender.state);
  check_equal(P2P_ERR_INVALID_STATE, fixture.sender.terminal_status);
  check_equal(MESH_MGMT_EXECUTION_SENDER_TERMINAL_FAILED,
      mesh_mgmt_execution_sender_send_next_runtime_v5(
          &fixture.sender, &fixture.egress, &fixture.runtime));
  check_equal((unsigned)1u, fixture.admissions);
  fixture_close(&fixture, 1);
}

spec("execution RESULT native send terminal state and failure contracts") {
  it("retains one Egress head through admission and full-wire terminal") {
    test_one_wire_terminal_commits_once();
  }
  it("does not replay a native failed RESULT generation") {
    test_wire_failure_is_sticky_without_replay();
  }
  it("does not replay a rejected encrypted send admission") {
    test_rejected_admission_retains_egress();
  }
  it("rejects a stale native terminal ticket without consuming a result") {
    test_stale_terminal_ticket_is_denied();
  }
}

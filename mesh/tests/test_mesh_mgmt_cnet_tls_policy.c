#include "mesh_stream_cnet_fixture.h"
#include "mesh_mgmt_cnet_peer.h"

static int count_event(void *context, const mesh_mgmt_dispatch_event_v1_t *event) {
  size_t *count = context;
  (void)event;
  ++*count;
  return 0;
}

spec("management CNet negotiated TLS policy") {
  it("rejects a real verified TLS 1.2 channel before signing or sending MMP") {
    test_pair_t pair;
    mesh_mgmt_cnet_peer_v1_t owner = {0};
    mesh_mgmt_cnet_peer_config_v1_t config = {0};
    char version[16] = {0};
    size_t length = 0u;
    size_t events = 0u;
    init_pair(&pair, TEST_OPENSSL_TLS12);
    check_equal(cnet_tls_negotiated_version(&pair.receiver.client, pair.receiver.connection,
                    version, sizeof(version), &length), SALTS_OK);
    check_equal(version, "TLSv1.2");
    config.on_event = count_event;
    config.event_context = &events;
    check_equal(mesh_mgmt_cnet_peer_init_v1(&owner, &pair.receiver.client,
                    pair.receiver.connection, &config), MESH_MGMT_PEER_CONNECTION_FAILED);
    check_equal(owner.last_cnet_status, SALTS_ENOTSUP);
    check_false(owner.initialized);
    check_equal(owner.signer.state, MESH_MGMT_PEER_SIGNER_UNINITIALIZED);
    check_equal(events, 0u);
    destroy_pair(&pair);
  }
}

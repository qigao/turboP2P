/* Two CNet owners: no raw socket, native submit, or separate event-loop path. */
#include <cnet/cnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MESSAGE_BOUND = 256, POLL_MS = 10, MAX_POLLS = 500, STOP_MS = 5000 };
static const unsigned char payload[] = {0x70, 0x32, 0x70, 0x00, 0xff};
static const uint64_t send_tag = UINT64_C(0x1020304050607080);

typedef struct probe {
  unsigned char bytes[MESSAGE_BOUND];
  size_t size;
  cnet_datagram_peer peer;
  unsigned receives;
  unsigned sends;
  uint64_t tag;
  int status;
  int invalid;
} probe;

static void received(void *user, cnet_datagram *owner, const cnet_datagram_peer *peer,
                     const cnet_receive_view *view) {
  probe *p = user;
  (void)owner;
  if (!peer || !view || view->kind != CNET_MESSAGE_DATAGRAM ||
      view->size > sizeof(p->bytes) || (view->size && !view->data)) {
    p->invalid = 1;
    return;
  }
  p->peer = *peer;
  p->size = view->size;
  if (view->size) memcpy(p->bytes, view->data, view->size);
  ++p->receives;
}

static void sent(void *user, cnet_datagram *owner, const cnet_datagram_peer *peer,
                 size_t size, int status, uint64_t tag) {
  probe *p = user;
  (void)owner;
  if (!peer || size != sizeof(payload)) p->invalid = 1;
  p->status = status;
  p->tag = tag;
  ++p->sends;
}

static cnet_datagram_config config_for(probe *p) {
  cnet_datagram_config config = CNET_DATAGRAM_CONFIG_INIT;
#if defined(_WIN32)
  config.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
  config.backend = NATIVE_IO_BACKEND_EPOLL;
#else
#error "This qualification covers Linux and Windows only"
#endif
  config.host = "127.0.0.1";
  config.send_capacity = 1;
  config.request_capacity = 2;
  config.completion_batch_capacity = 2;
  config.max_datagram_bytes = MESSAGE_BOUND;
  config.receive_buffer_bytes = MESSAGE_BOUND;
  config.observer.on_receive = received;
  config.observer.on_send = sent;
  config.observer.user = p;
  return config;
}

static int drain(cnet_datagram *owner) {
  int status;
  if (!owner->impl) return SALTS_OK;
  status = cnet_datagram_stop(owner, STOP_MS);
  if (status != SALTS_OK) return status;
  return cnet_datagram_destroy(owner);
}

#define REQUIRE(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "CNet SDK contract failed at line %d: %s\n", __LINE__, #condition); \
    goto done; \
  } \
} while (0)

int main(void) {
  cnet_datagram a = {0}, b = {0};
  probe pa = {0}, pb = {0};
  cnet_datagram_config ca = config_for(&pa), cb = config_for(&pb);
  cnet_datagram_peer peer = {0};
  unsigned char copied[sizeof(payload)];
  uint16_t a_port = 0, b_port = 0;
  size_t events = 0;
  int result = EXIT_FAILURE;
  int cleanup_a, cleanup_b;

  /* Invalid bounds must not publish a partially live owner. */
  ca.send_capacity = 0;
  REQUIRE(cnet_datagram_init(&a, &ca) == SALTS_EINVAL);
  REQUIRE(a.impl == NULL);
  ca = config_for(&pa);
  REQUIRE(cnet_datagram_init(&a, &ca) == SALTS_OK);
  REQUIRE(cnet_datagram_init(&b, &cb) == SALTS_OK);
  REQUIRE(cnet_datagram_port(&a, &a_port) == SALTS_OK && a_port != 0);
  REQUIRE(cnet_datagram_port(&b, &b_port) == SALTS_OK && b_port != 0);
  peer.family = CNET_DATAGRAM_ADDRESS_IPV4;
  peer.address[0] = 127;
  peer.address[3] = 1;
  peer.port = b_port;
  REQUIRE(cnet_datagram_receive(&b, 1) == SALTS_OK);
  memcpy(copied, payload, sizeof(payload));
  REQUIRE(cnet_datagram_send(&a, &peer, copied, sizeof(copied), send_tag) == SALTS_OK);
  memset(copied, 0, sizeof(copied));
  /* The single send slot remains occupied until terminal dispatch. */
  REQUIRE(cnet_datagram_send(&a, &peer, payload, sizeof(payload), send_tag + 1) == SALTS_ENOBUFS);
  for (unsigned i = 0; i < MAX_POLLS && (!pa.sends || !pb.receives); ++i) {
    REQUIRE(cnet_datagram_poll(&a, POLL_MS, &events) == SALTS_OK);
    REQUIRE(cnet_datagram_poll(&b, POLL_MS, &events) == SALTS_OK);
  }
  REQUIRE(pa.sends == 1 && pa.status == SALTS_OK && pa.tag == send_tag);
  REQUIRE(pb.receives == 1 && pb.size == sizeof(payload));
  REQUIRE(memcmp(pb.bytes, payload, sizeof(payload)) == 0);
  REQUIRE(pb.peer.port == a_port && pb.peer.family == CNET_DATAGRAM_ADDRESS_IPV4);
  REQUIRE(pb.peer.address[0] == 127 && pb.peer.address[1] == 0 &&
          pb.peer.address[2] == 0 && pb.peer.address[3] == 1);
  REQUIRE(!pa.invalid && !pb.invalid);
  result = EXIT_SUCCESS;
done:
  cleanup_b = drain(&b);
  cleanup_a = drain(&a);
  if (cleanup_a != SALTS_OK || cleanup_b != SALTS_OK) {
    fprintf(stderr, "CNet drain failed: %d / %d\n", cleanup_a, cleanup_b);
    result = EXIT_FAILURE;
  }
  if (pa.sends > 1) result = EXIT_FAILURE;
  if (result == EXIT_SUCCESS) puts("CNet-only UDP ownership/backpressure/terminal smoke passed");
  return result;
}

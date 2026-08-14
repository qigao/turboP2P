# TurboNet P2P Library

A peer-to-peer networking library built on a Kademlia DHT, running over the
TurboNet CoroNet transport. This is the data-plane library used by the mesh
module (`mesh/`); for the overlay-VPN product behavior see `mesh/MESH_STATUS.md`.

## Features

- **Kademlia DHT**: iterative lookup, k-buckets, request-id based lookups, value
  replication across connected/discovered peers
- **Chunked file transfer**: put/get with hash keys, async download with chunk
  requests, resume support
- **Pub/Sub messaging**: topic-based publish/subscribe routed through the node
- **Authenticated transport**: Noise
  `XX_25519_ChaChaPoly_BLAKE2s`, transcript-bound credentials, encrypted READY
  confirmation and bounded CipherState counters
- **Vivaldi coordinates**: decentralized latency estimation

## Security status (important)

Secure wire v2 is a hard protocol cutover: listeners refuse to start without an
identity policy, peers are not published before Noise XX, credential validation
and bilateral encrypted READY complete, and there is no legacy fallback. Raw
P2P supports an explicit static-key allowlist; Mesh management uses its signed
node certificate to bind the Noise X25519 key to the management principal,
managed node, mesh, roles, validity window and trust epoch.
Raw P2P can replace its copied pin set and evict no-longer-trusted sessions with
the owner-thread command `p2p_node_update_pinned_trust_v2()`.

Transport memory admission is bounded twice: CoroNet rejects a stream above its
configured send HWM (1 MiB by default), while P2P reserves that HWM against a
64 MiB node budget before retaining each inbound or outbound transport. Use
`p2p_node_get_security_status_v3()` to read one node-atomic value snapshot of
the conservative reservation, available capacity, active transport count,
typed rejection counters, optional blocking-key executor, and fixed
initiator/responder handshake-latency histograms. The v2 capacity getter and
V4 executor getter remain available unchanged for existing consumers. These
snapshots contain no key, credential, peer identity, address, channel binding,
or per-handshake sample data.
Inbound accepts also pass a fixed-capacity token bucket keyed by IPv4 `/32` or
IPv6 `/64` (default burst 16, refill 4/second, at most 256 source buckets).
Before allocating a peer, receive buffer, Noise state or full send-budget
reservation, the listener uses one of 128 fixed lightweight gate slots to
validate a source-IP-bound HMAC cookie. Cookie keys rotate every five minutes,
current/previous 10-second buckets are accepted, and the verified cookie is
included in the Noise prologue.

After an identity provider installs a newer trust snapshot on the CoroNet owner
thread, call `p2p_node_revalidate_security_v2()`. Existing credentials are
verified again without holding the node mutex; rejected or identity-changing
sessions are disconnected and must complete a fresh Noise handshake. The Mesh
provider updates its bounded remote epoch/role/revocation snapshot with
`mesh_mgmt_p2p_security_provider_update_remote_trust_v2()`. Dedicated Mesh
management runtimes should instead use
`mesh_mgmt_agent_runtime_update_remote_trust_v2()`, which performs update and
revalidation as one owner-thread command and fails closed on revalidation
resource failure.

The implementation is a security baseline, not yet a completed production
security audit. The versioned `p2p_private_key_provider_v3_t` boundary keeps
static private-key bytes out of the node and Noise-C, but its callbacks are
synchronous on the CoroNet owner thread and may only target non-blocking,
bounded-time key services. Blocking providers use the separate
`p2p_blocking_private_key_provider_v4_t`: the complete outgoing Noise message
that needs static DH runs on a bounded worker executor with an absolute
deadline, cancellation, capacity rejection, shutdown drain, and a read-only
status snapshot. Application protocol version 2 now uses explicit canonical
big-endian codecs for PING/PONG, DHT, file/chunk transfer and raw/custom
payloads; native C struct padding is not transmitted. Official interoperability
testing, continuous fuzzing, concrete OS/TPM/HSM adapters, key-rotation
operations and an independent review remain release gates. The exact
implemented/remaining matrix is in
[`NOISE_IDENTITY_DESIGN.md`](NOISE_IDENTITY_DESIGN.md).
部署、信任更新、撤销、身份轮换、告警和回滚流程见
[`SECURITY_OPERATIONS.md`](SECURITY_OPERATIONS.md)。

## Building

```bash
cmake -B build -G Ninja
cmake --build build --target p2p

# Run the P2P unit/integration tests
cmake --build build --target test_p2p
./build/bin/test_p2p
```

Linux security builds have dedicated `security-linux-clang-asan`,
`security-linux-clang-tsan`, and `security-linux-clang-fuzz` configure presets.
Their exact dependency contract, build/test presets, fuzz limits, corpus and
artifact commands are documented in
[`NOISE_IDENTITY_DESIGN.md`](NOISE_IDENTITY_DESIGN.md).

## Quick Start

```c
#include <p2p.h>
#include <stdio.h>

static void on_message(p2p_node_t *node, p2p_peer_t *peer,
                       const void *data, size_t len, void *user_data) {
    (void)node; (void)peer; (void)user_data;
    fwrite(data, 1, len, stdout);
}

int main(void) {
    static const uint8_t network_id[P2P_SECURITY_ID_SIZE] = {
        0x74, 0x75, 0x72, 0x62, 0x6f, 0x2d, 0x70, 0x32,
        0x70, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2d, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
        0x6b, 0x2d, 0x76, 0x32, 0x2d, 0x30, 0x30, 0x31,
    };
    p2p_node_t *node = p2p_create("0.0.0.0", 8000);
    uint8_t local_public_key[P2P_KEY_SIZE];
    if (!node) return 1;

    /* A real deployment loads a stable private key first and supplies every
       authorized peer public key, not only this local demonstration key. */
    if (p2p_node_get_public_key(node, local_public_key) != P2P_OK ||
        p2p_node_configure_pinned_security_v2(
            node, network_id, local_public_key, 1) != P2P_OK) {
        p2p_destroy(node);
        return 1;
    }
    p2p_set_message_handler(node, on_message, NULL);
    if (p2p_start(node) != P2P_OK) {   /* blocking event loop */
        p2p_destroy(node);
        return 1;
    }

    /* on another node, connect to a bootstrap peer */
    /* p2p_connect(node, "192.168.1.100", 8000); */

    p2p_destroy(node);
    return 0;
}
```

For a custom event loop (non-blocking), use `p2p_start_nonblocking()` plus
`p2p_get_loop()` and drive it with `coro_context_run()` — the mesh module does
exactly this from `mesh_poll()`.

## DHT

```c
uint8_t value[] = "hello";
p2p_dht_put(node, "key", value, sizeof(value));      /* replicated */

uint8_t buf[256];
size_t len = sizeof(buf);
if (p2p_dht_get(node, "key", buf, &len) == P2P_OK) {
    /* buf now holds the value; note p2p_dht_get does not NUL-terminate */
}
```

`p2p_dht_get()` is a synchronous network lookup; `p2p_dht_get_cached()` reads
only the local store. `p2p_dht_put_cached()` writes only the local store.

## File Sharing

```c
char key[65];
p2p_put_file(node, "/path/to/file.bin", key);        /* key = content hash */

p2p_get_file_async(node, key, "out.bin", on_done, NULL);
void on_done(p2p_node_t *node, const char *key, const char *path,
             int success, void *user_data) { ... }

/* synchronous variant: */
/* p2p_get_file(node, key, "out.bin"); */
```

## Messaging & Pub/Sub

```c
p2p_set_message_handler(node, on_message, NULL);     /* receives P2P_MSG_CUSTOM */
p2p_send(node, peer, data, len);                     /* unicast */
p2p_broadcast(node, data, len);                      /* to all peers */

p2p_subscribe(node, "chat/room1");                   /* join topic */
p2p_publish(node, "chat/room1", msg, strlen(msg));
p2p_unsubscribe(node, "chat/room1");
```

## Error Handling

```c
int ret = p2p_dht_put(node, "k", v, sizeof(v));
if (ret != P2P_OK) {
    printf("Error: %s\n", p2p_error_str(ret));
}
```

| Code | Description |
|------|-------------|
| `P2P_OK` | Success |
| `P2P_ERR_INVALID_ARG` | Invalid argument |
| `P2P_ERR_NO_MEM` | Memory allocation failed |
| `P2P_ERR_NETWORK` | Network error |
| `P2P_ERR_TIMEOUT` | Operation timed out |
| `P2P_ERR_NOT_FOUND` | Resource not found |
| `P2P_ERR_IO` | I/O error |
| `P2P_ERR_INVALID_STATE` | Invalid state for operation |
| `P2P_ERR_CRYPTO` | Cryptographic operation failed |
| `P2P_ERR_KEY_EXHAUSTED` | Session frame, age, or encrypted-byte limit reached; reconnect required |
| `P2P_ERR_PROTOCOL` | Protocol error |
| `P2P_ERR_INVALID` | Generic invalid value |
| `P2P_ERR_AUTH_REQUIRED` | Secure identity policy is not configured |
| `P2P_ERR_UNTRUSTED_IDENTITY` | Credential, pin, role, epoch or binding was rejected |
| `P2P_ERR_RESOURCE_EXHAUSTED` | A bounded security or peer resource is full |

## Layout

```
p2p/
├── include/           # Public API header (p2p.h)
├── src/
│   ├── api/           # Public API implementation
│   ├── cache/         # Local cache
│   ├── core/          # Node, peer, connection, peer table, Vivaldi
│   ├── crypto/        # Project cryptographic facade
│   ├── security/      # Opaque Noise-C backend and platform adapter
│   ├── dht/           # Kademlia DHT + RPC
│   ├── protocol/      # Message serialization and handlers
│   └── transfer/      # Chunked file transfer, bitmap, resume
├── examples/          # Standalone examples
└── tests/             # Unit and integration tests
```

## Dependencies

- **TurboUtils::Core** — utilities, logging, secure random
- **TurboNet::CoroNet** — event loop and stream transport
- **Noise-C** — pinned standard Noise handshake/CipherState implementation
- **TurboNet::Crypto** — operating-system CSPRNG, X25519 platform backend,
  SHA-256 and secure wipe
- **OpenSSL** — SHA-256 for DHT key/id derivation
- **vendor/** — roaring (bitmap), uthash (hash tables)

Third-party source and license details are recorded in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## License

See the LICENSE file in the repository root.

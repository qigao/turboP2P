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
- **Transport encryption**: X25519 + XChaCha20-Poly1305 AEAD, BLAKE2b key
  derivation, per-session nonce counters
- **Vivaldi coordinates**: decentralized latency estimation

## Security status (important)

The transport uses an **experimental, simplified Noise-like handshake**, not the
standard Noise Protocol:

- Handshake messages carry the ephemeral public key and an optional static
  public key **in plaintext**.
- Session keys are derived from `X25519(ephemeral)` plus `X25519(static)`
  via BLAKE2b, with per-direction labels.
- There is **no signature binding the static key to the session and no key
  confirmation message**. An active man-in-the-middle can substitute its own
  static keys, so the handshake provides **confidentiality but not identity
  authentication**.

Do not rely on this handshake for production-grade peer authentication until it
is migrated to a standard Noise `XX` (or `KK`) pattern with transcript binding
and signed static keys. `mesh/MESH_STATUS.md` applies the same caveat to the
mesh stream admission gate.

## Building

```bash
cmake -B build -G Ninja
cmake --build build --target p2p

# Run the P2P unit/integration tests
cmake --build build --target test_p2p
./build/bin/test_p2p
```

## Quick Start

```c
#include <p2p.h>

int main(void) {
    p2p_node_t *node = p2p_create("0.0.0.0", 8000);
    if (!node) return 1;

    p2p_set_message_handler(node, on_message, NULL);
    p2p_start(node);                    /* blocking event loop */

    /* on another node, connect to a bootstrap peer */
    /* p2p_connect(node, "192.168.1.100", 8000); */

    p2p_destroy(node);
    return 0;
}

void on_message(p2p_node_t *node, p2p_peer_t *peer,
                const void *data, size_t len, void *user_data) {
    (void)node; (void)peer; (void)user_data;
    fwrite(data, 1, len, stdout);
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
| `P2P_ERR_PROTOCOL` | Protocol error |
| `P2P_ERR_INVALID` | Generic invalid value |

## Layout

```
p2p/
├── include/           # Public API header (p2p.h)
├── src/
│   ├── api/           # Public API implementation
│   ├── cache/         # Local cache
│   ├── core/          # Node, peer, connection, peer table, Vivaldi
│   ├── crypto/        # Transport encryption and handshake
│   ├── dht/           # Kademlia DHT + RPC
│   ├── protocol/      # Message serialization and handlers
│   └── transfer/      # Chunked file transfer, bitmap, resume
├── examples/          # Standalone examples
└── tests/             # Unit and integration tests
```

## Dependencies

- **TurboUtils::Core** — utilities, logging, secure random
- **TurboNet::CoroNet** — event loop and stream transport
- **TurboNet::Crypto** — X25519, XChaCha20-Poly1305 AEAD, BLAKE2b
- **OpenSSL** — SHA-256 for DHT key/id derivation
- **vendor/** — roaring (bitmap), uthash (hash tables)

## License

See the LICENSE file in the repository root.

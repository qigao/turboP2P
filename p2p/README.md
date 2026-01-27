# TurboNet P2P Library

A high-performance, feature-rich peer-to-peer networking library built on Chord DHT protocol.

## Features

- **Chord DHT**: O(log n) routing with finger tables and successor lists
- **File Sharing**: Distributed file storage, discovery, and transfer
- **Chunked Transfer**: Parallel downloads, multi-source, resume support
- **Pub/Sub Messaging**: Topic-based publish/subscribe with DHT routing
- **Distributed Locks**: Named locks with TTL and wait queues
- **NAT Traversal**: ICE/STUN/TURN for connectivity through NATs
- **End-to-End Encryption**: Noise Protocol XX with ChaCha20-Poly1305
- **Internal DNS**: Name resolution within the DHT network
- **Vivaldi Coordinates**: Decentralized latency estimation
- **Fast Routing**: Parallel probing for lowest-latency paths

## Building

```bash
# Configure
cmake -B build -G Ninja

# Build
cmake --build build --target p2p

# Run tests
cmake --build build --target test_p2p_chord
./build/bin/test_p2p_chord
```

## Quick Start

### Initialize and Create a Node

```c
#include <p2p.h>

int main() {
    // Initialize library
    p2p_init();

    // Create a node
    p2p_handle_t node = p2p_create("0.0.0.0", 8000);
    if (!node) {
        printf("Failed to create node\n");
        return 1;
    }

    // Start listening
    p2p_start(node);

    // Create a new DHT ring (first node)
    p2p_create_ring(node);

    // ... or join an existing ring
    // p2p_join(node, "192.168.1.100", 8000);

    // Run event loop
    p2p_run(node);

    // Cleanup
    p2p_destroy(node);
    p2p_shutdown();
    return 0;
}
```

### File Sharing

```c
// Store a file in the DHT
p2p_store_file(node, "/path/to/myfile.txt");

// Find a file by name
p2p_find_file(node, "myfile.txt", on_file_found, user_data);

// Callback receives file location
void on_file_found(p2p_handle_t node, const char *filename,
                   const char *owner_ip, int owner_port, void *ctx) {
    if (owner_ip) {
        printf("Found %s at %s:%d\n", filename, owner_ip, owner_port);
    }
}
```

### File Transfer

```c
// Download a file
p2p_transfer_handle_t transfer = p2p_download_file(
    node,
    file_id,           // SHA-1 hash of file
    "output.txt",      // Local save path
    on_progress,       // Progress callback
    on_complete,       // Completion callback
    user_data
);

// Progress callback
void on_progress(p2p_transfer_handle_t t, size_t bytes, size_t total, void *ctx) {
    printf("Progress: %zu / %zu bytes\n", bytes, total);
}

// Completion callback
void on_complete(p2p_transfer_handle_t t, int success, const char *error, void *ctx) {
    if (success) {
        printf("Download complete!\n");
    } else {
        printf("Download failed: %s\n", error);
    }
}

// Control transfer
p2p_transfer_pause(transfer);
p2p_transfer_resume(transfer);
p2p_transfer_cancel(transfer);
```

### Pub/Sub Messaging

```c
// Subscribe to a topic
p2p_subscribe(node, "chat/room1", on_message, user_data);

// Message callback
void on_message(p2p_handle_t node, const char *topic,
                const void *data, size_t len, void *ctx) {
    printf("Received on %s: %.*s\n", topic, (int)len, (char*)data);
}

// Publish a message
const char *msg = "Hello, world!";
p2p_publish(node, "chat/room1", msg, strlen(msg));

// Unsubscribe
p2p_unsubscribe(node, "chat/room1");
```

### Distributed Locks

```c
// Acquire a lock
p2p_lock_acquire(node, "my-resource", on_lock_acquired, user_data);

// Lock callback
void on_lock_acquired(p2p_handle_t node, const char *name,
                      int acquired, void *ctx) {
    if (acquired) {
        printf("Lock acquired!\n");
        // Do work...
        p2p_lock_release(node, "my-resource");
    } else {
        printf("Lock denied\n");
    }
}

// Try acquire (non-blocking, no wait)
p2p_lock_try_acquire(node, "my-resource", on_lock_acquired, user_data);
```

### NAT Traversal

```c
// Configure STUN servers
p2p_ice_add_stun_server(node, "stun.l.google.com", 19302);
p2p_ice_add_stun_server(node, "stun1.l.google.com", 19302);

// Configure TURN server (for relay fallback)
p2p_ice_add_turn_server(node, "turn.example.com", 3478,
                        "username", "password");

// Connect to peer through NAT
p2p_ice_connect(node, peer_id, on_ice_connected, user_data);
```

### Internal DNS

```c
// Register a name
p2p_dns_register(node, "mynode.local", 300);  // 5 min TTL

// Resolve a name
p2p_dns_resolve(node, "othernode.local", on_resolved, user_data);

void on_resolved(p2p_handle_t node, const char *name,
                 const char *ip, int port, void *ctx) {
    if (ip) {
        printf("%s -> %s:%d\n", name, ip, port);
    }
}

// Unified lookup (auto-detects hex ID vs name)
p2p_lookup(node, "mynode.local", on_lookup, user_data);      // DNS lookup
p2p_lookup(node, "a1b2c3d4e5...", on_lookup, user_data);     // ID lookup
```

### Encryption

Encryption is enabled by default. Each node generates a long-term identity key on first run, stored in:
- Windows: `%APPDATA%/p2p_identity_<port>.key`
- Unix: `/tmp/p2p_identity_<port>.key`

The Noise Protocol XX handshake provides:
- Mutual authentication
- Perfect forward secrecy
- Identity hiding

```c
// Disable encryption (not recommended)
p2p_set_encryption(node, 0);

// Get node's public key
const uint8_t *pubkey = p2p_get_public_key(node);
```

## Architecture

```
p2p/
├── include/           # Public API headers
│   └── p2p.h
├── src/
│   ├── core/          # Node, peer, file management
│   ├── protocol/      # Message serialization, handlers
│   ├── dht/           # Chord ring, DNS, routing
│   ├── transfer/      # File transfer, chunking, resume
│   ├── pubsub/        # Publish/subscribe messaging
│   ├── ice/           # NAT traversal (ICE/STUN/TURN)
│   ├── lock/          # Distributed locking
│   ├── crypto/        # Noise Protocol encryption
│   └── api/           # Public API implementation
└── tests/             # Unit and integration tests
```

## Protocol

### Message Types

| Category | Messages |
|----------|----------|
| Core | PING, PONG |
| DHT Ring | JOIN, STABILIZE, NOTIFY, FIND_SUCCESSOR |
| File | FILE_STORE, FILE_FIND, FILE_REQUEST, FILE_RESPONSE |
| Transfer | CHUNK_REQUEST, CHUNK_DATA, FILE_ACK |
| Directory | DIR_REQUEST, DIR_RESPONSE, DIR_FILE_START, DIR_COMPLETE |
| Pub/Sub | SUBSCRIBE, UNSUBSCRIBE, PUBLISH |
| Lock | LOCK_REQUEST, LOCK_GRANTED, LOCK_DENIED, LOCK_RELEASE |
| ICE | ICE_OFFER, ICE_ANSWER, ICE_CANDIDATE |
| DNS | DNS_STORE, DNS_FIND, DNS_REPLY, DNS_DELETE |
| Crypto | NOISE_HANDSHAKE |

### Frame Format

```
+--------+--------+--------+--------+
|  Magic (2B)     | Payload Len (2B)|
+--------+--------+--------+--------+
|           Payload (N bytes)       |
+--------+--------+--------+--------+
|           CRC32 (4B)              |
+--------+--------+--------+--------+
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| Chunk size | 32 KB | Max 64 KB |
| Parallel chunks | 4 | Concurrent chunk requests |
| Lookup timeout | 5 sec | DHT lookup timeout |
| Lookup max hops | 32 | Maximum routing hops |
| Transfer timeout | 30 sec | Overall transfer timeout |
| Chunk timeout | 5 sec | Per-chunk timeout |
| Chunk retries | 3 | Retry attempts per chunk |
| Successor list | 8 | Fault tolerance |
| Finger bits | 8 | 256 finger table entries |
| Replication K | 3 | Data replication factor |
| DNS TTL | 5 min | Default name TTL |
| Lock TTL | 30 sec | Default lock TTL |
| Max peers | 1024 | Per-node peer limit |

## Security

### Encryption

- **Key Exchange**: Curve25519 (X25519)
- **Symmetric Cipher**: ChaCha20-Poly1305 (AEAD)
- **Hash Function**: BLAKE2b
- **Handshake**: Noise Protocol XX pattern

### Noise XX Handshake

```
-> e                     (initiator sends ephemeral public key)
<- e, ee, s, es          (responder sends ephemeral, DH, static, DH)
-> s, se                 (initiator sends static, DH)
```

After handshake, all messages are encrypted with derived session keys.

## Error Handling

```c
int ret = p2p_some_operation(node, ...);
if (ret != P2P_OK) {
    printf("Error: %s\n", p2p_error_string(ret));
}
```

| Error Code | Description |
|------------|-------------|
| P2P_OK | Success |
| P2P_ERR_INVALID_ARG | Invalid argument |
| P2P_ERR_NO_MEMORY | Memory allocation failed |
| P2P_ERR_NETWORK | Network error |
| P2P_ERR_NOT_FOUND | Resource not found |
| P2P_ERR_TIMEOUT | Operation timed out |
| P2P_ERR_IO | I/O error |
| P2P_ERR_INVALID_STATE | Invalid state for operation |

## Dependencies

- **libuv**: Async I/O and event loop
- **monocypher**: Cryptographic primitives
- **TurboNet Core**: TCP/UDP networking
- **TurboNet Common**: Utilities and logging

## License

See LICENSE file in the repository root.

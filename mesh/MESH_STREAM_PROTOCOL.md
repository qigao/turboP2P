# Turbo Mesh Stream Framing V1

## Decision

Reliable byte-stream transports use a length-first outer frame. The framing
codec remains separate from MMP management messages and from TurboMedia media
semantics:

```text
u32 frame_length | fixed stream header | canonical TLV metadata | raw payload
```

`frame_length` is network byte order and counts every byte after the four-byte
length prefix. A receiver can therefore determine the complete frame boundary
before reading type-specific fields. It must still reject the length against
the locally negotiated limit before reserving or growing a receive buffer.

The implementation is the internal, non-installed `mesh_stream_codec` target.
It is not linked into `mesh`, P2P handlers, CoroNet, or TurboMedia.

## Alternatives

### Reuse MMP canonical frames

Rejected for bulk data. MMP requires signed canonical payload TLVs and has a
16 KiB management-frame limit. Media and file bytes must remain opaque and
must not pay per-field management parsing costs.

### Type-first outer frame

Rejected for reliable byte streams. A receiver would need more protocol bytes
before it can determine how much input belongs to the current frame. It also
makes skipping an unsupported frame less direct.

### Length-first frame with TLV-encoded bulk bytes

Rejected. Metadata benefits from typed extensibility, but wrapping every raw
chunk in another value field adds parsing and complicates direct borrowed
views. V1 therefore uses canonical TLV only for bounded metadata and leaves the
remaining payload as raw bytes.

## Wire layout

All integers use network byte order. `header_length` counts bytes after the
length prefix through the end of metadata, so its minimum is 44.

| Offset | Width | Field | Constraint |
|--------|------:|-------|------------|
| 0 | 4 | frame_length | bytes following this field |
| 4 | 1 | type | one of the V1 frame types |
| 5 | 1 | flags | only declared bits are accepted |
| 6 | 2 | header_length | `44..frame_length` |
| 8 | 16 | stream_id | non-zero random identifier |
| 24 | 8 | stream_epoch | non-zero path/session generation |
| 32 | 8 | sequence | stream-layer ordering input |
| 40 | 8 | offset | logical byte offset |
| 48 | variable | metadata | at most 4096 bytes canonical TLV |
| `4 + header_length` | remaining | payload | raw borrowed bytes |

Metadata fields use `type:u16 | length:u16 | value`. Types must be non-zero and
strictly increasing; duplicates, truncated values, and trailing partial fields are
rejected. Message-specific metadata schemas belong to
`mesh_stream_session`, not the structural codec.

V1 frame types are `OPEN`, `ACCEPT`, `DATA`, `WINDOW_UPDATE`, `CANCEL`, and
`CLOSE`. Only `DATA` may carry raw payload. A zero-length `DATA` frame is valid
only with `END_STREAM`; control frames reject `END_STREAM` and raw payload.

The hard encoded-frame ceiling is 256 KiB, including the length prefix. Each
connection may negotiate a smaller maximum, which is supplied to every encode
and decode call. The remote endpoint cannot raise the local maximum.

## Streaming and ownership

The codec is stateless and allocation-free:

1. Fewer than four input bytes returns `NEED_MORE` with required size 4.
2. Once the prefix is present, an oversized length fails immediately.
3. A bounded but incomplete frame returns `NEED_MORE` with its exact total.
4. A complete frame returns borrowed metadata and payload views and consumes
   exactly one frame, leaving trailing bytes for the next call.

The transport adapter owns one contiguous receive window allocated once at the
negotiated `max_frame_size`. Returned pointers become invalid when the event
callback returns. Arbitrary `coro_socket_recv()` chunks are copied into this
window and immediately released exactly once with `coro_socket_free_recv()`.
The adapter compacts only when tail capacity is exhausted and repeatedly drives
the session until it needs more bytes.

Decode time is `O(metadata bytes)` and space is `O(1)`; raw payload is neither
scanned nor copied. Encode time is `O(metadata + payload)` because it writes one
contiguous transport frame, with `O(1)` auxiliary space.

### CoroNet adapter and backpressure

`mesh_stream_transport` separates a testable bounded-window driver from a thin
`coro_socket` function mapping. The socket remains owned by its coroutine; the
adapter owns neither the socket nor its event-loop context. The CoroNet entry
points accept only a fully-open TLS 1.3 socket. Channel and registry creation
also require a live authorization produced by the three-message bind below;
the authorization's exporter, role, remote node, admission generation, stream
ID/epoch, and expiry must all match. `pump_once` must be called by that owner
and treats CoroNet's `NULL/0` interrupted receive as a non-terminal wakeup.

The application event callback is synchronous. It may inspect borrowed OPEN,
DATA, CANCEL, or CLOSE fields but must not retain their pointers. A non-zero
callback result rejects the event without committing session state and makes
the transport terminally failed.

ACCEPT and WINDOW_UPDATE are encoded into bounded temporary control storage.
The CoroNet copy-send must succeed before their preparations are committed.
The adapter configures a non-zero socket send high-water mark and a bounded
receive timeout; an HWM, timeout, or other I/O failure is terminal because
delivery is ambiguous after the connection fails. Receive-window replenishment occurs only after DATA consumption and only
when outstanding credit reaches a configured threshold. It restores at most
the initial window and never crosses the declared or local total-size cap.

The CoroNet regression completes INIT/ACCEPT/CONFIRM on one real TLS 1.3
loopback connection, verifies both authorizations carry the same exporter, and
only then admits a registry stream through OPEN/DATA/CLOSE. It also proves that
even a connected raw TCP socket and a locally forged authorization cannot
create bind, transport, or registry state. CoroNet's own TLS regression proves
two distinct TLS 1.3 connections do not reuse the exporter. Daemon and
multi-node orchestration remain later integration work.

### Peer lifecycle admission

Stream admission is disabled by default. `mesh_stream_admission_enable()` makes
the node advertise `MESH_CAP_STREAM_V1` in its existing HELLO, which runs only
after the current P2P transport handshake callback. A direct peer is stream-ready only
when all of the following remain true:

1. the P2P transport reached its authenticated callback;
2. HELLO is accepted by virtual-IP, node-ID, protocol-major, and ACL checks;
3. the HELLO node ID exactly matches the P2P remote public key;
4. both nodes advertise `MESH_CAP_STREAM_V1`; and
5. the peer is still connected and announced.

`mesh_peer_stream_ready()` exposes this derived decision. Disconnect revokes
the authenticated flag and Stream V1 capability before the application
disconnect callback. No second reader is attached to the existing
`turbo_stream`: it remains owned by P2P framing. The admission gate therefore
does not yet attach `mesh_stream_transport` to a daemon data connection.

This gate is not production cryptographic proof by itself. The current
`p2p_noise_*` implementation is explicitly a simplified Noise-like handshake,
not a complete Noise protocol implementation, and its receive path replaces
the configured remote public key with the received ephemeral key. Stream V1
must therefore not describe this lifecycle as standard Noise authentication or
use it as the only identity proof for a dedicated data connection.

### Authenticated channel lifecycle

The internal `mesh_stream_channel` owns one `mesh_stream_transport` lifecycle,
but not its I/O context or CoroNet socket. Its admission snapshot binds the
remote transport identity, admitted peer generation, stream ID, and stream
epoch. The stream ID and epoch must equal the receiver configuration before
transport setup. The mesh peer owner remains responsible for deriving this
snapshot only after `mesh_peer_stream_ready()` succeeds; the snapshot is not a
substitute for that security decision.

Every feed, receive, revoke, and close operation carries the admission
generation. A delayed callback from an older connection receives
`STALE_ADMISSION` and cannot revoke a channel created after reconnect. The
serialized owner state is:

```text
UNINITIALIZED -> READY -> CLOSED
                       -> REVOKED
                       -> FAILED
```

An interrupted CoroNet receive leaves the channel `READY`. A normal stream
terminal frame, matching admission revoke, application rejection, protocol
failure, or I/O failure snapshots the final counters and diagnostics and then
releases the receive window immediately. Socket cancellation and destruction
remain the coroutine owner's responsibility. Cross-thread shutdown must first
wake or cancel its pending receive, then execute channel revoke/close on that
same owner; the channel contains no hidden lock or second reader.

This owner is still an uninstalled internal target. It does not create a daemon
data connection, alter P2P wire messages, or attach itself to the existing P2P
framing socket.

### Bounded channel registry

`mesh_stream_registry` is the single owner-loop fact source for multiple
channels. Initialization allocates a fixed slot table once and validates both a
total channel capacity and a stable-identity per-peer limit. Both limits are
mandatory, bounded by 4096 slots, and fail closed; terminal channels continue to
consume their slot until the owner explicitly releases them after collecting
diagnostics.

An occupied key is the tuple `(remote identity, admission generation, stream
ID, stream epoch)`. Reopening the same tuple is rejected even after its channel
has become terminal. Peer quota counts all occupied generations for the stable
remote identity, preventing reconnect churn from escaping the limit.

Data operations use a handle containing registry identity, registry generation,
slot index, and slot generation. Slot reuse increments its generation, and the
registry owner must provide a new non-zero registry generation for each
registry lifetime. This prevents both ordinary slot ABA, cross-registry handle
confusion, and an old handle targeting storage after registry reinitialization.
Disconnect handling scans by remote identity plus admission generation, so it
revokes the old generation without touching a newer connection for the same
node.

Open, peer revoke, and stats are bounded `O(N)` operations where `N <= 4096`;
feed, pump, close, release, and channel query validate the handle and access its
slot in `O(1)`. The registry has no internal lock, performs no socket close, and
must run on the same coroutine/event-loop owner as its channels. Registry
destruction requires pending receives to be stopped first.

### Dedicated TLS connection secure bind

The internal `mesh_stream_bind` target defines the fail-closed admission
protocol for a dedicated data socket. Its CoroNet adapter derives the exporter
from the live socket and sends INIT/ACCEPT/CONFIRM in order; callers cannot
supply the data-plane binding. Stream frames remain forbidden until bind
authorization is validated at channel/registry creation.

Prerequisites are:

1. the dedicated connection has completed TLS 1.3 with server certificate
   verification enabled;
2. both endpoints obtain the exact 32-byte `tls-exporter` channel binding from
   that TLS connection using label `EXPORTER-Channel-Binding`, empty context,
   and length 32 as specified by [RFC 9266](https://datatracker.ietf.org/doc/html/rfc9266#section-2);
3. the responder issues a one-time ticket and delivers it only through the
   authenticated MMP control session; and
4. the ticket binds mesh ID, distinct initiator/responder node IDs and Ed25519
   management keys, stream ID/epoch, admission generation, and responder-owned
   expiry.

The exact-length V1 handshake is:

```text
initiator -> responder: INIT(ticket claims, tls-exporter, nonce_i, key_i, sig_i)
responder -> initiator: ACCEPT(ticket_id, hash(INIT), tls-exporter, nonce_r, key_r, sig_r)
initiator -> responder: CONFIRM(ticket_id, hash(ACCEPT), tls-exporter, key_i, sig_i)
```

Every integer is network byte order. Frames are 368, 232, and 200 bytes
respectively; each begins with `u32 remaining_length | u8 type | u8 version |
u16 reserved`, and V1 requires both reserved bytes to be zero. Signatures use
separate `TurboNet-Mesh-Stream-Bind-v1/{init,accept,confirm}` domains. The
ACCEPT and CONFIRM hashes cover the complete preceding frame, including its
signature. This prevents field substitution, role reflection, cross-ticket
mixing, and replay on another TLS connection. The channel-binding value is
public binding data, not a traffic key, and must never be reused as one.

The responder's fixed-capacity table is the single ticket fact source:

```text
FREE -> ISSUED -> CHALLENGE -> CONSUMED -> FREE after expiry
```

Only the responder evaluates ticket time, avoiding cross-node wall-clock
decisions. A bad signature or channel binding does not advance state. A valid
CONFIRM atomically returns the admitted ticket and leaves a consumed tombstone
until expiry, so retransmission is reported as replay rather than not-found.
Socket or send ambiguity must explicitly invalidate the ticket. Capacity and
TTL are mandatory, with hard ceilings of 4096 tickets and 60 seconds. Lookup
and sweep are bounded `O(N)` setup-path work; per-ticket storage is `O(1)`.

MMP now defines fixed canonical request/issued ticket payloads and an internal
domain command that derives initiator claims from the authenticated MMP
session, writes only the responder-owned ticket store, and verifies response
correlation, identities, request claims, time, and TTL before initiator use.
The MMP dispatcher remains observer-only. Ticket-event orchestration is not
connected yet. The internal MMP transport
can now preserve and exchange bounded frames over a real TLS 1.3 CoroNet
socket, but endpoint discovery, daemon listener/connect ownership, HELLO send,
and ticket response signing/sending remain absent. CoroNet exposes a fixed,
read-only TLS 1.3 RFC 9266 channel-binding query. The adapter fails closed for raw TCP,
an incomplete handshake, a non-TLS-1.3 connection, exporter failure, expired
authorization, claim mismatch, or reuse on another TLS connection. A failed
ACCEPT send tombstones the responder ticket; a failed initiator send clears
its local bind state. Public peer-certificate queries remain absent, so the
deployment still relies on CoroNet certificate verification plus the signed
MMP ticket identities rather than exposing certificate internals to Mesh.

## TurboMedia boundary

TurboMedia remains the owner of codec, track, timestamp, keyframe, RTP, RTMP,
WebRTC, muxing, and demuxing semantics. Its borrowed `turbo_media_frame_t`
`data/size` can become a stream `DATA` payload, while a dedicated adapter maps
track and timestamp information into an agreed metadata schema. The networking
codec does not include or depend on TurboMedia headers.

This separation also permits file, diagnostic, and application streams to use
the same framing without pretending they are media frames.

## Security and state boundaries

This structural codec does not authenticate peers, authorize stream creation,
apply flow control, or advance replay state. The internal receiver-side
`mesh_stream_session` applies:

```text
authenticated channel
-> structural decode and resource ceiling
-> stream_id/epoch binding
-> OPEN authorization
-> sequence and offset window
-> flow-control quota
-> typed metadata validation
-> application delivery
```

Lengths are validated before payload access. Codec and session failures do not
modify a session or application fact source. The session returns borrowed data
and a generation-bound preparation; the caller commits it only after the
application has accepted or consumed the event.

### Receiver binding and OPEN schema

The authenticated channel creates a receiver session with one non-zero
`stream_id`, one non-zero `stream_epoch`, allowed stream-class bits, frame and
total-size limits, and bounded initial/maximum receive windows. These local
facts are the authorization source; an OPEN cannot broaden them.

OPEN must use sequence 0 and offset 0. Its canonical metadata schema is:

| TLV type | Width | Meaning |
|----------|------:|---------|
| 1 | 1 | stream class: blob=1, media=2, diagnostic=3, application=4 |
| 2 | 8 | total size; `UINT64_MAX` means unknown only when locally allowed |
| 3 | 1..64 | optional visible-ASCII content type |

Unknown fields, reordered fields, an unauthorized class, and a total larger
than the local cap are rejected. ACCEPT is generated in the reverse control
sequence space with sequence 0 and its `offset` equal to the absolute receive
limit. It has no metadata or payload.

### Ordering, flow control, and terminal frames

After ACCEPT is sent, the first DATA has sequence 1 and offset 0. Each later
sender frame must have the exact next sequence and committed byte offset; V1
does not buffer gaps or reorder frames. A known total may not be exceeded, and
END_STREAM must finish exactly at that total.

An unknown declared total does not mean unbounded input: committed offsets and
advertised absolute credit still cannot exceed the receiver's local
`max_total_size` hard cap.

The receiver advertises credit as an absolute byte limit, not a delta. A
WINDOW_UPDATE uses the next reverse control sequence and puts the new absolute
limit in `offset`. Outstanding credit (`receive_limit - committed_offset`) may
never exceed the configured maximum. The prepare/commit split prevents failed
network sends from advancing the advertised-limit fact source.

CANCEL is valid after OPEN and carries exactly one reason TLV (`type=1`,
`length=2`). CLOSE uses the same reason schema and is accepted only after
END_STREAM. Both are terminal after commit. ACCEPT and WINDOW_UPDATE arriving
on the receiver's sender-to-receiver direction are rejected.

The codec and session targets have no callback or socket side effect. The
transport target adds one synchronous application callback and CoroNet I/O but
still has no file write, media publication, command side effect, or internal
locking. Any protocol, binding, application, trailing-data, or I/O failure is
terminal; callers close the non-owned socket at their lifecycle boundary.

## Migration and rollback

The framing, receiver session, and transport adapter remain internal targets.
`MESH_CAP_STREAM_V1` is a new optional HELLO bit; it is never advertised unless
admission is explicitly enabled, and older peers ignore it while retaining
their existing data-plane behavior. The admission APIs are additive and
`mesh_config_t` keeps its existing field layout. Peers must not reinterpret
arbitrary `P2P_MSG_CUSTOM` bytes as stream frames.

Rollback disables `stream_enabled` or omits the enable call, which removes the
capability on the next HELLO without changing stored data. Removing the
unattached internal transport targets requires no data migration.

# TurboP2P CNet 2.3 / CMeta ACE connection admission

## Responsibility boundaries

CMeta Strategy = a canonical typed borrowed Interface for composing
host-side connection pressure and bounded SG handoff credits. No global
registry, new strategy engine or duplicated Reactor/Proactor is introduced.

CNet Owner Placement = EXPLICIT, ROUND_ROBIN, LOWEST_PRESSURE, STRICT_KEY.
It exclusively chooses an Owner at admission. Pre-Noise STRICT_KEY remains
rejected because raw TCP source information is not authenticated identity.

CNet Handoff = generation-safe ticket, real detached TCP stream and
authoritative bounded reserve/publish/take/release. A hint cannot reserve
physical CNet slots or turn a failed commit into implicit failover.

NativeIO SG = one borrowed backend and one authoritative Host observe
per shard; the final Owner alone runs P2P cookie, Noise and message callbacks.

## Connection accounting before this change

The previous lowest-pressure hint used only Handoff RESERVED, QUEUED and
TAKEN credits. It missed P2P connections owned by the same target, such as
outbound streams or locally accepted non-handoff streams. Its local-owner
special case added the live count to TAKEN, which can double-count the same
established incoming connection.

Now each P2P transport Owner publishes its exact live-list count with an
atomic release-store when a connection enters or retires from the list.
The acceptor uses an acquire-load: no unsynchronized read of a foreign
Owner's linked list or mutable connection count.

The typed CMeta p2p_sg_ace_hint Strategy builds a pressure hint:

    pressure = max(owner_published_live_p2p, handoff_taken)
             + handoff_reserved + handoff_queued

An Owner is eligible only when it is not sealed, the handoff credit budget is
not full, and this hint is below the Owner's actual CNet client connection
capacity. Credit capacity and physical capacity are checked separately:
an app may choose a tighter handoff credit limit than the underlying client.

EXPLICIT computes only its pinned Owner's pressure (O(1) host snapshot),
rather than acquiring every other inbox snapshot. RR and LOWEST_PRESSURE
compute all bounded hints and use upstream cnet_owner_placement_choose.
The final CNet/Handoff reservation remains authoritative, so a stale hint
can still fail closed without hidden retry or a new Owner choice.

## ACE composition and limits

Strategy: CMeta Interface + exact C11/C++17 native signatures; borrowed
state is stack-local to each synchronous TCP accept. No reflection walk on
any receive/send operation, and no provider/module retention.

Acceptor-Connector: CNet listener/client remain the only transport owners.
ACT: CNet Handoff ticket and SG request generation, not a second tracker.
Reactor/Proactor: NativeIO/CNet, not CMeta callbacks with their own loop.

The published counter covers the P2P CNet transport Owner's own connections.
An independently cohosted CNet client has its own physical capacity and is
not included in the P2P owner's live-list count. For a complete mixed-SG
pressure signal, add an explicit Host-owned capacity/telemetry publication
contract instead of reading foreign cnet_client.impl or claiming that the
pure placement decision reserves external clients.

Client direction: signed management endpoint policy already selects stable
identity through CNet destination strategies. CNet Manager, ClientPool,
ManagedDial integration after authenticated Noise + signed MMP READY is a
separate delivery (#38). Never equate CONNECTED with protocol READY,
duplicate reconnect timers or replay MMP commands/DHT writes/files on retry.

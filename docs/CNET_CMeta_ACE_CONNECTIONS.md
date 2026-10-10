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

The exact calculation requires two facts published from one P2P Owner:
live physical connections and how many of those still retain an *adopted*
Handoff TAKEN ticket. They are atomically packed into one release/acquire
publication to avoid cross-shard torn counts. CNet HandOff separately
publishes RESERVED/QUEUED/TAKEN.

    uncredited_p2p_live = p2p_live - p2p_adopted_taken
    p2p_occupancy = uncredited_p2p_live
                  + handoff_taken + handoff_reserved + handoff_queued
    shared_host_pressure = p2p_occupancy + other_cnet_slots

Unlike max(live, TAKEN), this also counts TAKEN tickets still awaiting Adopt
alongside unrelated outbound P2P connections. Impossible intersections
(adopted > live or adopted > TAKEN) fail closed, never become a negative or
wrapped occupancy.

The actual SG Host uses p2p_cnet_owner_publish_sg_host_load() on the
borrowed Owner shard and exact lease to publish **other CNet Client physical
slots** from CONNECTING until terminal plus an optional shared physical
connection budget. Both values are published in one atomic word. If a P2P
SG poll receives an extras[] group without prior Host publication, it fails
before touching P2P admission state, key-worker completion or NativeIO observe.

An Owner is eligible only when it is not sealed, the Handoff credit budget
is not full, P2P occupancy is below that Owner's own physical CNet client
capacity, and (if the Host supplies a shared budget) combined P2P+CNet
pressure is below that shared Host capacity. Credit capacity and physical capacity are checked separately:
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

The published per-P2P Owner counters cover that P2P CNet Client only.
Independent cohosted CNet clients supply **explicit Host-owned telemetry**:
the host counts real connecting/live physical occupied slots across all
additional CNet clients and publishes a separate shared budget. It must
update the publication as connections are admitted/retired and keep callback
storage alive until CNet terminal + stop/destroy. The publication is advisory
and can become stale between Owner accept and CNet admission; the final
CNet/Handoff reserve is the sole authoritative enforcement. There is no
private CNet impl inspection or invented native backend pool.

When multiple CNet consumers share one SG backend, this shared capacity is
an application Host budget, not an SDK-owned physical capacity reservation.
An additional Host-side reservation credit is still required if the product
wants strict global shared-slot admission rather than a conservative hint.

Client direction: signed management endpoint policy already selects stable
identity through CNet destination strategies. CNet Manager, ClientPool,
ManagedDial integration after authenticated Noise + signed MMP READY is a
separate delivery (#38). Never equate CONNECTED with protocol READY,
duplicate reconnect timers or replay MMP commands/DHT writes/files on retry.

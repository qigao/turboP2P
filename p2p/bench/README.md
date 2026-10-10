# SG Host + P2P Noise benchmark (experimental)

This benchmark builds real TurboP2P production CNet/Noise sources **only against
installed Salts.Native 2.3.0-* and SaltsUtils.Native 4.3.0-***. It uses one
NativeIO SG backend/host lease per shard, one authoritative observer on each
shard, and real TCP connections plus peer-cookie/Noise authentication.

Run the **P2P SG Host performance profiles** workflow or build manually:

```sh
cmake -S tests/salts_foundation -B build/p2p-sg-benchmark -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DP2P_SG_BUILD_BENCHMARKS=ON \
  -DCMAKE_TOOLCHAIN_FILE="$QIGAO_VCPKG_TOOLCHAIN_FILE" -DVCPKG_MANIFEST_MODE=OFF
cmake --build build/p2p-sg-benchmark --target \
  bench_p2p_sg_1 bench_p2p_sg_2 bench_p2p_sg_4_1 bench_p2p_sg_4
P2P_SG_BENCH_WARMUP=16 P2P_SG_BENCH_ROUNDS=128 \
  ./build/p2p-sg-benchmark/bench_p2p_sg_4
```

## Metric definition and limits

- 1 shard: one SG-native P2P listener and P2P protocol Owner; **1** connection,
  no cross-Owner handoff.
- 2 shards: SG listener/acceptor plus one final Owner; **1** connection.
- 4 shards (comparison): SG acceptor plus three final P2P Owners, of which
  only one is used by **1** client. It isolates additional idle shard costs.
- 4 shards (multi-session): SG acceptor plus three final P2P Owners; **3**
  active connections. Placement
  is ROUND_ROBIN during accepted-stream admission and never per packet.
- Every session is authenticated with real cookie/Noise handshake **outside**
  the measured interval. Each measured round sends one 8-byte application
  request per session and receives one 8-byte reply, by driving explicit SG
  Owner/standalone-client polling. A latency sample measures the **complete
  parallel echo round**, not per-packet wire latency. Warmup rounds are excluded.
- Percentiles use monotonic-clock nanoseconds; process CPU includes both SG
  workers and standalone client threads. Throughput counts only application
  payload bytes, not wire framing/TLS/Noise or I/O bytes. Reports include session
  count, payload size, warmup/samples, CPU% and messages/s.
- The dedicated workflow uses 64 warmup + 1024 measured rounds, with **five
  independent process repeats per topology**. It saves all raw samples and
  separately reports medians of per-run P50/P95/P99, throughput and CPU. The
  result is still a synchronous host-driven benchmark on a shared GitHub runner.
  A one-session 1/2/4-shard comparison can quantify overhead, but **not**
  multicore speedup. There is still **no raw CNet baseline, same three-session
  1/2/4-shard scaling workload, connection-admission benchmark, varied message
  sizes, confidence intervals, or isolated/pinned CPU environment** in this phase.
  Do **not** infer linear multicore scaling, product throughput capacity or an
  accepted performance regression from these numbers. #37 remains open.
- No benchmark runs as part of ordinary release, debug or sanitizer CTest.

Source and CI output must remain attached to the same commit SHA. No fixed RC
dependency pin, synthetic socket/Noise bypass, Actor scheduler or extra observer.

## Owner-independent SG progress versus global barrier

`bench_p2p_sg_{1,2,4_1,4}_async` uses the exact same installed SDK and
P2P cookie/Noise/transport sources as the original `global-barrier`
profiles. Only the measured progress driver differs. An external coordinator
uses nonblocking `native_io_sharded_try_submit_to` to enqueue at most **one
finite pending task per SG Owner**. A task's finalize callback releases its
atomic readiness token; SG callbacks publish received-message count with
release/acquire atomics, avoiding unsynchronized reads of peer/node fields.

No `native_io_sharded_wait` is invoked during a measured async round. One
final drain before teardown verifies each outstanding task and its callback
storage has quiesced; setup and teardown remain synchronized. No second SG
observer, permanent executor task, Actor or additional backend is installed.

The workload still coordinates **one synchronous request/reply echo batch**
per round, including all standalone-client progression in process CPU; it is
not an open-loop saturated data-plane test. The CSV distinguishes
`owner-independent` from `global-barrier`, with 5 separately initialized
process runs per mode/topology and the same active-session matrix (1/1/1/3).
Raw CNet/equal-concurrency multiple-peer and payload-size sweeps remain open.

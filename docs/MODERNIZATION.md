# Salts-native modernization

Tracks issues #1 and #2 and draft PR #3. This document defines the destination,
not a claim that the historical production sources have already migrated.

## Ownership

**CNet is the only networking foundation for TurboP2P.** All peer, discovery,
relay, stream, Raft and management network traffic must go through CNet or an
explicitly verified CNet-backed protocol component. CHttp Client/Server are
such components. A missing CNet feature is an upstream issue, not permission
to add an OS socket, NativeIO network backend, CoroNet bridge or event loop.
CNet's public configuration uses NativeIO backend identifiers; selecting one
is not the same thing as implementing a parallel NativeIO networking path.

CMeta/reflection and SaltsUtils DataBind improve how code is expressed:
typed contracts, generic operations, generated message/configuration bindings,
validation and registration/dispatch. They are not a second network runtime,
and reflection is not restricted to a mandatory control-plane framework.
Compile/admit repeated work once; keep packet processing on typed, bounded
operations rather than traversing schema metadata for every packet.

CFlow expresses mesh peer/session protocol lifecycle and orchestration. It
does not duplicate CNet's canonical connection/terminal state. Salts Plugin
owns loader/publication/lease lifetime, independent of CFlow. Keep a module
lease until all borrowed metadata, function pointers and pending invocations
are dead; reflection does not itself grant execution or authorization.
DataBind is part of SaltsUtils (`Salts::DataBind`), not another package root.

## Executable first checkpoint

`ci/restore_native_sdks.py` restores the latest stable `Salts.Native`,
`SaltsUtils.Native` and `CHttp.Native` in one fresh NuGet resolution. It reads
exact selected identities from `project.assets.json`, not directory globs or
version guesses. Missing/ambiguous SDKs fail; no older package is substituted.
Resolved versions are written to the CI summary, not committed lock metadata.

The workflow uses `qigao/vcpkg-cache/.github/actions/setup-vcpkg-cache@master`.
The shared action owns toolchain, overlays, executable/scripts identity and
remote binary-cache configuration. A GitHub Actions local cache supplements
that same binary store. CMake still performs vcpkg manifest installation and
ABI validation. Cache misses may build the required third-party version;
that is not a fallback to a retired SDK/API. Remote cache access is read-only.
Windows uses the producer's target/host triplets, not a hard-coded DLL path.
The baseline is retained because it matches the current CHttp manifest.

The direct presets in `ci/sdk_contract` qualify the installed SDK target
closure, CMeta header/runtime ABI, current CNet headers and a bounded CNet-only
UDP exchange. Both endpoints use CNet. The exchange checks copied payload
ownership, peer identity, send-slot backpressure, exactly one tagged send
terminal and stop/destroy. CHttp's public target graph must include CNet.
No fake SDK or stub networking library is used in that CI test.

Local Python unit tests validate SDK selection and output hygiene only. They
are not evidence that a native SDK compiled or any network test passed.

## Full migration gate remains separate

After SDK qualification, the same job configures/builds/tests the full current
TurboP2P source graph via `migration-*` presets. Failures are not ignored or
converted to skips. At this checkpoint root/component CMake and production
sources still reference retired packages and APIs. A successful SDK-only
consumer therefore **does not** mean this repository builds on the new stack.

Do not close #1/#2 or mark PR #3 ready based on the SDK tests. Required work:

1. Replace root/component dependency and installed-package contracts with the
   actual Salts/SaltsUtils/CHttp targets; remove retired aliases and machine-local
   user presets. Replace production Windows runtime staging with imported-target
   configuration-aware dependencies.
2. Migrate peer/discovery/relay/stream and HTTP paths to current CNet/CHttp.
   Preserve packet framing, identity checks and terminal/ownership semantics;
   test TCP partial writes, TLS identity/ALPN, UDP and authenticated KCP/FEC.
3. Qualify optional Raft/FlowMQ integrations on CNet-backed dependencies.
4. Add an isolated installed **TurboP2P** consumer. The SDK consumer here is
   deliberately not a substitute for that packaging test.
5. Introduce CMeta/DataBind contracts, CFlow protocol lifecycle and Plugin
   extensions in independently tested slices with bounded ownership.

The Clang ASan/UBSan preset instruments the consumer and subsequently TurboP2P
sources. Prebuilt SDK libraries are not thereby instrumented; full dependency
sanitizer coverage requires a separately qualified instrumented SDK build.

## Commands

From the repository root, after supplying the current SDK/cache environment:

```sh
python -m unittest discover -s ci/tests -v
cd ci/sdk_contract
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release
cd ../..
cmake --preset migration-linux-release
cmake --build --preset migration-linux-release
ctest --preset migration-linux-release
```

The Windows names are `windows-release` / `migration-windows-release`; Clang
consumer/source sanitizer names are `linux-clang-asan` /
`migration-linux-clang-asan`. All commands invoke CMake presets directly.

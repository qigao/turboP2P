# TurboP2P third-party notices

## Noise-C

- Project: [rweather/noise-c](https://github.com/rweather/noise-c)
- Pinned commit: `cfe25410979a87391bb9ac8d4d4bef64e9f268c6`
- Copyright: Copyright (C) 2016 Southern Storm Software, Pty Ltd.
- License: MIT

TurboP2P builds only the Noise protocol state machine and the pinned
`25519/ChaChaPoly/BLAKE2s` dependencies. X25519 key generation and agreement,
plus the operating-system random source, are supplied by the local
`p2p_noise_c_platform.c` adapter.

The upstream MIT license text is available at
[COPYING](https://github.com/rweather/noise-c/blob/cfe25410979a87391bb9ac8d4d4bef64e9f268c6/COPYING)
and must accompany redistributed Noise-C object code.

# TurboP2P third-party notices

## Noise-C

- Project: [rweather/noise-c](https://github.com/rweather/noise-c)
- Source: floating upstream `master`; the resolved revision is recorded at configure time.
- Offline builds may explicitly select a clean checkout using `TURBO_P2P_NOISE_C_SOURCE_DIR`.
- Copyright: Copyright (C) 2016 Southern Storm Software, Pty Ltd.
- License: MIT

TurboP2P builds only the Noise protocol state machine and the fixed-suite
`25519/ChaChaPoly/BLAKE2s` dependencies. X25519 key generation and agreement,
plus the operating-system random source, are supplied by the local
`p2p_noise_c_platform.c` adapter using the existing Monocypher dependency
and Salts Platform CSPRNG.

The upstream MIT license text is available at
[COPYING](https://github.com/rweather/noise-c/blob/master/COPYING)
and must accompany redistributed Noise-C object code.

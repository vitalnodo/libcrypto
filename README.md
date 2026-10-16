# libcrypto

This repo contains various cryptoprimitives reimplemented in zig.

## Algorithms

### Block ciphers
* [Twofish](src/ciphers/twofish) — 128 and 256 bit keys
* [Serpent](src/ciphers/serpent) — 128 and 256 bit keys

### Hash functions
* [RIPEMD-160](src/hash/ripemd)
* [Whirlpool](src/hash/whirlpool)

### Modes of operation
* [XTS](src/modes/xts) — for any 128-bit block cipher (AES, Twofish and Serpent are tested)

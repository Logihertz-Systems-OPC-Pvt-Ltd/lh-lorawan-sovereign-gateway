# Contributing to Logihertz Sovereign LoRaWAN Gateway (`lh-lorawan-sovereign-gateway`)

Thank you for contributing to **`lh-lorawan-sovereign-gateway`** (`bin/lh-lorawan`)! We enforce zero-dependency minimalism, strict ISO C11 compliance, and physical-layer LPWAN cryptographic rigor.

## Architectural Mandates

1. **100% Zero External Third-Party Dependencies**:
   - Compiles strictly under standard ISO C11 (`-std=c11 -O2 -Wall -Wextra -Werror -pedantic`) using standard library headers (`<stdint.h>`, `<stdbool.h>`, `<string.h>`, `<stdio.h>`, `<stdlib.h>`, `<math.h>`).
   - No external cryptography libraries (OpenSSL, libsodium, mbedTLS). All AES-128 and CMAC math must remain internal and clean-room implemented.
2. **Deterministic Cryptographic & Time-on-Air Math**:
   - FIPS 197 AES-128 and RFC 4493 AES-128-CMAC implementations must conform to standard reference test vectors.
   - LoRa CSS Time-on-Air calculations must follow exact Semtech formula specifications including Low Data Rate Optimization flags.
   - Message Integrity Code comparisons must execute in constant time via `lh_constant_time_memcmp`.
3. **Multi-Compiler Clean Build**:
   - Must build cleanly without warnings or errors under both `gcc` and `clang`.
   - All tests must pass with 100% assertions in `tests/test_runner.c`.

## Build & Test Workflow

```bash
# Build the CLI executable
make all

# Run deterministic test runner
make test

# Compile with Clang
make CC=clang clean all test
```

## Commit Message Conventions

We adhere to Conventional Commits:
- `feat(mac): implement adaptive data rate physical plausibility filter`
- `fix(cmac): correct subkey derivation overflow edge case`
- `test(otaa): add test case for non-monotonic DevNonce rejection`

## Code of Conduct

All contributors must uphold the ethical standards detailed in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

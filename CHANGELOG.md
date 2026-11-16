# Changelog

All notable changes to **`lh-lorawan-sovereign-gateway`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-16

### Added
- **FIPS 197 AES-128 & RFC 4493 AES-128-CMAC Engine**:
  - Full 10-round key expansion and AES-128 forward cipher block transformation.
  - RFC 4493 subkey derivation ($K_1, K_2$) with conditional polynomial feedback ($R_b = \texttt{0x87}$).
  - 32-bit LoRaWAN Message Integrity Code (`MIC`) extraction and constant-time verification.
  - LoRaWAN CTR payload encryption and decryption ($A_i$ and $S_i$ blocks).
- **Air-Gapped Sovereign Local OTAA Join Server & MAC Engine**:
  - `JoinRequest` parsing, `MIC` verification under root `AppKey`, and dynamic session key derivation (`NwkSKey`, `AppSKey`).
  - Persistent per-device `DevNonce` tracking preventing join replay attacks.
  - Monotonic 32-bit `FCntUp` anti-rollback checks for uplink frame counter protection.
  - Secure zeroization of cryptographic session materials on deactivation or re-join.
- **LoRa Chirp Spread Spectrum (CSS) Time-on-Air ($T_{\text{ToA}}$) Math**:
  - Calculation of symbol duration, preamble time, payload symbols, and total packet duration.
  - Low Data Rate Optimization ($DE = 1$) modeling for $\text{SF} \ge 11$ at $125\text{ kHz}$.
  - Support for India `IN865` ($865.0625, 865.4025, 865.9850\text{ MHz}$) and Europe `EU868` regulatory plans.
- **10-Rule LoRaWAN Security Posture Auditor (`lorawan_auditor.c`)**:
  - Automated evaluation of rules `LH-LORA-001` through `LH-LORA-010`.
  - Standardized Logihertz security posture score calculation ($S_{\text{posture}} \in [0, 100]$).
- **Multi-Format Reporting & CLI**:
  - ANSI Table, Canonical JSON, and OASIS SARIF v2.1.0 exporters.
  - CLI subcommands: `scan`, `join-otaa`, `verify-uplink`, `calc-toa`, `--version`, and `--help`.
- **Zero External Dependencies**:
  - Implemented entirely in ISO C11 with zero external libraries.

# lh-lorawan-sovereign-gateway

[![CI Pipeline](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-lorawan-sovereign-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-lorawan-sovereign-gateway/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v0.1.0-blue.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-lorawan-sovereign-gateway/releases/tag/v0.1.0)
[![Standard](https://img.shields.io/badge/standard-ISO%20C11-green.svg)](https://en.cppreference.com/w/c/11)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(Pure%20C11)-brightgreen.svg)](#zero-dependencies)

**`lh-lorawan-sovereign-gateway`** is a production-grade, zero-dependency **ISO C11 Cloud-Free Air-Gapped IN865/EU868 LoRaWAN Packet Forwarder & Local OTAA Join Server, AES-128-CMAC MIC Verifier, CSS Time-on-Air Engine, and 10-Rule Sovereign Security Posture Auditor**.

Engineered specifically for mission-critical national infrastructure, sovereign border sensors, industrial SCADA perimeters, and air-gapped IoT deployments, `lh-lorawan-sovereign-gateway` completely eliminates reliance on insecure legacy protocols (such as unencrypted Semtech UDP forwarders on port 1700) and external cloud network servers.

---

## Key Capabilities

1. **Clean-Room Cryptographic Core (Zero External Libraries)**:
   - FIPS 197 AES-128 block cipher implementation with 10-round key expansion.
   - RFC 4493 AES-128-CMAC Message Integrity Code (`MIC`) calculation with Galois field $GF(2^8)$ subkey derivation ($K_1, K_2$).
   - Constant-time verification (`lh_constant_time_memcmp`) to eliminate timing side-channels.
   - Active volatile memory zeroization (`lh_secure_zero`) for cryptographic keys and round buffers.
   - Symmetric LoRaWAN CTR payload encryption and decryption using standard $A_i$ block counters.

2. **Sovereign Local OTAA Join Server**:
   - Dynamic Over-The-Air Activation (OTAA) execution in air-gapped environments without WAN connectivity.
   - Constant-time 32-bit MIC verification on 23-byte `JoinRequest` frames using device root `AppKey`.
   - Strict `DevNonce` anti-replay guard rejecting repeated or replayed join nonces.
   - Deterministic derivation of Network Session Key (`NwkSKey`) and Application Session Key (`AppSKey`):
     $$\text{NwkSKey} = \text{AES-128}_{\text{AppKey}}(0x01 \parallel \text{JoinNonce}[3] \parallel \text{NetID}[3] \parallel \text{DevNonce}[2] \parallel \text{pad}_7[0])$$
     $$\text{AppSKey} = \text{AES-128}_{\text{AppKey}}(0x02 \parallel \text{JoinNonce}[3] \parallel \text{NetID}[3] \parallel \text{DevNonce}[2] \parallel \text{pad}_7[0])$$
   - Automatic synthesis of authenticated 17-byte `JoinAccept` telemetry.

3. **Uplink Authentication & CTR Decryption Engine**:
   - Reconstructs $B_0$ authentication blocks and verifies 32-bit MIC under `NwkSKey`.
   - Enforces strict 32-bit Frame Counter (`FCntUp`) anti-replay tracking with $2^{16}$ rollover window guards.
   - Decrypts `FRMPayload` using `AppSKey` (or `NwkSKey` for MAC port 0) in AES-CTR mode.

4. **LoRa CSS Time-on-Air (ToA) & Duty Cycle Calculator**:
   - Symbol duration:
     $$T_{\text{sym}} = \frac{2^{\text{SF}}}{\text{BW}_{\text{kHz}}}\text{ ms}$$
   - Preamble duration:
     $$T_{\text{preamble}} = (N_{\text{preamble}} + 4.25) \cdot T_{\text{sym}}$$
   - Payload symbol count:
     $$n_{\text{payload}} = 8 + \max\left(0, \left\lceil \frac{8 \cdot PL - 4 \cdot SF + 28 + 16 \cdot CRC - 20 \cdot H}{4 \cdot (SF - 2 \cdot DE)} \right\rceil \cdot (CR + 4)\right)$$
   - Total Time-on-Air:
     $$T_{\text{ToA}} = T_{\text{preamble}} + n_{\text{payload}} \cdot T_{\text{sym}}$$
   - Statutory 1% duty cycle off-time enforcement:
     $$T_{\text{off}} = 99.0 \cdot T_{\text{ToA}}$$

5. **Regional Frequency Band & Statutory Clamp Enforcement**:
   - **India `IN865`**: 865.0 MHz to 867.0 MHz band enforcement; validation of mandatory default join channels (865.0625, 865.4025, 865.9850 MHz); EIRP clamp at 30.0 dBm (1.0 W).
   - **Europe `EU868`**: 863.0 MHz to 870.0 MHz band validation; 1.0% duty cycle quota enforcement.

6. **10-Rule Sovereign LoRaWAN Security Posture Auditor**:
   - Evaluates gateway operational configurations against 10 strict industrial security rules.
   - Computes weighted deduction-based posture scores:
     $$S_{\text{posture}} = \max\left(0, 100 - \sum \text{Deductions}\right)$$
   - Exports reports to ANSI colored terminal tables, canonical JSON, and OASIS SARIF v2.1.0 for CI/CD DevSecOps pipelines.

---

## 10-Rule Security Posture Evaluation Matrix

| Rule ID | Severity | Deduction | CWE ID | Rule Name | Description |
|:---|:---:|:---:|:---:|:---|:---|
| **LH-LORA-001** | CRITICAL | -25 | CWE-327 | Mandatory Dynamic OTAA Join Enforcement | Gateway strictly mandates dynamic OTAA and rejects insecure static ABP provisioning. |
| **LH-LORA-002** | CRITICAL | -25 | CWE-294 | DevNonce Anti-Replay Store & 32-Bit FCnt Guard | Persistent DevNonce database and strict 32-bit frame counter monotonicity validation. |
| **LH-LORA-003** | CRITICAL | -25 | CWE-319 | Elimination of Unencrypted Semtech UDP Forwarder | Banning legacy Semtech UDP (port 1700) in favor of sovereign local join server architecture. |
| **LH-LORA-004** | HIGH | -10 | CWE-326 | AppKey Minimum Entropy & Weak Key Blacklist | Enforcing cryptographically random 128-bit AppKeys and rejecting manufacturer defaults. |
| **LH-LORA-005** | HIGH | -10 | CWE-208 | Constant-Time AES-CMAC MIC Verification | Side-channel timing attack protection and immediate drop of invalid frames at the edge. |
| **LH-LORA-006** | HIGH | -10 | CWE-20 | Regional Band Plan & EIRP Limit Enforcement | Enforcing regional spectrum boundaries (IN865/EU868) and statutory transmit power caps. |
| **LH-LORA-007** | HIGH | -10 | CWE-300 | Local Gateway Backhaul Mutual TLS (mTLS) | Mandating certificate-based mTLS and binding internal telemetry brokers to loopback. |
| **LH-LORA-008** | MEDIUM | -4 | CWE-345 | ADR Spoof Guard & Physical RSSI/SNR Check | Validating Adaptive Data Rate commands against physical RF link budget plausibility. |
| **LH-LORA-009** | MEDIUM | -4 | CWE-320 | Secure Key Storage at Rest & Key Ephemerality | Hardware keystore encryption for root keys and immediate memory zeroization of retired sessions. |
| **LH-LORA-010** | LOW | -1 | CWE-778 | RF Jamming Detection & Telemetry Logging | Continuous noise floor monitoring for RF jamming alerts and structured security event logging. |

---

## Architecture & Directory Layout

```
lh-lorawan-sovereign-gateway/
├── bin/                        # Compiled executable binaries
│   └── lh-lorawan              # Unified C11 CLI tool
├── include/                    # C11 API headers
│   ├── aes128_cmac.h           # FIPS 197 & RFC 4493 clean-room declarations
│   ├── exporters.h             # Table, JSON, and OASIS SARIF v2.1.0 formatting
│   ├── json_parser.h           # Zero-dependency policy & frame JSON parser
│   ├── lorawan_auditor.h       # 10-rule posture evaluation engine
│   ├── lorawan_mac.h           # OTAA join server, uplink verifier, ToA calculator
│   └── lorawan_types.h         # Core data structures and enumerations
├── src/                        # C11 source implementations
│   ├── aes128_cmac.c           # AES-128, GF(2^8) math, CMAC, CTR mode
│   ├── exporters.c             # Formatted terminal and machine-readable output
│   ├── json_parser.c           # Parser & hex byte conversion routines
│   ├── lorawan_auditor.c       # Posture evaluation implementation
│   ├── lorawan_mac.c           # MAC processing, session management, ToA math
│   └── main.c                  # Unified CLI driver
├── fixtures/                   # Enterprise policy and frame fixtures
│   ├── hardened_lorawan_policy.json   # 100/100 score compliance fixture
│   ├── vulnerable_lorawan_policy.json # 0/100 score failed compliance fixture
│   └── sample_lorawan_frames.json     # Authenticated IN865 frames
├── tests/                      # Verification test suite
│   └── test_runner.c           # 112+ comprehensive unit & integration tests
├── .github/workflows/          # Automated GitHub Actions CI
│   └── ci.yml                  # Dual GCC & Clang automated matrix verification
├── CHANGELOG.md                # Release documentation
├── CODE_OF_CONDUCT.md          # Contributor Covenant standard
├── CONTRIBUTING.md             # Developer guidelines
├── LICENSE                     # Apache License 2.0
├── Makefile                    # Standard build automation
├── NOTICE                      # Copyright & attribution notice
├── README.md                   # Technical documentation
└── SECURITY.md                 # Security & threat model documentation
```

---

## Build & Installation

### Prerequisites
- Any standard ISO C11 compiler (`gcc` $\ge 9.0$ or `clang` $\ge 10.0$).
- GNU Make.
- Standard C runtime libraries (`libc`, `libm`). **Zero third-party library dependencies.**

### Compilation
```bash
# Build the unified CLI binary
make all

# Build and run the comprehensive verification suite
make test

# Clean artifacts
make clean
```

---

## Command-Line Usage

### 1. Gateway Security Posture Audit (`audit`)
Scan a gateway operational policy JSON file against all 10 sovereign rules:
```bash
# Terminal table format (exit 0 on score >= 80, exit 1 on failure)
./bin/lh-lorawan audit fixtures/hardened_lorawan_policy.json

# Machine-readable JSON output
./bin/lh-lorawan audit fixtures/hardened_lorawan_policy.json --format=json

# OASIS SARIF v2.1.0 output for CI/CD security scanning
./bin/lh-lorawan audit fixtures/vulnerable_lorawan_policy.json --format=sarif --output=sarif-report.sarif
```

### 2. Sovereign OTAA Join Processing (`join-otaa`)
Verify a 23-byte `JoinRequest` frame, check `DevNonce` anti-replay, and derive session keys:
```bash
./bin/lh-lorawan join-otaa 0000112233445566770102030405060708010007f4a03e \
  --app-key=2B7E151628AED2A6ABF7158809CF4F3C \
  --join-nonce=010203 \
  --net-id=000001 \
  --dev-addr=00112233
```

### 3. Uplink Verification & Decryption (`verify-uplink`)
Verify 32-bit $B_0$ MIC, validate regional band plan, enforce FCnt monotonicity, and decrypt payload:
```bash
./bin/lh-lorawan verify-uplink 403322110000010001f7f96bff7d644f7ac2f66c0c76 \
  --nwk-skey=7504da33cd7f83015a20c4ec1c7688ff \
  --app-skey=a702552f2fa89297c0cea5d43107ebd9 \
  --dev-addr=00112233 \
  --fcnt=0 \
  --freq=865.0625 \
  --region=IN865
```

### 4. LoRa CSS Time-on-Air Calculation (`calc-toa`)
Compute exact physical packet duration and statutory duty cycle limits:
```bash
# Standard SF7 uplink at 125 kHz
./bin/lh-lorawan calc-toa --sf=7 --bw=125 --payload=16 --region=IN865

# Long-range SF12 uplink with Low Data Rate Optimization
./bin/lh-lorawan calc-toa --sf=12 --bw=125 --payload=23 --region=IN865 --format=json
```

---

## Zero Dependencies

`lh-lorawan-sovereign-gateway` requires **zero third-party libraries**:
- No external cryptographic packages (clean-room C11 AES-128 and AES-CMAC).
- No external JSON libraries (in-tree zero-allocation scanner).
- No external network framework requirements.
- Strictly adheres to ISO C11 (`-std=c11 -Wall -Wextra -Werror -pedantic -lm`).

---

## Author & Attribution

- **Author**: Sameer Tawade
- **Organization**: Logihertz Systems (OPC) Private Limited
- **Contact**: `ops@logihertz.com`

---

## License

Copyright (c) 2026 Logihertz Systems (OPC) Private Limited.  
Licensed under the **Apache License, Version 2.0**.

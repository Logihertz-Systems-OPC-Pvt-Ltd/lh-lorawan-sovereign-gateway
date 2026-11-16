# Security Policy: lh-lorawan-sovereign-gateway

Logihertz Systems (OPC) Private Limited maintains rigorous cryptographic and physical-layer operational security standards for sovereign and air-gapped LoRaWAN edge gateway deployments.

## Supported Versions

| Version | Supported          | Security Maintenance Status |
|---------|--------------------|-----------------------------|
| 0.1.x   | :white_check_mark: | Active Current Release      |
| < 0.1.0 | :x:                | Unsupported                 |

## Threat Model & Scope

The `lh-lorawan-sovereign-gateway` (`bin/lh-lorawan`) daemon processes long-range LPWAN telemetry in high-consequence critical infrastructure (defense sites, industrial scada, agricultural IoT, smart utility grids). Key threat vectors addressed in this architecture include:

- **Local OTAA Key Management**: Eradicating cloud-dependent Join Servers. Generating dynamic session keys (`NwkSKey`, `AppSKey`) directly on air-gapped gateways without external network exposure.
- **Replay & Desynchronization Attacks**: Enforcing non-volatile, persistent `DevNonce` ledgers to defeat `JoinRequest` replay attacks (CWE-294), and validating strictly monotonic 32-bit `FCntUp` frame counters.
- **Message Integrity & Forgery**: Verifying 32-bit Message Integrity Codes (`MIC`) using constant-time RFC 4493 AES-128-CMAC comparisons to prevent timing side-channel attacks and frame spoofing (CWE-353).
- **Semtech UDP Packet Forwarder Vulnerabilities**: Eliminating plaintext, unauthenticated legacy Semtech UDP (port 1700) backhauls vulnerable to man-in-the-middle packet injection (CWE-319).
- **Physical-Layer RF & Regulatory Compliance**: Enforcing India `IN865` ($865.0\text{--}867.0\text{ MHz}$) and Europe `EU868` ($863.0\text{--}870.0\text{ MHz}$) frequency plans, maximum EIRP ($\le 30.0\text{ dBm}$), and duty-cycle / Time-on-Air limits to mitigate radio frequency jamming and denial-of-service (CWE-400).
- **Memory Remanence**: Enforcing explicit zeroization of root `AppKey` materials and expired session keys from volatile memory buffers upon re-join or session termination (CWE-226).

## Reporting a Vulnerability

If you identify a security issue, cryptographic flaw, or protocol vulnerability in `lh-lorawan-sovereign-gateway`, please report it directly to:

- **Primary Contact**: Sameer Tawade (`security@logihertz.com`)
- **Operations Team**: `ops@logihertz.com`
- **PGP Encryption**: Available upon request for confidential vulnerability disclosures.
- **Report Details Required**:
  - Technical description and proof-of-concept frame payload or policy configuration
  - Affected module (`aes128_cmac.c`, `lorawan_mac.c`, `lorawan_auditor.c`, etc.)
  - Assessment of exploitability in air-gapped or RF-exposed scenarios

## Response Timeline

- **Initial Acknowledgement**: Within 24 business hours.
- **Triage & Severity Assessment**: Within 72 business hours.
- **Remediation & Advisory Release**: Coordinated disclosure within 30 calendar days.

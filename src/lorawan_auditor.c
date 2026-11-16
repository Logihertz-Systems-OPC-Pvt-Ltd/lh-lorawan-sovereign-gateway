#include "lorawan_auditor.h"
#include <stdio.h>
#include <string.h>

const char *audit_severity_to_str(audit_severity_t sev) {
    switch (sev) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:     return "HIGH";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_LOW:      return "LOW";
        case SEV_INFO:     return "INFO";
        default:           return "UNKNOWN";
    }
}

static void safe_copy(char *dst, size_t dst_sz, const char *src) {
    if (!dst || dst_sz == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, dst_sz, "%s", src);
}

void lorawan_audit_policy(const gateway_policy_t *policy, audit_report_t *report) {
    if (!policy || !report) return;

    memset(report, 0, sizeof(*report));
    safe_copy(report->policy_name, sizeof(report->policy_name), policy->policy_name);
    report->total_rules = MAX_AUDIT_RULES;

    int passed_count = 0;
    int failed_count = 0;
    int deductions = 0;

    /* Rule 1: LH-LORA-001 */
    {
        audit_finding_t *f = &report->findings[0];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-001");
        safe_copy(f->rule_name, sizeof(f->rule_name), "Mandatory Dynamic OTAA Join Enforcement");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-327");
        f->severity = SEV_CRITICAL;
        f->deduction = 25;
        f->passed = (policy->require_otaa_only && !policy->allow_abp_devices);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "Gateway strictly enforces dynamic Over-The-Air Activation (OTAA) and bans static ABP.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Maintain mandatory dynamic OTAA activation mode.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "Static ABP devices permitted or OTAA not mandated; keys subject to physical dump & replay.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set require_otaa_only: true and allow_abp_devices: false.");
        }
    }

    /* Rule 2: LH-LORA-002 */
    {
        audit_finding_t *f = &report->findings[1];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-002");
        safe_copy(f->rule_name, sizeof(f->rule_name), "DevNonce Anti-Replay Store & 32-Bit FCnt Monotonicity");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-294");
        f->severity = SEV_CRITICAL;
        f->deduction = 25;
        f->passed = (policy->persist_devnonce_store && policy->strict_32bit_fcnt_anti_replay);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "DevNonce persistent replay store active; strict 32-bit FCnt monotonicity enforced.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Maintain persistent DevNonce store and strict 32-bit frame counter checks.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "DevNonce store volatile or 32-bit FCnt rollover anti-replay disabled.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set persist_devnonce_store: true and strict_32bit_fcnt_anti_replay: true.");
        }
    }

    /* Rule 3: LH-LORA-003 */
    {
        audit_finding_t *f = &report->findings[2];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-003");
        safe_copy(f->rule_name, sizeof(f->rule_name), "Elimination of Unencrypted Semtech UDP Forwarder");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-319");
        f->severity = SEV_CRITICAL;
        f->deduction = 25;
        f->passed = (policy->disable_legacy_semtech_udp && policy->sovereign_local_join_server);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "Unencrypted Semtech UDP (port 1700) eliminated; local air-gapped Join Server active.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Maintain air-gapped sovereign architecture with Semtech UDP disabled.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "Semtech UDP forwarder active or relying on external cloud join server.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set disable_legacy_semtech_udp: true and sovereign_local_join_server: true.");
        }
    }

    /* Rule 4: LH-LORA-004 */
    {
        audit_finding_t *f = &report->findings[3];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-004");
        safe_copy(f->rule_name, sizeof(f->rule_name), "AppKey Minimum Entropy & Weak Key Blacklist");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-326");
        f->severity = SEV_HIGH;
        f->deduction = 10;
        f->passed = (policy->reject_default_weak_appkeys && policy->min_appkey_entropy_bits >= 128);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "Weak AppKey blacklist active; 128-bit root cryptographic entropy enforced.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Enforce cryptographically random 128-bit AppKeys at commissioning.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "Default factory AppKeys allowed or entropy requirement below 128 bits.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set reject_default_weak_appkeys: true and min_appkey_entropy_bits >= 128.");
        }
    }

    /* Rule 5: LH-LORA-005 */
    {
        audit_finding_t *f = &report->findings[4];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-005");
        safe_copy(f->rule_name, sizeof(f->rule_name), "Constant-Time AES-CMAC MIC Verification");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-208");
        f->severity = SEV_HIGH;
        f->deduction = 10;
        f->passed = (policy->constant_time_mic_verification && policy->drop_invalid_mic_at_edge);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "Constant-time comparison protects against side channels; invalid MIC dropped at edge.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Keep constant-time verification and edge dropping enabled.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "Variable-time MIC check vulnerable to timing attacks or corrupted frames forwarded.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set constant_time_mic_verification: true and drop_invalid_mic_at_edge: true.");
        }
    }

    /* Rule 6: LH-LORA-006 */
    {
        audit_finding_t *f = &report->findings[5];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-006");
        safe_copy(f->rule_name, sizeof(f->rule_name), "Regional Band Plan & EIRP Limit Enforcement");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-20");
        f->severity = SEV_HIGH;
        f->deduction = 10;
        f->passed = (policy->enforce_regional_band_limits && policy->max_eirp_dbm > 0.0 && policy->max_eirp_dbm <= 30.0);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "Regional RF band boundaries and maximum EIRP clamped within statutory limits.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Maintain regional regulatory spectrum frequency and power clamps.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "Regional frequency limits unvalidated or transmit EIRP exceeds statutory threshold.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set enforce_regional_band_limits: true and clamp max_eirp_dbm <= 30.0.");
        }
    }

    /* Rule 7: LH-LORA-007 */
    {
        audit_finding_t *f = &report->findings[6];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-007");
        safe_copy(f->rule_name, sizeof(f->rule_name), "Local Gateway Backhaul Mutual TLS (mTLS)");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-300");
        f->severity = SEV_HIGH;
        f->deduction = 10;
        f->passed = (policy->local_mqtt_mtls_required && policy->broker_bind_loopback_only);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "Backhaul requires certificate-based mTLS; internal broker isolated to loopback interface.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Maintain mTLS backhaul and loopback broker binding.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "Plaintext backhaul telemetry permitted or broker exposed on external interfaces.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set local_mqtt_mtls_required: true and broker_bind_loopback_only: true.");
        }
    }

    /* Rule 8: LH-LORA-008 */
    {
        audit_finding_t *f = &report->findings[7];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-008");
        safe_copy(f->rule_name, sizeof(f->rule_name), "ADR Spoof Guard & Physical RSSI/SNR Verification");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-345");
        f->severity = SEV_MEDIUM;
        f->deduction = 4;
        f->passed = (policy->adr_spoof_guard_enabled && policy->rssi_snr_plausibility_check);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "ADR downlink commands validated against physical RF link budget (RSSI/SNR).");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Maintain ADR RF plausibility verification.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "ADR downlinks unverified against physical RF link budget; risk of silent starvation.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set adr_spoof_guard_enabled: true and rssi_snr_plausibility_check: true.");
        }
    }

    /* Rule 9: LH-LORA-009 */
    {
        audit_finding_t *f = &report->findings[8];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-009");
        safe_copy(f->rule_name, sizeof(f->rule_name), "Secure Key Storage at Rest & Key Ephemerality");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-320");
        f->severity = SEV_MEDIUM;
        f->deduction = 4;
        f->passed = (policy->encrypt_root_keys_at_rest && policy->zeroize_old_session_keys);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "AppKeys encrypted at rest in hardware keystore; retired session keys zeroized.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Keep encryption at rest and active zeroization enabled.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "Root keys stored in clear flash or retired session keys retain state in RAM.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set encrypt_root_keys_at_rest: true and zeroize_old_session_keys: true.");
        }
    }

    /* Rule 10: LH-LORA-010 */
    {
        audit_finding_t *f = &report->findings[9];
        safe_copy(f->rule_id, sizeof(f->rule_id), "LH-LORA-010");
        safe_copy(f->rule_name, sizeof(f->rule_name), "RF Jamming Detection & Security Telemetry Logging");
        safe_copy(f->cwe_id, sizeof(f->cwe_id), "CWE-778");
        f->severity = SEV_LOW;
        f->deduction = 1;
        f->passed = (policy->jamming_noise_floor_monitor && policy->log_join_and_mic_anomalies);
        if (f->passed) {
            passed_count++;
            safe_copy(f->details, sizeof(f->details), "Continuous noise floor monitoring and structured security anomaly logging active.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Maintain continuous RF telemetry monitoring.");
        } else {
            failed_count++;
            deductions += f->deduction;
            safe_copy(f->details, sizeof(f->details), "Absence of RF noise floor monitoring and join/MIC anomaly logging.");
            safe_copy(f->recommendation, sizeof(f->recommendation), "Set jamming_noise_floor_monitor: true and log_join_and_mic_anomalies: true.");
        }
    }

    report->passed_rules = passed_count;
    report->failed_rules = failed_count;
    report->total_deductions = deductions;
    report->posture_score = (100 - deductions > 0) ? (100 - deductions) : 0;
}

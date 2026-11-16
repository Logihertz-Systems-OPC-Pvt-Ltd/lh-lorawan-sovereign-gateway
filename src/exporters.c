#include "exporters.h"
#include "lorawan_auditor.h"
#include "json_parser.h"
#include "lorawan_mac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void export_audit_table(const audit_report_t *report, FILE *out) {
    if (!report || !out) return;

    fprintf(out, "\n========================================================================================\n");
    fprintf(out, "        LOGIHERTZ SOVEREIGN LORAWAN GATEWAY SECURITY AUDIT REPORT\n");
    fprintf(out, "========================================================================================\n");
    fprintf(out, " Policy Profile:  %s\n", report->policy_name);
    fprintf(out, " Total Rules:     %d\n", report->total_rules);
    fprintf(out, " Passed:          \033[1;32m%d\033[0m\n", report->passed_rules);
    fprintf(out, " Failed:          \033[1;31m%d\033[0m\n", report->failed_rules);
    fprintf(out, " Deductions:      -%d\n", report->total_deductions);
    if (report->posture_score >= 80) {
        fprintf(out, " Posture Score:   \033[1;32m%d / 100 [PASS]\033[0m\n", report->posture_score);
    } else {
        fprintf(out, " Posture Score:   \033[1;31m%d / 100 [FAIL]\033[0m\n", report->posture_score);
    }
    fprintf(out, "----------------------------------------------------------------------------------------\n");
    fprintf(out, " %-12s | %-8s | %-4s | %-6s | %-44s\n", "Rule ID", "Severity", "Ded.", "Status", "Rule Name");
    fprintf(out, "----------------------------------------------------------------------------------------\n");

    for (int i = 0; i < report->total_rules; i++) {
        const audit_finding_t *f = &report->findings[i];
        const char *status_str = f->passed ? "\033[1;32mPASS\033[0m" : "\033[1;31mFAIL\033[0m";
        const char *sev_str = audit_severity_to_str(f->severity);
        fprintf(out, " %-12s | %-8s | -%-3d | %-15s | %-44s\n",
                f->rule_id, sev_str, f->passed ? 0 : f->deduction, status_str, f->rule_name);
        if (!f->passed) {
            fprintf(out, "   -> Details:        %s\n", f->details);
            fprintf(out, "   -> Recommendation: %s\n", f->recommendation);
        }
    }
    fprintf(out, "========================================================================================\n\n");
}

void export_audit_json(const audit_report_t *report, FILE *out) {
    if (!report || !out) return;

    fprintf(out, "{\n");
    fprintf(out, "  \"policy_name\": \"%s\",\n", report->policy_name);
    fprintf(out, "  \"total_rules\": %d,\n", report->total_rules);
    fprintf(out, "  \"passed_rules\": %d,\n", report->passed_rules);
    fprintf(out, "  \"failed_rules\": %d,\n", report->failed_rules);
    fprintf(out, "  \"total_deductions\": %d,\n", report->total_deductions);
    fprintf(out, "  \"posture_score\": %d,\n", report->posture_score);
    fprintf(out, "  \"status\": \"%s\",\n", (report->posture_score >= 80) ? "PASS" : "FAIL");
    fprintf(out, "  \"findings\": [\n");

    for (int i = 0; i < report->total_rules; i++) {
        const audit_finding_t *f = &report->findings[i];
        fprintf(out, "    {\n");
        fprintf(out, "      \"rule_id\": \"%s\",\n", f->rule_id);
        fprintf(out, "      \"rule_name\": \"%s\",\n", f->rule_name);
        fprintf(out, "      \"cwe_id\": \"%s\",\n", f->cwe_id);
        fprintf(out, "      \"severity\": \"%s\",\n", audit_severity_to_str(f->severity));
        fprintf(out, "      \"deduction\": %d,\n", f->deduction);
        fprintf(out, "      \"passed\": %s,\n", f->passed ? "true" : "false");
        fprintf(out, "      \"details\": \"%s\",\n", f->details);
        fprintf(out, "      \"recommendation\": \"%s\"\n", f->recommendation);
        fprintf(out, "    }%s\n", (i + 1 < report->total_rules) ? "," : "");
    }

    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

static const char *sarif_level_str(audit_severity_t sev) {
    switch (sev) {
        case SEV_CRITICAL:
        case SEV_HIGH:
            return "error";
        case SEV_MEDIUM:
            return "warning";
        case SEV_LOW:
        case SEV_INFO:
        default:
            return "note";
    }
}

void export_audit_sarif(const audit_report_t *report, FILE *out) {
    if (!report || !out) return;

    fprintf(out, "{\n");
    fprintf(out, "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n");
    fprintf(out, "  \"version\": \"2.1.0\",\n");
    fprintf(out, "  \"runs\": [\n");
    fprintf(out, "    {\n");
    fprintf(out, "      \"tool\": {\n");
    fprintf(out, "        \"driver\": {\n");
    fprintf(out, "          \"name\": \"lh-lorawan-sovereign-gateway\",\n");
    fprintf(out, "          \"version\": \"0.1.0\",\n");
    fprintf(out, "          \"informationUri\": \"https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-lorawan-sovereign-gateway\",\n");
    fprintf(out, "          \"rules\": [\n");

    for (int i = 0; i < report->total_rules; i++) {
        const audit_finding_t *f = &report->findings[i];
        fprintf(out, "            {\n");
        fprintf(out, "              \"id\": \"%s\",\n", f->rule_id);
        fprintf(out, "              \"name\": \"%s\",\n", f->rule_name);
        fprintf(out, "              \"shortDescription\": { \"text\": \"%s\" },\n", f->rule_name);
        fprintf(out, "              \"help\": { \"text\": \"%s\" },\n", f->recommendation);
        fprintf(out, "              \"defaultConfiguration\": { \"level\": \"%s\" }\n", sarif_level_str(f->severity));
        fprintf(out, "            }%s\n", (i + 1 < report->total_rules) ? "," : "");
    }

    fprintf(out, "          ]\n");
    fprintf(out, "        }\n");
    fprintf(out, "      },\n");
    fprintf(out, "      \"results\": [\n");

    int printed_results = 0;
    for (int i = 0; i < report->total_rules; i++) {
        const audit_finding_t *f = &report->findings[i];
        if (!f->passed) {
            if (printed_results > 0) fprintf(out, ",\n");
            fprintf(out, "        {\n");
            fprintf(out, "          \"ruleId\": \"%s\",\n", f->rule_id);
            fprintf(out, "          \"level\": \"%s\",\n", sarif_level_str(f->severity));
            fprintf(out, "          \"message\": { \"text\": \"%s. %s\" },\n", f->details, f->recommendation);
            fprintf(out, "          \"locations\": [\n");
            fprintf(out, "            {\n");
            fprintf(out, "              \"physicalLocation\": {\n");
            fprintf(out, "                \"artifactLocation\": { \"uri\": \"%s\" }\n", report->policy_name);
            fprintf(out, "              }\n");
            fprintf(out, "            }\n");
            fprintf(out, "          ]\n");
            fprintf(out, "        }");
            printed_results++;
        }
    }
    if (printed_results > 0) fprintf(out, "\n");

    fprintf(out, "      ]\n");
    fprintf(out, "    }\n");
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

void export_toa_table(const lora_toa_params_t *params, const lora_toa_result_t *result, FILE *out) {
    if (!params || !result || !out) return;

    fprintf(out, "\n========================================================================================\n");
    fprintf(out, "              LOGIHERTZ LORA CHIRP SPREAD SPECTRUM TIME-ON-AIR REPORT\n");
    fprintf(out, "========================================================================================\n");
    fprintf(out, " Regional Plan:          %s\n", lorawan_region_to_str(params->region));
    fprintf(out, " Spreading Factor (SF):  SF%d\n", params->sf);
    fprintf(out, " Bandwidth (BW):         %.1f kHz\n", params->bw_khz);
    fprintf(out, " Coding Rate (CR):       4/%d\n", params->cr + 4);
    fprintf(out, " Payload Length:         %zu bytes\n", params->payload_bytes);
    fprintf(out, " Preamble Symbols:       %d symbols\n", (params->preamble_symbols > 0) ? params->preamble_symbols : 8);
    fprintf(out, " Low Data Rate Opt (DE): %s\n", params->low_dr_opt ? "ENABLED" : "DISABLED");
    fprintf(out, " Header Mode:            %s\n", params->explicit_header ? "EXPLICIT" : "IMPLICIT");
    fprintf(out, " Payload CRC:            %s\n", params->crc_enabled ? "ENABLED" : "DISABLED");
    fprintf(out, "----------------------------------------------------------------------------------------\n");
    fprintf(out, " Symbol Duration (T_sym):       %.4f ms\n", result->t_sym_ms);
    fprintf(out, " Preamble Duration (T_preamble):%.2f ms\n", result->t_preamble_ms);
    fprintf(out, " Payload Symbol Count:          %.2f symbols\n", result->n_payload_sym);
    fprintf(out, " Payload Duration (T_payload):  %.2f ms\n", result->t_payload_ms);
    fprintf(out, " Total Time-on-Air (T_ToA):     \033[1;36m%.2f ms\033[0m\n", result->t_toa_ms);
    fprintf(out, " Minimum Required Off-Time:     \033[1;33m%.2f ms\033[0m (1%% Duty Cycle: 99 * T_ToA)\n", result->t_off_ms);
    fprintf(out, " Duty Cycle Compliance:         \033[1;32m%s\033[0m\n", result->duty_cycle_compliant ? "COMPLIANT" : "VIOLATION");
    fprintf(out, "========================================================================================\n\n");
}

void export_toa_json(const lora_toa_params_t *params, const lora_toa_result_t *result, FILE *out) {
    if (!params || !result || !out) return;

    fprintf(out, "{\n");
    fprintf(out, "  \"region\": \"%s\",\n", lorawan_region_to_str(params->region));
    fprintf(out, "  \"sf\": %d,\n", params->sf);
    fprintf(out, "  \"bw_khz\": %.1f,\n", params->bw_khz);
    fprintf(out, "  \"cr\": \"4/%d\",\n", params->cr + 4);
    fprintf(out, "  \"payload_bytes\": %zu,\n", params->payload_bytes);
    fprintf(out, "  \"preamble_symbols\": %d,\n", (params->preamble_symbols > 0) ? params->preamble_symbols : 8);
    fprintf(out, "  \"low_dr_opt\": %s,\n", params->low_dr_opt ? "true" : "false");
    fprintf(out, "  \"explicit_header\": %s,\n", params->explicit_header ? "true" : "false");
    fprintf(out, "  \"crc_enabled\": %s,\n", params->crc_enabled ? "true" : "false");
    fprintf(out, "  \"t_sym_ms\": %.4f,\n", result->t_sym_ms);
    fprintf(out, "  \"t_preamble_ms\": %.2f,\n", result->t_preamble_ms);
    fprintf(out, "  \"n_payload_sym\": %.2f,\n", result->n_payload_sym);
    fprintf(out, "  \"t_payload_ms\": %.2f,\n", result->t_payload_ms);
    fprintf(out, "  \"t_toa_ms\": %.2f,\n", result->t_toa_ms);
    fprintf(out, "  \"t_off_ms\": %.2f,\n", result->t_off_ms);
    fprintf(out, "  \"duty_cycle_compliant\": %s\n", result->duty_cycle_compliant ? "true" : "false");
    fprintf(out, "}\n");
}

void export_join_request_info(
    const lorawan_join_request_t *req,
    bool mic_valid,
    uint32_t assigned_dev_addr,
    const uint8_t nwk_skey[16],
    const uint8_t app_skey[16],
    FILE *out
) {
    if (!req || !out) return;

    char join_eui_hex[20], dev_eui_hex[20];
    char nwk_hex[36], app_hex[36];
    bytes_to_hex(req->join_eui, 8, join_eui_hex, sizeof(join_eui_hex));
    bytes_to_hex(req->dev_eui, 8, dev_eui_hex, sizeof(dev_eui_hex));
    if (nwk_skey) bytes_to_hex(nwk_skey, 16, nwk_hex, sizeof(nwk_hex)); else strcpy(nwk_hex, "N/A");
    if (app_skey) bytes_to_hex(app_skey, 16, app_hex, sizeof(app_hex)); else strcpy(app_hex, "N/A");

    fprintf(out, "\n========================================================================================\n");
    fprintf(out, "             LOGIHERTZ LORAWAN OTAA JOIN-REQUEST TELEMETRY\n");
    fprintf(out, "========================================================================================\n");
    fprintf(out, " Message Type (MHDR):    0x%02X (Join-Request)\n", req->mhdr);
    fprintf(out, " JoinEUI / AppEUI:       %s\n", join_eui_hex);
    fprintf(out, " DevEUI:                 %s\n", dev_eui_hex);
    fprintf(out, " DevNonce:               0x%04X (%u)\n", req->dev_nonce, req->dev_nonce);
    fprintf(out, " Frame MIC:              0x%08X\n", req->mic);
    fprintf(out, " MIC Verification:       %s\n", mic_valid ? "\033[1;32mVALID [PASS]\033[0m" : "\033[1;31mINVALID [FAIL]\033[0m");
    if (mic_valid) {
        fprintf(out, " Assigned DevAddr:       0x%08X\n", assigned_dev_addr);
        fprintf(out, " Derived NwkSKey:        %s\n", nwk_hex);
        fprintf(out, " Derived AppSKey:        %s\n", app_hex);
        fprintf(out, " Session Status:         \033[1;32mACTIVATED (Air-Gapped Sovereign Join)\033[0m\n");
    }
    fprintf(out, "========================================================================================\n\n");
}

void export_uplink_frame_info(
    const lorawan_uplink_frame_t *frame,
    bool mic_valid,
    const uint8_t *decrypted_payload,
    size_t decrypted_len,
    FILE *out
) {
    if (!frame || !out) return;

    char raw_payload_hex[516];
    char dec_payload_hex[516];
    bytes_to_hex(frame->frm_payload, frame->frm_payload_len, raw_payload_hex, sizeof(raw_payload_hex));
    if (decrypted_payload && decrypted_len > 0) {
        bytes_to_hex(decrypted_payload, decrypted_len, dec_payload_hex, sizeof(dec_payload_hex));
    } else {
        strcpy(dec_payload_hex, "");
    }

    fprintf(out, "\n========================================================================================\n");
    fprintf(out, "              LOGIHERTZ LORAWAN UPLINK TELEMETRY VERIFICATION\n");
    fprintf(out, "========================================================================================\n");
    fprintf(out, " Message Type (MHDR):    0x%02X (%s)\n",
            frame->mhdr,
            ((frame->mhdr >> 5) == MTYPE_CONFIRMED_DATA_UP) ? "Confirmed Data Up" : "Unconfirmed Data Up");
    fprintf(out, " Device Address:         0x%08X\n", frame->dev_addr);
    fprintf(out, " Frame Control (FCtrl):  0x%02X (FOptsLen: %zu)\n", frame->fctrl, frame->fopts_len);
    fprintf(out, " Frame Counter (FCntUp): %u (32-bit Anti-Replay Verified)\n", frame->fcnt);
    fprintf(out, " Port (FPort):           %u\n", frame->fport);
    fprintf(out, " RF Frequency:           %.4f MHz\n", frame->frequency_mhz);
    fprintf(out, " Ciphertext Payload:     %s (%zu bytes)\n", raw_payload_hex, frame->frm_payload_len);
    fprintf(out, " Frame MIC:              0x%08X\n", frame->mic);
    fprintf(out, " MIC Integrity:          %s\n", mic_valid ? "\033[1;32mAUTHENTICATED [PASS]\033[0m" : "\033[1;31mTAMPERED/MISMATCH [FAIL]\033[0m");
    if (mic_valid && decrypted_len > 0) {
        fprintf(out, " Decrypted Plaintext:    \033[1;36m%s\033[0m\n", dec_payload_hex);
        fprintf(out, " Plaintext ASCII:        \"");
        for (size_t i = 0; i < decrypted_len; i++) {
            char c = (char)decrypted_payload[i];
            if (c >= 32 && c <= 126) fputc(c, out);
            else fputc('.', out);
        }
        fprintf(out, "\"\n");
    }
    fprintf(out, "========================================================================================\n\n");
}

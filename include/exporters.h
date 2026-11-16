#ifndef EXPORTERS_H
#define EXPORTERS_H

#include "lorawan_types.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Audit Report Exporters */
void export_audit_table(const audit_report_t *report, FILE *out);
void export_audit_json(const audit_report_t *report, FILE *out);
void export_audit_sarif(const audit_report_t *report, FILE *out);

/* Time-on-Air Exporters */
void export_toa_table(const lora_toa_params_t *params, const lora_toa_result_t *result, FILE *out);
void export_toa_json(const lora_toa_params_t *params, const lora_toa_result_t *result, FILE *out);

/* Frame Inspection Exporters */
void export_join_request_info(
    const lorawan_join_request_t *req,
    bool mic_valid,
    uint32_t assigned_dev_addr,
    const uint8_t nwk_skey[16],
    const uint8_t app_skey[16],
    FILE *out
);

void export_uplink_frame_info(
    const lorawan_uplink_frame_t *frame,
    bool mic_valid,
    const uint8_t *decrypted_payload,
    size_t decrypted_len,
    FILE *out
);

#ifdef __cplusplus
}
#endif

#endif /* EXPORTERS_H */

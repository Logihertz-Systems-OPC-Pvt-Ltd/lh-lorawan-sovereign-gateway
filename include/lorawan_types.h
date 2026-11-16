#ifndef LORAWAN_TYPES_H
#define LORAWAN_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    REGION_IN865 = 0,
    REGION_EU868 = 1,
    REGION_UNKNOWN = 2
} lora_region_t;

typedef enum {
    MTYPE_JOIN_REQUEST         = 0x00,
    MTYPE_JOIN_ACCEPT          = 0x01,
    MTYPE_UNCONFIRMED_DATA_UP  = 0x02,
    MTYPE_UNCONFIRMED_DATA_DOWN= 0x03,
    MTYPE_CONFIRMED_DATA_UP    = 0x04,
    MTYPE_CONFIRMED_DATA_DOWN  = 0x05,
    MTYPE_REJOIN_REQUEST       = 0x06,
    MTYPE_PROPRIETARY          = 0x07
} lora_mtype_t;

typedef enum {
    LORA_OK                    = 0,
    LORA_ERR_INVALID_LENGTH    = 1,
    LORA_ERR_MIC_MISMATCH      = 2,
    LORA_ERR_DEVNONCE_REPLAY   = 3,
    LORA_ERR_FCNT_REPLAY       = 4,
    LORA_ERR_INVALID_REGION    = 5,
    LORA_ERR_INVALID_KEY       = 6,
    LORA_ERR_PARSE_FAILED      = 7,
    LORA_ERR_POLICY_VIOLATION  = 8
} lora_error_t;

typedef enum {
    SEV_CRITICAL = 0,
    SEV_HIGH     = 1,
    SEV_MEDIUM   = 2,
    SEV_LOW      = 3,
    SEV_INFO     = 4
} audit_severity_t;

/* OTAA Join Request (23 bytes) */
typedef struct {
    uint8_t mhdr;
    uint8_t join_eui[8]; // AppEUI
    uint8_t dev_eui[8];
    uint16_t dev_nonce;
    uint32_t mic;
} lorawan_join_request_t;

/* Active Device Session */
typedef struct {
    uint8_t dev_eui[8];
    uint32_t dev_addr;
    uint8_t nwk_skey[16];
    uint8_t app_skey[16];
    uint32_t last_fcnt_up;
    uint16_t last_dev_nonce;
    bool has_dev_nonce;
    bool has_fcnt_up;
    bool is_active;
} lorawan_session_t;

/* Uplink Data Frame */
typedef struct {
    uint8_t mhdr;
    uint32_t dev_addr;
    uint8_t fctrl;
    uint32_t fcnt; // 32-bit frame counter
    uint8_t fopts[16];
    size_t fopts_len;
    uint8_t fport;
    uint8_t frm_payload[256];
    size_t frm_payload_len;
    uint32_t mic;
    double frequency_mhz;
    int sf;
    double bw_khz;
    int cr;
} lorawan_uplink_frame_t;

/* Time-on-Air calculation inputs */
typedef struct {
    int sf;                  /* Spreading factor: 7..12 */
    double bw_khz;           /* Bandwidth: 125, 250, 500 */
    int cr;                  /* Coding rate: 1 (4/5), 2 (4/6), 3 (4/7), 4 (4/8) */
    size_t payload_bytes;    /* Byte count of PHYPayload */
    int preamble_symbols;    /* Typically 8 */
    bool explicit_header;    /* Typically true */
    bool low_dr_opt;         /* Low data rate optimization: 1 for SF11/SF12 @ 125kHz */
    bool crc_enabled;        /* Typically true for uplinks */
    lora_region_t region;    /* IN865 or EU868 */
} lora_toa_params_t;

/* Time-on-Air calculation output */
typedef struct {
    double t_sym_ms;
    double t_preamble_ms;
    double n_payload_sym;
    double t_payload_ms;
    double t_toa_ms;
    double t_off_ms;         /* Required off-time for 1% duty cycle: 99 * T_ToA */
    bool duty_cycle_compliant;
} lora_toa_result_t;

/* Gateway Security Policy */
typedef struct {
    char policy_name[64];
    bool require_otaa_only;
    bool allow_abp_devices;
    bool persist_devnonce_store;
    bool strict_32bit_fcnt_anti_replay;
    bool disable_legacy_semtech_udp;
    bool sovereign_local_join_server;
    bool reject_default_weak_appkeys;
    int min_appkey_entropy_bits;
    bool constant_time_mic_verification;
    bool drop_invalid_mic_at_edge;
    bool enforce_regional_band_limits;
    double max_eirp_dbm;
    bool local_mqtt_mtls_required;
    bool broker_bind_loopback_only;
    bool adr_spoof_guard_enabled;
    bool rssi_snr_plausibility_check;
    bool encrypt_root_keys_at_rest;
    bool zeroize_old_session_keys;
    bool jamming_noise_floor_monitor;
    bool log_join_and_mic_anomalies;
} gateway_policy_t;

/* Single audit finding */
typedef struct {
    char rule_id[16];
    char rule_name[80];
    char cwe_id[16];
    audit_severity_t severity;
    int deduction;
    bool passed;
    char details[256];
    char recommendation[256];
} audit_finding_t;

#define MAX_AUDIT_RULES 10

/* Audit report */
typedef struct {
    char policy_name[64];
    int total_rules;
    int passed_rules;
    int failed_rules;
    int total_deductions;
    int posture_score;
    audit_finding_t findings[MAX_AUDIT_RULES];
} audit_report_t;

#ifdef __cplusplus
}
#endif

#endif /* LORAWAN_TYPES_H */

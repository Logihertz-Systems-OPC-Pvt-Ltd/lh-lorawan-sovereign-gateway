#ifndef LORAWAN_MAC_H
#define LORAWAN_MAC_H

#include "lorawan_types.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* String conversions & region utilities */
const char *lora_error_to_str(lora_error_t err);
const char *lorawan_region_to_str(lora_region_t region);
lora_region_t lorawan_str_to_region(const char *str);
bool lorawan_is_frequency_valid(double freq_mhz, lora_region_t region);
bool lorawan_is_in865_join_frequency(double freq_mhz);

/* Session management */
void lorawan_init_session(lorawan_session_t *session, const uint8_t dev_eui[8], uint32_t dev_addr);

/* OTAA Session Key Derivation (FIPS 197 / LoRaWAN 1.0.x) */
void lorawan_derive_session_keys(
    const uint8_t app_key[16],
    const uint8_t join_nonce[3],
    const uint8_t net_id[3],
    uint16_t dev_nonce,
    uint8_t nwk_skey[16],
    uint8_t app_skey[16]
);

/* OTAA Join-Request parsing and processing */
lora_error_t lorawan_parse_join_request(
    const uint8_t *raw,
    size_t len,
    lorawan_join_request_t *req
);

lora_error_t lorawan_process_join_request(
    const uint8_t *raw,
    size_t len,
    const uint8_t app_key[16],
    const uint8_t join_nonce[3],
    const uint8_t net_id[3],
    uint32_t assigned_dev_addr,
    lorawan_session_t *session,
    uint8_t *join_accept_out,
    size_t *join_accept_len
);

/* Uplink Frame parsing, MIC verification, and payload decryption */
lora_error_t lorawan_parse_uplink_frame(
    const uint8_t *raw,
    size_t len,
    lorawan_uplink_frame_t *frame
);

lora_error_t lorawan_verify_and_decrypt_uplink(
    const uint8_t *raw,
    size_t len,
    double freq_mhz,
    lora_region_t region,
    lorawan_session_t *session,
    lorawan_uplink_frame_t *frame,
    uint8_t *decrypted_payload,
    size_t *decrypted_len
);

/* CSS Time-on-Air (ToA) calculation */
void lora_calculate_toa(const lora_toa_params_t *params, lora_toa_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* LORAWAN_MAC_H */

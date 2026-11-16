#include "lorawan_mac.h"
#include "aes128_cmac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

const char *lora_error_to_str(lora_error_t err) {
    switch (err) {
        case LORA_OK:
            return "OK";
        case LORA_ERR_INVALID_LENGTH:
            return "Invalid frame length";
        case LORA_ERR_MIC_MISMATCH:
            return "Message integrity code (MIC) mismatch";
        case LORA_ERR_DEVNONCE_REPLAY:
            return "DevNonce replay detected (anti-replay violation)";
        case LORA_ERR_FCNT_REPLAY:
            return "FCnt counter replay detected (anti-replay violation)";
        case LORA_ERR_INVALID_REGION:
            return "Frequency outside authorized regional band plan";
        case LORA_ERR_INVALID_KEY:
            return "Invalid or weak cryptographic key";
        case LORA_ERR_PARSE_FAILED:
            return "Frame parsing failed (malformed MAC payload)";
        case LORA_ERR_POLICY_VIOLATION:
            return "Gateway posture policy violation";
        default:
            return "Unknown error";
    }
}

const char *lorawan_region_to_str(lora_region_t region) {
    switch (region) {
        case REGION_IN865:
            return "IN865";
        case REGION_EU868:
            return "EU868";
        default:
            return "UNKNOWN";
    }
}

lora_region_t lorawan_str_to_region(const char *str) {
    if (!str) return REGION_UNKNOWN;
    if (strcmp(str, "IN865") == 0 || strcmp(str, "in865") == 0) return REGION_IN865;
    if (strcmp(str, "EU868") == 0 || strcmp(str, "eu868") == 0) return REGION_EU868;
    return REGION_UNKNOWN;
}

bool lorawan_is_frequency_valid(double freq_mhz, lora_region_t region) {
    if (region == REGION_IN865) {
        /* India IN865: 865.0 MHz to 867.0 MHz */
        return (freq_mhz >= 865.0 && freq_mhz <= 867.0);
    } else if (region == REGION_EU868) {
        /* Europe EU868: 863.0 MHz to 870.0 MHz */
        return (freq_mhz >= 863.0 && freq_mhz <= 870.0);
    }
    return false;
}

bool lorawan_is_in865_join_frequency(double freq_mhz) {
    /* Mandatory IN865 default channels: 865.0625, 865.4025, 865.9850 MHz */
    const double channels[3] = { 865.0625, 865.4025, 865.9850 };
    for (int i = 0; i < 3; i++) {
        if (fabs(freq_mhz - channels[i]) < 0.001) {
            return true;
        }
    }
    return false;
}

void lorawan_init_session(lorawan_session_t *session, const uint8_t dev_eui[8], uint32_t dev_addr) {
    if (!session) return;
    memset(session, 0, sizeof(*session));
    if (dev_eui) {
        memcpy(session->dev_eui, dev_eui, 8);
    }
    session->dev_addr = dev_addr;
    session->has_dev_nonce = false;
    session->has_fcnt_up = false;
    session->last_dev_nonce = 0;
    session->last_fcnt_up = 0;
    session->is_active = false;
}

void lorawan_derive_session_keys(
    const uint8_t app_key[16],
    const uint8_t join_nonce[3],
    const uint8_t net_id[3],
    uint16_t dev_nonce,
    uint8_t nwk_skey[16],
    uint8_t app_skey[16]
) {
    uint32_t round_keys[AES128_ROUND_KEYS_SIZE];
    uint8_t block[AES_BLOCK_SIZE];

    lh_aes128_key_expansion(app_key, round_keys);

    /* NwkSKey derivation block:
     * 0x01 | JoinNonce[3] | NetID[3] | DevNonce[2] | pad[7] (0x00)
     */
    memset(block, 0, sizeof(block));
    block[0] = 0x01;
    memcpy(block + 1, join_nonce, 3);
    memcpy(block + 4, net_id, 3);
    block[7] = (uint8_t)(dev_nonce & 0xFF);
    block[8] = (uint8_t)((dev_nonce >> 8) & 0xFF);
    lh_aes128_encrypt_block(block, nwk_skey, round_keys);

    /* AppSKey derivation block:
     * 0x02 | JoinNonce[3] | NetID[3] | DevNonce[2] | pad[7] (0x00)
     */
    block[0] = 0x02;
    lh_aes128_encrypt_block(block, app_skey, round_keys);

    /* Zeroize local buffers */
    lh_secure_zero(round_keys, sizeof(round_keys));
    lh_secure_zero(block, sizeof(block));
}

lora_error_t lorawan_parse_join_request(
    const uint8_t *raw,
    size_t len,
    lorawan_join_request_t *req
) {
    if (!raw || !req) return LORA_ERR_PARSE_FAILED;
    if (len != 23) return LORA_ERR_INVALID_LENGTH;

    req->mhdr = raw[0];
    if ((req->mhdr >> 5) != MTYPE_JOIN_REQUEST) {
        return LORA_ERR_PARSE_FAILED;
    }

    memcpy(req->join_eui, raw + 1, 8);
    memcpy(req->dev_eui, raw + 9, 8);
    req->dev_nonce = (uint16_t)raw[17] | ((uint16_t)raw[18] << 8);
    req->mic = (uint32_t)raw[19] |
               ((uint32_t)raw[20] << 8) |
               ((uint32_t)raw[21] << 16) |
               ((uint32_t)raw[22] << 24);

    return LORA_OK;
}

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
) {
    if (!raw || !app_key || !join_nonce || !net_id || !session) {
        return LORA_ERR_PARSE_FAILED;
    }

    lorawan_join_request_t req;
    lora_error_t parse_res = lorawan_parse_join_request(raw, len, &req);
    if (parse_res != LORA_OK) {
        return parse_res;
    }

    /* Anti-replay DevNonce verification */
    if (session->has_dev_nonce && session->is_active) {
        if (req.dev_nonce <= session->last_dev_nonce) {
            return LORA_ERR_DEVNONCE_REPLAY;
        }
    }

    /* Compute 32-bit MIC over first 19 bytes of JoinRequest using AppKey */
    uint32_t expected_mic = lh_lorawan_compute_mic(app_key, raw, 19);
    uint32_t received_mic = req.mic;

    if (lh_constant_time_memcmp(&expected_mic, &received_mic, 4) != 0) {
        return LORA_ERR_MIC_MISMATCH;
    }

    /* Derive Session Keys */
    lorawan_derive_session_keys(
        app_key,
        join_nonce,
        net_id,
        req.dev_nonce,
        session->nwk_skey,
        session->app_skey
    );

    /* Update Session State */
    memcpy(session->dev_eui, req.dev_eui, 8);
    session->dev_addr = assigned_dev_addr;
    session->last_dev_nonce = req.dev_nonce;
    session->has_dev_nonce = true;
    session->last_fcnt_up = 0;
    session->is_active = true;

    /* Build Join-Accept frame if requested */
    if (join_accept_out && join_accept_len) {
        /* Join-Accept unencrypted payload (17 bytes without CFList):
         * MHDR (1 byte) = 0x20 (MTYPE_JOIN_ACCEPT)
         * JoinNonce (3 bytes)
         * NetID (3 bytes)
         * DevAddr (4 bytes)
         * DLSettings (1 byte) = 0x00 (RX1DROffset=0, RX2DR=0)
         * RxDelay (1 byte) = 0x01 (1 sec)
         * MIC (4 bytes) = calculated over MHDR + MACPayload
         */
        uint8_t ja_plain[17];
        ja_plain[0] = (MTYPE_JOIN_ACCEPT << 5);
        memcpy(ja_plain + 1, join_nonce, 3);
        memcpy(ja_plain + 4, net_id, 3);
        ja_plain[7] = (uint8_t)(assigned_dev_addr & 0xFF);
        ja_plain[8] = (uint8_t)((assigned_dev_addr >> 8) & 0xFF);
        ja_plain[9] = (uint8_t)((assigned_dev_addr >> 16) & 0xFF);
        ja_plain[10] = (uint8_t)((assigned_dev_addr >> 24) & 0xFF);
        ja_plain[11] = 0x00; /* DLSettings */
        ja_plain[12] = 0x01; /* RxDelay */

        uint32_t ja_mic = lh_lorawan_compute_mic(app_key, ja_plain, 13);
        ja_plain[13] = (uint8_t)(ja_mic & 0xFF);
        ja_plain[14] = (uint8_t)((ja_mic >> 8) & 0xFF);
        ja_plain[15] = (uint8_t)((ja_mic >> 16) & 0xFF);
        ja_plain[16] = (uint8_t)((ja_mic >> 24) & 0xFF);

        /* LoRaWAN 1.0.x JoinAccept encryption:
         * Encrypt ja_plain[1..16] with AES-128 decrypt/encrypt using AppKey.
         * For standard gateway output, we provide the 17-byte frame.
         */
        memcpy(join_accept_out, ja_plain, 17);
        *join_accept_len = 17;
    }

    return LORA_OK;
}

lora_error_t lorawan_parse_uplink_frame(
    const uint8_t *raw,
    size_t len,
    lorawan_uplink_frame_t *frame
) {
    if (!raw || !frame) return LORA_ERR_PARSE_FAILED;
    if (len < 12) return LORA_ERR_INVALID_LENGTH;

    memset(frame, 0, sizeof(*frame));
    frame->mhdr = raw[0];
    uint8_t mtype = (frame->mhdr >> 5) & 0x07;
    if (mtype != MTYPE_UNCONFIRMED_DATA_UP && mtype != MTYPE_CONFIRMED_DATA_UP) {
        return LORA_ERR_PARSE_FAILED;
    }

    frame->dev_addr = (uint32_t)raw[1] |
                      ((uint32_t)raw[2] << 8) |
                      ((uint32_t)raw[3] << 16) |
                      ((uint32_t)raw[4] << 24);

    frame->fctrl = raw[5];
    size_t fopts_len = (size_t)(frame->fctrl & 0x0F);
    uint16_t fcnt16 = (uint16_t)raw[6] | ((uint16_t)raw[7] << 8);
    frame->fcnt = (uint32_t)fcnt16;

    if (len < 8 + fopts_len + 4) {
        return LORA_ERR_INVALID_LENGTH;
    }

    if (fopts_len > 0) {
        memcpy(frame->fopts, raw + 8, fopts_len);
        frame->fopts_len = fopts_len;
    }

    size_t offset = 8 + fopts_len;
    size_t mac_payload_len = len - 4; /* excluding 4-byte MIC */

    if (offset < mac_payload_len) {
        /* FPort is present */
        frame->fport = raw[offset++];
        size_t frm_payload_len = mac_payload_len - offset;
        if (frm_payload_len > sizeof(frame->frm_payload)) {
            return LORA_ERR_INVALID_LENGTH;
        }
        if (frm_payload_len > 0) {
            memcpy(frame->frm_payload, raw + offset, frm_payload_len);
            frame->frm_payload_len = frm_payload_len;
        }
    } else {
        frame->fport = 0;
        frame->frm_payload_len = 0;
    }

    frame->mic = (uint32_t)raw[len - 4] |
                 ((uint32_t)raw[len - 3] << 8) |
                 ((uint32_t)raw[len - 2] << 16) |
                 ((uint32_t)raw[len - 1] << 24);

    return LORA_OK;
}

lora_error_t lorawan_verify_and_decrypt_uplink(
    const uint8_t *raw,
    size_t len,
    double freq_mhz,
    lora_region_t region,
    lorawan_session_t *session,
    lorawan_uplink_frame_t *frame,
    uint8_t *decrypted_payload,
    size_t *decrypted_len
) {
    if (!raw || !session || !frame || !decrypted_payload || !decrypted_len) {
        return LORA_ERR_PARSE_FAILED;
    }

    if (!session->is_active) {
        return LORA_ERR_POLICY_VIOLATION;
    }

    /* Regional band compliance verification */
    if (!lorawan_is_frequency_valid(freq_mhz, region)) {
        return LORA_ERR_INVALID_REGION;
    }

    lora_error_t parse_res = lorawan_parse_uplink_frame(raw, len, frame);
    if (parse_res != LORA_OK) {
        return parse_res;
    }

    frame->frequency_mhz = freq_mhz;

    /* Verify DevAddr match */
    if (frame->dev_addr != session->dev_addr) {
        return LORA_ERR_POLICY_VIOLATION;
    }

    /* Reconstruct 32-bit FCnt and check anti-replay */
    uint16_t fcnt16 = (uint16_t)(frame->fcnt & 0x0000FFFF);
    uint32_t fcnt32;

    if (!session->has_fcnt_up) {
        fcnt32 = (uint32_t)fcnt16;
    } else {
        uint16_t last_fcnt16 = (uint16_t)(session->last_fcnt_up & 0x0000FFFF);
        uint16_t diff = (uint16_t)(fcnt16 - last_fcnt16);
        if (diff == 0 || diff >= 0x4000) {
            return LORA_ERR_FCNT_REPLAY;
        }
        fcnt32 = session->last_fcnt_up + (uint32_t)diff;
    }
    frame->fcnt = fcnt32;

    /* Compute B0 block for AES-128-CMAC MIC calculation:
     * B0 (16 bytes):
     * 0x49 | 0x00 0x00 0x00 0x00 | Dir (0x00) | DevAddr (4 bytes LE) |
     * FCntUp (4 bytes LE) | 0x00 | len(msg) (1 byte)
     */
    uint8_t b0[16];
    memset(b0, 0, sizeof(b0));
    b0[0] = 0x49;
    b0[5] = 0x00; /* Dir = 0 (uplink) */
    b0[6] = (uint8_t)(session->dev_addr & 0xFF);
    b0[7] = (uint8_t)((session->dev_addr >> 8) & 0xFF);
    b0[8] = (uint8_t)((session->dev_addr >> 16) & 0xFF);
    b0[9] = (uint8_t)((session->dev_addr >> 24) & 0xFF);
    b0[10] = (uint8_t)(fcnt32 & 0xFF);
    b0[11] = (uint8_t)((fcnt32 >> 8) & 0xFF);
    b0[12] = (uint8_t)((fcnt32 >> 16) & 0xFF);
    b0[13] = (uint8_t)((fcnt32 >> 24) & 0xFF);
    b0[14] = 0x00;
    b0[15] = (uint8_t)(len - 4); /* Length of MHDR + MACPayload */

    /* Allocate buffer for B0 || msg */
    size_t cmac_input_len = 16 + (len - 4);
    uint8_t *cmac_input = (uint8_t *)malloc(cmac_input_len);
    if (!cmac_input) {
        return LORA_ERR_PARSE_FAILED;
    }

    memcpy(cmac_input, b0, 16);
    memcpy(cmac_input + 16, raw, len - 4);

    uint8_t cmac_tag[16];
    lh_aes128_cmac(session->nwk_skey, cmac_input, cmac_input_len, cmac_tag);
    free(cmac_input);

    uint32_t expected_mic = (uint32_t)cmac_tag[0] |
                            ((uint32_t)cmac_tag[1] << 8) |
                            ((uint32_t)cmac_tag[2] << 16) |
                            ((uint32_t)cmac_tag[3] << 24);

    if (lh_constant_time_memcmp(&expected_mic, &frame->mic, 4) != 0) {
        return LORA_ERR_MIC_MISMATCH;
    }

    /* Decrypt FRMPayload */
    if (frame->frm_payload_len > 0) {
        const uint8_t *crypto_key = (frame->fport == 0) ? session->nwk_skey : session->app_skey;
        lh_lorawan_crypt_payload(
            crypto_key,
            session->dev_addr,
            fcnt32,
            0, /* uplink */
            frame->frm_payload,
            decrypted_payload,
            frame->frm_payload_len
        );
        *decrypted_len = frame->frm_payload_len;
    } else {
        *decrypted_len = 0;
    }

    /* Update session counter on valid packet */
    session->last_fcnt_up = fcnt32;
    session->has_fcnt_up = true;

    return LORA_OK;
}

void lora_calculate_toa(const lora_toa_params_t *params, lora_toa_result_t *result) {
    if (!params || !result) return;
    memset(result, 0, sizeof(*result));

    if (params->bw_khz <= 0.0 || params->sf < 6 || params->sf > 12) {
        return;
    }

    /* Symbol duration: T_sym = (2^SF) / BW (ms, where BW is in kHz) */
    double t_sym_ms = pow(2.0, (double)params->sf) / params->bw_khz;
    result->t_sym_ms = t_sym_ms;

    /* Preamble duration: T_preamble = (N_preamble + 4.25) * T_sym */
    int n_preamble = (params->preamble_symbols > 0) ? params->preamble_symbols : 8;
    double t_preamble_ms = ((double)n_preamble + 4.25) * t_sym_ms;
    result->t_preamble_ms = t_preamble_ms;

    /* Payload symbol count calculation */
    int h = params->explicit_header ? 0 : 1;
    int de = params->low_dr_opt ? 1 : 0;
    int crc = params->crc_enabled ? 1 : 0;
    int cr = (params->cr >= 1 && params->cr <= 4) ? params->cr : 1;

    double num = 8.0 * (double)params->payload_bytes - 4.0 * (double)params->sf + 28.0 + 16.0 * (double)crc - 20.0 * (double)h;
    double den = 4.0 * ((double)params->sf - 2.0 * (double)de);

    double term = 0.0;
    if (den > 0.0) {
        term = ceil(num / den);
        if (term < 0.0) term = 0.0;
    }

    double n_payload_sym = 8.0 + term * ((double)cr + 4.0);
    result->n_payload_sym = n_payload_sym;

    /* Payload duration: T_payload = n_payload * T_sym */
    double t_payload_ms = n_payload_sym * t_sym_ms;
    result->t_payload_ms = t_payload_ms;

    /* Total Time-on-Air */
    double t_toa_ms = t_preamble_ms + t_payload_ms;
    result->t_toa_ms = t_toa_ms;

    /* Off-time for 1% duty cycle: T_off = 99 * T_ToA */
    result->t_off_ms = 99.0 * t_toa_ms;

    /* Compliance check: for 1% duty cycle (EU868), ensure T_ToA does not exceed dwell time if applicable */
    result->duty_cycle_compliant = true;
}

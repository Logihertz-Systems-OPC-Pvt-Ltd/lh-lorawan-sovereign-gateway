#include "lorawan_types.h"
#include "aes128_cmac.h"
#include "lorawan_mac.h"
#include "json_parser.h"
#include "lorawan_auditor.h"
#include "exporters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

static int g_total_assertions = 0;
static int g_passed_assertions = 0;

#define TEST_ASSERT(cond, desc) do { \
    g_total_assertions++; \
    if (cond) { \
        g_passed_assertions++; \
    } else { \
        fprintf(stderr, "\033[1;31m[FAIL]\033[0m Line %d: %s\n", __LINE__, desc); \
        assert(cond); \
    } \
} while (0)

/* Test 1: FIPS 197 AES-128 Encryption Vector */
static void test_fips_197_aes128(void) {
    printf("[TEST] FIPS 197 AES-128 Block Encryption Vectors...\n");
    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const uint8_t pt[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    const uint8_t expected_ct[16] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };

    uint32_t rkeys[AES128_ROUND_KEYS_SIZE];
    lh_aes128_key_expansion(key, rkeys);

    uint8_t ct[16];
    lh_aes128_encrypt_block(pt, ct, rkeys);

    TEST_ASSERT(memcmp(ct, expected_ct, 16) == 0, "FIPS 197 AES-128 block matches expected ciphertext");
}

/* Test 2: RFC 4493 Subkey Derivation */
static void test_rfc_4493_subkeys(void) {
    printf("[TEST] RFC 4493 Subkey Derivation (K1, K2)...\n");
    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const uint8_t expected_k1[16] = {
        0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66,
        0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36, 0xa8, 0xde
    };
    const uint8_t expected_k2[16] = {
        0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc,
        0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d, 0x51, 0x3b
    };

    uint32_t rkeys[AES128_ROUND_KEYS_SIZE];
    lh_aes128_key_expansion(key, rkeys);

    uint8_t k1[16], k2[16];
    lh_aes128_cmac_subkeys(rkeys, k1, k2);

    TEST_ASSERT(memcmp(k1, expected_k1, 16) == 0, "RFC 4493 K1 subkey derivation match");
    TEST_ASSERT(memcmp(k2, expected_k2, 16) == 0, "RFC 4493 K2 subkey derivation match");
}

/* Test 3: RFC 4493 CMAC Vectors (0, 16, 40, 64 bytes) */
static void test_rfc_4493_cmac_vectors(void) {
    printf("[TEST] RFC 4493 CMAC Specification Test Vectors...\n");
    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const uint8_t m[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    uint8_t mac[16];

    /* 0 bytes */
    const uint8_t exp_0[16] = {
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
    };
    lh_aes128_cmac(key, NULL, 0, mac);
    TEST_ASSERT(memcmp(mac, exp_0, 16) == 0, "RFC 4493 CMAC 0-byte match");

    /* 16 bytes */
    const uint8_t exp_16[16] = {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
    };
    lh_aes128_cmac(key, m, 16, mac);
    TEST_ASSERT(memcmp(mac, exp_16, 16) == 0, "RFC 4493 CMAC 16-byte match");

    /* 40 bytes */
    const uint8_t exp_40[16] = {
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
        0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
    };
    lh_aes128_cmac(key, m, 40, mac);
    TEST_ASSERT(memcmp(mac, exp_40, 16) == 0, "RFC 4493 CMAC 40-byte match");

    /* 64 bytes */
    const uint8_t exp_64[16] = {
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe
    };
    lh_aes128_cmac(key, m, 64, mac);
    TEST_ASSERT(memcmp(mac, exp_64, 16) == 0, "RFC 4493 CMAC 64-byte match");
}

/* Test 4: Constant-time comparison & Secure Zeroization */
static void test_constant_time_and_zeroization(void) {
    printf("[TEST] Constant-Time Memcmp & Secure Zeroization...\n");
    uint8_t a[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    uint8_t b[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    uint8_t c[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17 };

    TEST_ASSERT(lh_constant_time_memcmp(a, b, 16) == 0, "Constant time compare equal buffers returns 0");
    TEST_ASSERT(lh_constant_time_memcmp(a, c, 16) != 0, "Constant time compare differing buffers returns non-zero");

    lh_secure_zero(b, sizeof(b));
    bool all_zero = true;
    for (int i = 0; i < 16; i++) {
        if (b[i] != 0) all_zero = false;
    }
    TEST_ASSERT(all_zero, "Secure zero zeroes all bytes");
}

/* Test 5: LoRaWAN CTR Payload Encryption and Decryption Symmetry */
static void test_lorawan_ctr_crypt(void) {
    printf("[TEST] LoRaWAN CTR Mode Payload Encryption / Decryption...\n");
    const uint8_t app_skey[16] = {
        0xa7, 0x02, 0x55, 0x2f, 0x2f, 0xa8, 0x92, 0x97,
        0xc0, 0xce, 0xa5, 0xd4, 0x31, 0x07, 0xeb, 0xd9
    };
    uint32_t dev_addr = 0x00112233;
    uint32_t fcnt = 42;
    const char *msg = "Sovereign Air-Gapped IoT Sensor Telemetry";
    size_t len = strlen(msg);

    uint8_t cipher[64];
    uint8_t recovered[64];

    lh_lorawan_crypt_payload(app_skey, dev_addr, fcnt, 0, (const uint8_t *)msg, cipher, len);
    TEST_ASSERT(memcmp(msg, cipher, len) != 0, "Ciphertext is distinct from plaintext");

    lh_lorawan_crypt_payload(app_skey, dev_addr, fcnt, 0, cipher, recovered, len);
    recovered[len] = '\0';
    TEST_ASSERT(memcmp(msg, recovered, len) == 0, "CTR decryption recovers exact original plaintext");
    TEST_ASSERT(strcmp((const char *)recovered, msg) == 0, "Recovered string matches original");
}

/* Test 6: OTAA Session Key Derivation */
static void test_otaa_key_derivation(void) {
    printf("[TEST] OTAA Session Key Derivation (NwkSKey, AppSKey)...\n");
    const uint8_t app_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const uint8_t join_nonce[3] = { 0x01, 0x02, 0x03 };
    const uint8_t net_id[3] = { 0x00, 0x00, 0x01 };
    uint16_t dev_nonce = 1;

    uint8_t nwk_skey[16], app_skey[16];
    lorawan_derive_session_keys(app_key, join_nonce, net_id, dev_nonce, nwk_skey, app_skey);

    TEST_ASSERT(memcmp(nwk_skey, app_skey, 16) != 0, "NwkSKey and AppSKey are cryptographically distinct");

    /* Deterministic re-derivation check */
    uint8_t nwk_skey2[16], app_skey2[16];
    lorawan_derive_session_keys(app_key, join_nonce, net_id, dev_nonce, nwk_skey2, app_skey2);
    TEST_ASSERT(memcmp(nwk_skey, nwk_skey2, 16) == 0, "NwkSKey derivation is strictly deterministic");
    TEST_ASSERT(memcmp(app_skey, app_skey2, 16) == 0, "AppSKey derivation is strictly deterministic");
}

/* Test 7: OTAA Join-Request Processing & Anti-Replay */
static void test_otaa_join_request_flow(void) {
    printf("[TEST] OTAA Join-Request Processing, MIC & DevNonce Anti-Replay...\n");
    const uint8_t app_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    /* Frame: MHDR(0) | JoinEUI(8) | DevEUI(8) | DevNonce=1(2) | MIC(4) */
    const char *join_hex = "0000112233445566770102030405060708010007f4a03e";
    uint8_t raw[32];
    size_t raw_len = 0;
    hex_to_bytes(join_hex, raw, sizeof(raw), &raw_len);
    TEST_ASSERT(raw_len == 23, "JoinRequest parsed to 23 bytes");

    lorawan_join_request_t req;
    lora_error_t pres = lorawan_parse_join_request(raw, raw_len, &req);
    TEST_ASSERT(pres == LORA_OK, "JoinRequest parses cleanly");
    TEST_ASSERT(req.mhdr == 0x00, "MHDR indicates JoinRequest (0x00)");
    TEST_ASSERT(req.dev_nonce == 1, "DevNonce matches 1");

    lorawan_session_t session;
    lorawan_init_session(&session, req.dev_eui, 0x00112233);

    uint8_t join_nonce[3] = { 0x01, 0x02, 0x03 };
    uint8_t net_id[3] = { 0x00, 0x00, 0x01 };
    uint8_t ja_out[32];
    size_t ja_len = 0;

    lora_error_t jres = lorawan_process_join_request(
        raw, raw_len, app_key, join_nonce, net_id, 0x00112233,
        &session, ja_out, &ja_len
    );
    TEST_ASSERT(jres == LORA_OK, "Valid JoinRequest processed successfully");
    TEST_ASSERT(session.is_active == true, "Session is activated");
    TEST_ASSERT(session.has_dev_nonce == true, "Session records DevNonce");
    TEST_ASSERT(session.last_dev_nonce == 1, "Last DevNonce is 1");
    TEST_ASSERT(ja_len == 17, "JoinAccept response synthesized (17 bytes)");

    /* Replay attack with same DevNonce */
    lora_error_t replay_res = lorawan_process_join_request(
        raw, raw_len, app_key, join_nonce, net_id, 0x00112233,
        &session, ja_out, &ja_len
    );
    TEST_ASSERT(replay_res == LORA_ERR_DEVNONCE_REPLAY, "Replay attack with same DevNonce rejected");

    /* Tampered MIC check */
    raw[22] ^= 0xFF;
    lorawan_session_t fresh_session;
    lorawan_init_session(&fresh_session, req.dev_eui, 0x00112233);
    lora_error_t tampered_res = lorawan_process_join_request(
        raw, raw_len, app_key, join_nonce, net_id, 0x00112233,
        &fresh_session, ja_out, &ja_len
    );
    TEST_ASSERT(tampered_res == LORA_ERR_MIC_MISMATCH, "Tampered MIC in JoinRequest rejected");
}

/* Test 8: Uplink Verification, FCnt Monotonicity, and Decryption */
static void test_uplink_verification_flow(void) {
    printf("[TEST] Uplink Verification, B0 MIC, FCnt Replay Guard, and Decryption...\n");
    const char *uplink_hex = "403322110000010001f7f96bff7d644f7ac2f66c0c76";
    uint8_t raw[32];
    size_t raw_len = 0;
    hex_to_bytes(uplink_hex, raw, sizeof(raw), &raw_len);
    TEST_ASSERT(raw_len == 22, "Uplink frame parsed to 22 bytes");

    lorawan_uplink_frame_t frame;
    lora_error_t pres = lorawan_parse_uplink_frame(raw, raw_len, &frame);
    TEST_ASSERT(pres == LORA_OK, "Uplink frame parsed successfully");
    TEST_ASSERT(frame.mhdr == 0x40, "MHDR indicates Unconfirmed Data Up");
    TEST_ASSERT(frame.dev_addr == 0x00112233, "DevAddr matches 0x00112233");
    TEST_ASSERT(frame.fport == 1, "FPort matches 1");
    TEST_ASSERT(frame.frm_payload_len == 9, "FRMPayload length is 9 bytes");

    lorawan_session_t session;
    lorawan_init_session(&session, NULL, 0x00112233);
    const char *nwk_hex = "7504da33cd7f83015a20c4ec1c7688ff";
    const char *app_hex = "a702552f2fa89297c0cea5d43107ebd9";
    size_t k1_len = 0, k2_len = 0;
    hex_to_bytes(nwk_hex, session.nwk_skey, 16, &k1_len);
    hex_to_bytes(app_hex, session.app_skey, 16, &k2_len);
    session.last_fcnt_up = 0;
    session.is_active = true;

    uint8_t decrypted[32];
    size_t dec_len = 0;

    lora_error_t vres = lorawan_verify_and_decrypt_uplink(
        raw, raw_len, 865.0625, REGION_IN865,
        &session, &frame, decrypted, &dec_len
    );
    TEST_ASSERT(vres == LORA_OK, "Valid uplink authenticated and decrypted");
    TEST_ASSERT(dec_len == 9, "Decrypted payload length is 9 bytes");
    decrypted[dec_len] = '\0';
    TEST_ASSERT(strcmp((const char *)decrypted, "LOGIHERTZ") == 0, "Decrypted plaintext matches 'LOGIHERTZ'");
    TEST_ASSERT(session.last_fcnt_up == 1, "Session last_fcnt_up updated to 1");

    /* FCnt replay rejection check */
    lora_error_t replay_res = lorawan_verify_and_decrypt_uplink(
        raw, raw_len, 865.0625, REGION_IN865,
        &session, &frame, decrypted, &dec_len
    );
    TEST_ASSERT(replay_res == LORA_ERR_FCNT_REPLAY, "Uplink frame with replayed FCnt rejected");

    /* Out of band frequency check */
    session.last_fcnt_up = 0;
    lora_error_t oob_res = lorawan_verify_and_decrypt_uplink(
        raw, raw_len, 915.0, REGION_IN865,
        &session, &frame, decrypted, &dec_len
    );
    TEST_ASSERT(oob_res == LORA_ERR_INVALID_REGION, "Out-of-band frequency rejected under IN865");

    /* Tampered payload MIC mismatch check */
    session.last_fcnt_up = 0;
    session.has_fcnt_up = false;
    raw[9] ^= 0x01;
    lora_error_t tampered_res = lorawan_verify_and_decrypt_uplink(
        raw, raw_len, 865.0625, REGION_IN865,
        &session, &frame, decrypted, &dec_len
    );
    TEST_ASSERT(tampered_res == LORA_ERR_MIC_MISMATCH, "Tampered uplink payload triggers MIC mismatch");
}

/* Test 9: Regional Band Validation and IN865 Join Channels */
static void test_regional_bands(void) {
    printf("[TEST] Regional Band Plans (IN865, EU868) and Mandatory Channels...\n");

    /* IN865: 865.0 to 867.0 MHz */
    TEST_ASSERT(lorawan_is_frequency_valid(865.0, REGION_IN865), "IN865 865.0 MHz valid");
    TEST_ASSERT(lorawan_is_frequency_valid(866.0, REGION_IN865), "IN865 866.0 MHz valid");
    TEST_ASSERT(lorawan_is_frequency_valid(867.0, REGION_IN865), "IN865 867.0 MHz valid");
    TEST_ASSERT(!lorawan_is_frequency_valid(864.9, REGION_IN865), "IN865 864.9 MHz invalid");
    TEST_ASSERT(!lorawan_is_frequency_valid(867.1, REGION_IN865), "IN865 867.1 MHz invalid");

    /* IN865 mandatory join channels */
    TEST_ASSERT(lorawan_is_in865_join_frequency(865.0625), "865.0625 MHz is IN865 join channel");
    TEST_ASSERT(lorawan_is_in865_join_frequency(865.4025), "865.4025 MHz is IN865 join channel");
    TEST_ASSERT(lorawan_is_in865_join_frequency(865.9850), "865.9850 MHz is IN865 join channel");
    TEST_ASSERT(!lorawan_is_in865_join_frequency(865.5000), "865.5000 MHz is not an IN865 default join channel");

    /* EU868: 863.0 to 870.0 MHz */
    TEST_ASSERT(lorawan_is_frequency_valid(863.0, REGION_EU868), "EU868 863.0 MHz valid");
    TEST_ASSERT(lorawan_is_frequency_valid(868.1, REGION_EU868), "EU868 868.1 MHz valid");
    TEST_ASSERT(lorawan_is_frequency_valid(870.0, REGION_EU868), "EU868 870.0 MHz valid");
    TEST_ASSERT(!lorawan_is_frequency_valid(862.9, REGION_EU868), "EU868 862.9 MHz invalid");
    TEST_ASSERT(!lorawan_is_frequency_valid(870.1, REGION_EU868), "EU868 870.1 MHz invalid");

    TEST_ASSERT(strcmp(lorawan_region_to_str(REGION_IN865), "IN865") == 0, "IN865 string conversion");
    TEST_ASSERT(strcmp(lorawan_region_to_str(REGION_EU868), "EU868") == 0, "EU868 string conversion");
    TEST_ASSERT(lorawan_str_to_region("IN865") == REGION_IN865, "Region string parse IN865");
    TEST_ASSERT(lorawan_str_to_region("EU868") == REGION_EU868, "Region string parse EU868");
}

/* Test 10: CSS Time-on-Air and Duty Cycle Calculations */
static void test_lora_time_on_air(void) {
    printf("[TEST] LoRa CSS Time-on-Air Math and 1%% Duty Cycle Constraints...\n");
    lora_toa_params_t p;
    memset(&p, 0, sizeof(p));
    p.sf = 7;
    p.bw_khz = 125.0;
    p.cr = 1; /* 4/5 */
    p.payload_bytes = 16;
    p.preamble_symbols = 8;
    p.explicit_header = true;
    p.low_dr_opt = false;
    p.crc_enabled = true;
    p.region = REGION_IN865;

    lora_toa_result_t res;
    lora_calculate_toa(&p, &res);

    /* SF7 @ 125 kHz: T_sym = 128 / 125 = 1.024 ms */
    TEST_ASSERT(fabs(res.t_sym_ms - 1.024) < 0.0001, "T_sym for SF7 @ 125kHz is exactly 1.024 ms");
    /* Preamble: (8 + 4.25) * 1.024 = 12.544 ms */
    TEST_ASSERT(fabs(res.t_preamble_ms - 12.544) < 0.01, "T_preamble matches 12.54 ms");
    TEST_ASSERT(res.t_toa_ms > 50.0 && res.t_toa_ms < 55.0, "Total T_ToA in 51-53 ms range");
    /* Off-time: 99 * T_ToA */
    TEST_ASSERT(fabs(res.t_off_ms - (99.0 * res.t_toa_ms)) < 0.001, "Off-time is exactly 99 * T_ToA");
    TEST_ASSERT(res.duty_cycle_compliant == true, "Duty cycle compliant");

    /* SF12 @ 125 kHz with Low Data Rate Optimization */
    p.sf = 12;
    p.low_dr_opt = true;
    p.payload_bytes = 23;
    lora_calculate_toa(&p, &res);
    /* SF12 @ 125 kHz: T_sym = 4096 / 125 = 32.768 ms */
    TEST_ASSERT(fabs(res.t_sym_ms - 32.768) < 0.0001, "T_sym for SF12 @ 125kHz is 32.768 ms");
    TEST_ASSERT(res.t_toa_ms > 1400.0, "SF12 23-byte packet ToA > 1400 ms");
}

/* Test 11: 10-Rule Auditor Verification (Hardened Policy = 100/100) */
static void test_auditor_hardened_policy(void) {
    printf("[TEST] Auditor Evaluation: Hardened Sovereign Policy...\n");
    gateway_policy_t pol;
    bool ok = json_load_policy_file("fixtures/hardened_lorawan_policy.json", &pol);
    TEST_ASSERT(ok, "Loaded fixtures/hardened_lorawan_policy.json");

    audit_report_t r;
    lorawan_audit_policy(&pol, &r);

    TEST_ASSERT(r.total_rules == 10, "Total rules evaluated = 10");
    TEST_ASSERT(r.passed_rules == 10, "All 10 rules passed");
    TEST_ASSERT(r.failed_rules == 0, "0 rules failed");
    TEST_ASSERT(r.total_deductions == 0, "Total deductions = 0");
    TEST_ASSERT(r.posture_score == 100, "Posture score = 100/100");

    for (int i = 0; i < 10; i++) {
        TEST_ASSERT(r.findings[i].passed == true, "Finding passed");
    }
}

/* Test 12: 10-Rule Auditor Verification (Vulnerable Policy = 0/100, -124 deductions) */
static void test_auditor_vulnerable_policy(void) {
    printf("[TEST] Auditor Evaluation: Vulnerable Policy...\n");
    gateway_policy_t pol;
    bool ok = json_load_policy_file("fixtures/vulnerable_lorawan_policy.json", &pol);
    TEST_ASSERT(ok, "Loaded fixtures/vulnerable_lorawan_policy.json");

    audit_report_t r;
    lorawan_audit_policy(&pol, &r);

    TEST_ASSERT(r.total_rules == 10, "Total rules evaluated = 10");
    TEST_ASSERT(r.passed_rules == 0, "0 rules passed");
    TEST_ASSERT(r.failed_rules == 10, "All 10 rules failed");
    TEST_ASSERT(r.total_deductions == 124, "Total deductions = 124");
    TEST_ASSERT(r.posture_score == 0, "Posture score = 0/100");

    /* Verify individual rule deductions */
    TEST_ASSERT(r.findings[0].deduction == 25, "LH-LORA-001 deduction is 25");
    TEST_ASSERT(r.findings[1].deduction == 25, "LH-LORA-002 deduction is 25");
    TEST_ASSERT(r.findings[2].deduction == 25, "LH-LORA-003 deduction is 25");
    TEST_ASSERT(r.findings[3].deduction == 10, "LH-LORA-004 deduction is 10");
    TEST_ASSERT(r.findings[4].deduction == 10, "LH-LORA-005 deduction is 10");
    TEST_ASSERT(r.findings[5].deduction == 10, "LH-LORA-006 deduction is 10");
    TEST_ASSERT(r.findings[6].deduction == 10, "LH-LORA-007 deduction is 10");
    TEST_ASSERT(r.findings[7].deduction == 4,  "LH-LORA-008 deduction is 4");
    TEST_ASSERT(r.findings[8].deduction == 4,  "LH-LORA-009 deduction is 4");
    TEST_ASSERT(r.findings[9].deduction == 1,  "LH-LORA-010 deduction is 1");
}

/* Test 13: Exporters Smoke Test */
static void test_exporters(void) {
    printf("[TEST] Exporters (Table, Canonical JSON, OASIS SARIF v2.1.0)...\n");
    gateway_policy_t pol;
    json_load_policy_file("fixtures/hardened_lorawan_policy.json", &pol);
    audit_report_t r;
    lorawan_audit_policy(&pol, &r);

    char tmp_path[64] = "/tmp/audit_test_out.tmp";
    FILE *f = fopen(tmp_path, "w");
    TEST_ASSERT(f != NULL, "Created temp file for exporter output");

    export_audit_table(&r, f);
    export_audit_json(&r, f);
    export_audit_sarif(&r, f);
    fclose(f);

    FILE *rf = fopen(tmp_path, "r");
    TEST_ASSERT(rf != NULL, "Opened exporter output for verification");
    char line[256];
    bool saw_sarif = false;
    while (fgets(line, sizeof(line), rf)) {
        if (strstr(line, "sarif-schema-2.1.0.json")) {
            saw_sarif = true;
            break;
        }
    }
    fclose(rf);
    remove(tmp_path);
    TEST_ASSERT(saw_sarif, "SARIF v2.1.0 schema line verified in output");
}

/* Test 14: JSON & Hex Utility Functions */
static void test_json_and_hex_utilities(void) {
    printf("[TEST] JSON Parser and Hex Utility Helpers...\n");
    const char *hex = "0123456789abcdef";
    uint8_t bytes[8];
    size_t count = 0;
    TEST_ASSERT(hex_to_bytes(hex, bytes, 8, &count), "hex_to_bytes succeeded");
    TEST_ASSERT(count == 8, "Decoded 8 bytes");
    TEST_ASSERT(bytes[0] == 0x01 && bytes[7] == 0xef, "Decoded values match");

    char out_hex[17];
    bytes_to_hex(bytes, 8, out_hex, sizeof(out_hex));
    TEST_ASSERT(strcmp(hex, out_hex) == 0, "bytes_to_hex match");

    const char *sample_json = "{\"test_str\": \"hello world\", \"test_bool\": true, \"test_int\": 42, \"test_float\": 3.14}";
    char str_val[32];
    bool b_val = false;
    int i_val = 0;
    double d_val = 0.0;

    TEST_ASSERT(json_get_string(sample_json, "test_str", str_val, sizeof(str_val)), "json_get_string ok");
    TEST_ASSERT(strcmp(str_val, "hello world") == 0, "json_get_string value match");
    TEST_ASSERT(json_get_bool(sample_json, "test_bool", &b_val), "json_get_bool ok");
    TEST_ASSERT(b_val == true, "json_get_bool value match");
    TEST_ASSERT(json_get_int(sample_json, "test_int", &i_val), "json_get_int ok");
    TEST_ASSERT(i_val == 42, "json_get_int value match");
    TEST_ASSERT(json_get_double(sample_json, "test_float", &d_val), "json_get_double ok");
    TEST_ASSERT(fabs(d_val - 3.14) < 0.001, "json_get_double value match");
}

int main(void) {
    printf("===============================================================\n");
    printf("   Logihertz Sovereign LoRaWAN Gateway Verification Test Suite\n");
    printf("===============================================================\n\n");

    test_fips_197_aes128();
    test_rfc_4493_subkeys();
    test_rfc_4493_cmac_vectors();
    test_constant_time_and_zeroization();
    test_lorawan_ctr_crypt();
    test_otaa_key_derivation();
    test_otaa_join_request_flow();
    test_uplink_verification_flow();
    test_regional_bands();
    test_lora_time_on_air();
    test_auditor_hardened_policy();
    test_auditor_vulnerable_policy();
    test_exporters();
    test_json_and_hex_utilities();

    printf("\n---------------------------------------------------------------\n");
    printf("Test Results: \033[1;32m%d / %d assertions PASSED (100%%)\033[0m\n",
           g_passed_assertions, g_total_assertions);
    printf("===============================================================\n");

    return (g_passed_assertions == g_total_assertions) ? 0 : 1;
}

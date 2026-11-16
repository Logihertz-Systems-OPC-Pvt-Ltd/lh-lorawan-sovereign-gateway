#include "json_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

bool hex_to_bytes(const char *hex, uint8_t *out, size_t max_out, size_t *out_len) {
    if (!hex || !out || !out_len) return false;
    size_t count = 0;
    const char *p = hex;

    while (*p && count < max_out) {
        while (*p && (isspace((unsigned char)*p) || *p == ':' || *p == '-')) {
            p++;
        }
        if (!*p) break;

        char c1 = *p++;
        if (!*p) return false;
        char c2 = *p++;

        int v1, v2;
        if (c1 >= '0' && c1 <= '9') v1 = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') v1 = c1 - 'a' + 10;
        else if (c1 >= 'A' && c1 <= 'F') v1 = c1 - 'A' + 10;
        else return false;

        if (c2 >= '0' && c2 <= '9') v2 = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') v2 = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') v2 = c2 - 'A' + 10;
        else return false;

        out[count++] = (uint8_t)((v1 << 4) | v2);
    }

    *out_len = count;
    return true;
}

void bytes_to_hex(const uint8_t *in, size_t len, char *out, size_t max_out) {
    if (!in || !out || max_out == 0) return;
    static const char hex_chars[] = "0123456789abcdef";
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 2 < max_out; i++) {
        out[pos++] = hex_chars[(in[i] >> 4) & 0x0F];
        out[pos++] = hex_chars[in[i] & 0x0F];
    }
    out[pos] = '\0';
}

static const char *find_key_pos(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return NULL;

    p += strlen(needle);
    while (*p && (isspace((unsigned char)*p) || *p == ':')) {
        p++;
    }
    return p;
}

bool json_get_string(const char *json, const char *key, char *out_val, size_t max_len) {
    if (!json || !key || !out_val || max_len == 0) return false;
    const char *p = find_key_pos(json, key);
    if (!p || *p != '\"') return false;

    p++; /* skip opening quote */
    size_t idx = 0;
    while (*p && *p != '\"' && idx + 1 < max_len) {
        if (*p == '\\' && *(p + 1)) {
            p++; /* skip escape */
        }
        out_val[idx++] = *p++;
    }
    out_val[idx] = '\0';
    return true;
}

bool json_get_bool(const char *json, const char *key, bool *out_val) {
    if (!json || !key || !out_val) return false;
    const char *p = find_key_pos(json, key);
    if (!p) return false;

    if (strncmp(p, "true", 4) == 0) {
        *out_val = true;
        return true;
    } else if (strncmp(p, "false", 5) == 0) {
        *out_val = false;
        return true;
    }
    return false;
}

bool json_get_int(const char *json, const char *key, int *out_val) {
    if (!json || !key || !out_val) return false;
    const char *p = find_key_pos(json, key);
    if (!p) return false;

    char *endptr = NULL;
    long val = strtol(p, &endptr, 10);
    if (endptr == p) return false;

    *out_val = (int)val;
    return true;
}

bool json_get_double(const char *json, const char *key, double *out_val) {
    if (!json || !key || !out_val) return false;
    const char *p = find_key_pos(json, key);
    if (!p) return false;

    char *endptr = NULL;
    double val = strtod(p, &endptr);
    if (endptr == p) return false;

    *out_val = val;
    return true;
}

bool json_parse_policy(const char *json_str, gateway_policy_t *policy) {
    if (!json_str || !policy) return false;
    memset(policy, 0, sizeof(*policy));

    if (!json_get_string(json_str, "policy_name", policy->policy_name, sizeof(policy->policy_name))) {
        strncpy(policy->policy_name, "Default Policy", sizeof(policy->policy_name) - 1);
    }

    json_get_bool(json_str, "require_otaa_only", &policy->require_otaa_only);
    json_get_bool(json_str, "allow_abp_devices", &policy->allow_abp_devices);
    json_get_bool(json_str, "persist_devnonce_store", &policy->persist_devnonce_store);
    json_get_bool(json_str, "strict_32bit_fcnt_anti_replay", &policy->strict_32bit_fcnt_anti_replay);
    json_get_bool(json_str, "disable_legacy_semtech_udp", &policy->disable_legacy_semtech_udp);
    json_get_bool(json_str, "sovereign_local_join_server", &policy->sovereign_local_join_server);
    json_get_bool(json_str, "reject_default_weak_appkeys", &policy->reject_default_weak_appkeys);
    json_get_int(json_str, "min_appkey_entropy_bits", &policy->min_appkey_entropy_bits);
    json_get_bool(json_str, "constant_time_mic_verification", &policy->constant_time_mic_verification);
    json_get_bool(json_str, "drop_invalid_mic_at_edge", &policy->drop_invalid_mic_at_edge);
    json_get_bool(json_str, "enforce_regional_band_limits", &policy->enforce_regional_band_limits);
    json_get_double(json_str, "max_eirp_dbm", &policy->max_eirp_dbm);
    json_get_bool(json_str, "local_mqtt_mtls_required", &policy->local_mqtt_mtls_required);
    json_get_bool(json_str, "broker_bind_loopback_only", &policy->broker_bind_loopback_only);
    json_get_bool(json_str, "adr_spoof_guard_enabled", &policy->adr_spoof_guard_enabled);
    json_get_bool(json_str, "rssi_snr_plausibility_check", &policy->rssi_snr_plausibility_check);
    json_get_bool(json_str, "encrypt_root_keys_at_rest", &policy->encrypt_root_keys_at_rest);
    json_get_bool(json_str, "zeroize_old_session_keys", &policy->zeroize_old_session_keys);
    json_get_bool(json_str, "jamming_noise_floor_monitor", &policy->jamming_noise_floor_monitor);
    json_get_bool(json_str, "log_join_and_mic_anomalies", &policy->log_join_and_mic_anomalies);

    return true;
}

bool json_load_policy_file(const char *file_path, gateway_policy_t *policy) {
    if (!file_path || !policy) return false;
    FILE *f = fopen(file_path, "rb");
    if (!f) return false;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }
    long len = ftell(f);
    if (len < 0 || len > 1024 * 1024) { /* max 1 MB */
        fclose(f);
        return false;
    }
    rewind(f);

    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return false;
    }

    size_t read_bytes = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[read_bytes] = '\0';

    bool ok = json_parse_policy(buf, policy);
    free(buf);
    return ok;
}

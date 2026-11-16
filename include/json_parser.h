#ifndef JSON_PARSER_H
#define JSON_PARSER_H

#include "lorawan_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hex utility functions */
bool hex_to_bytes(const char *hex, uint8_t *out, size_t max_out, size_t *out_len);
void bytes_to_hex(const uint8_t *in, size_t len, char *out, size_t max_out);

/* JSON policy parsing */
bool json_parse_policy(const char *json_str, gateway_policy_t *policy);
bool json_load_policy_file(const char *file_path, gateway_policy_t *policy);

/* Simple JSON value extraction helpers */
bool json_get_bool(const char *json, const char *key, bool *out_val);
bool json_get_int(const char *json, const char *key, int *out_val);
bool json_get_double(const char *json, const char *key, double *out_val);
bool json_get_string(const char *json, const char *key, char *out_val, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* JSON_PARSER_H */

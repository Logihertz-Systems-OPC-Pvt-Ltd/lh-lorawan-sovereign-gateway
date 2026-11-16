#ifndef AES128_CMAC_H
#define AES128_CMAC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE 16
#define AES128_KEY_SIZE 16
#define AES128_ROUND_KEYS_SIZE 44

/* FIPS 197 AES-128 Key Expansion and Block Encryption */
void lh_aes128_key_expansion(const uint8_t key[16], uint32_t round_keys[44]);
void lh_aes128_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t round_keys[44]);

/* RFC 4493 AES-128-CMAC Computation */
void lh_aes128_cmac_subkeys(const uint32_t round_keys[44], uint8_t k1[16], uint8_t k2[16]);
void lh_aes128_cmac(const uint8_t key[16], const uint8_t *msg, size_t msg_len, uint8_t mac[16]);

/* LoRaWAN 32-bit Message Integrity Code (MIC) */
uint32_t lh_lorawan_compute_mic(const uint8_t key[16], const uint8_t *msg, size_t msg_len);

/* Constant-Time Comparison & Secure Zeroization */
int lh_constant_time_memcmp(const void *a, const void *b, size_t len);
void lh_secure_zero(void *v, size_t n);

/* LoRaWAN Payload Decryption/Encryption (CTR mode with Ai blocks) */
void lh_lorawan_crypt_payload(
    const uint8_t key[16],
    uint32_t dev_addr,
    uint32_t fcnt,
    uint8_t dir, // 0 = uplink, 1 = downlink
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

#ifdef __cplusplus
}
#endif

#endif /* AES128_CMAC_H */

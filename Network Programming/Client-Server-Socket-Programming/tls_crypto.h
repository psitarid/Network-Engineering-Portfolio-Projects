/* tls_crypto.h
 *
 * The cryptographic building blocks of the DHE-RSA-AES256-SHA256 cipher suite,
 * implemented by hand on top of libcrypto primitives:
 *
 *   - TLS 1.2 PRF (P_SHA256)                         RFC 5246 section 5
 *   - Ephemeral Diffie-Hellman key agreement         RFC 5246 section 7.4.3 / 8.1.2
 *   - RSA PKCS#1 v1.5 signatures with SHA-256        RFC 5246 section 4.7
 *   - Record protection: AES-256-CBC + HMAC-SHA256   RFC 5246 section 6.2.3.2
 *     (MAC-then-encrypt, explicit per-record IV)
 */
#ifndef TLS_CRYPTO_H
#define TLS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#define TLS_RANDOM_LEN      32
#define TLS_MASTER_LEN      48
#define TLS_MAC_KEY_LEN     32   /* HMAC-SHA256  */
#define TLS_ENC_KEY_LEN     32   /* AES-256      */
#define TLS_BLOCK_LEN       16   /* AES block / IV size */
#define TLS_MAC_LEN         32
#define TLS_VERIFY_DATA_LEN 12
#define TLS_MIN_DH_BITS     2048

/* PRF(secret, label, seed) = P_SHA256(secret, label + seed), truncated to out_len. */
int tls_prf(const uint8_t *secret, size_t secret_len, const char *label,
            const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len);

int tls_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* RSA PKCS#1 v1.5 + SHA-256. sign: *sig is malloc'ed. Return 1 on success. */
int rsa_sign_sha256(EVP_PKEY *key, const uint8_t *data, size_t len, uint8_t **sig, size_t *sig_len);
int rsa_verify_sha256(EVP_PKEY *key, const uint8_t *data, size_t len, const uint8_t *sig, size_t sig_len);

/* ---- Diffie-Hellman ----
 * Big-endian byte strings, as they travel on the wire. Buffers returned are malloc'ed. */
typedef struct {
    uint8_t *p,  *g,  *pub;
    size_t   p_len, g_len, pub_len;
} dh_wire_params;

void dh_wire_params_free(dh_wire_params *w);

/* Server: generate an ephemeral key in the RFC 7919 ffdhe2048 group and export p, g, Ys. */
EVP_PKEY *dh_server_keygen(dh_wire_params *out);

/* Client: generate an ephemeral key in the group (p, g) the server chose and export Yc. */
EVP_PKEY *dh_keygen_from_params(const uint8_t *p, size_t p_len, const uint8_t *g, size_t g_len,
                                uint8_t **pub, size_t *pub_len);

/* Shared secret Z = peer_pub ^ own_priv mod p (leading zeros stripped, as TLS requires).
 * The peer's public value is range-checked before use. *secret is malloc'ed. */
int dh_derive(EVP_PKEY *own_key, const uint8_t *peer_pub, size_t peer_pub_len,
              uint8_t **secret, size_t *secret_len);

/* ---- Record protection (one direction) ---- */
typedef struct {
    uint8_t  mac_key[TLS_MAC_KEY_LEN];
    uint8_t  enc_key[TLS_ENC_KEY_LEN];
    uint64_t seq;          /* implicit 64-bit sequence number, starts at 0 after ChangeCipherSpec */
} tls_cipher_state;

/* out must hold len + TLS_BLOCK_LEN (IV) + TLS_MAC_LEN + TLS_BLOCK_LEN (padding). */
int tls_record_encrypt(tls_cipher_state *st, uint8_t content_type, const uint8_t *in, size_t len,
                       uint8_t *out, size_t *out_len);

/* Decrypts in place. On success *plain points inside `buf`. Returns 0 on failure (bad_record_mac). */
int tls_record_decrypt(tls_cipher_state *st, uint8_t content_type, uint8_t *buf, size_t len,
                       uint8_t **plain, size_t *plain_len);

#endif /* TLS_CRYPTO_H */

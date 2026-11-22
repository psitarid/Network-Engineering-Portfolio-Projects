/* tls_crypto.c - cipher-suite primitives for DHE-RSA-AES256-SHA256 (see tls_crypto.h). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "tls_crypto.h"


/* ------------------------------------------------------------------ */
/*  HMAC-SHA256 over up to three concatenated pieces                    */
/* ------------------------------------------------------------------ */
static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len,
                       const uint8_t *c, size_t c_len,
                       uint8_t out[32]) {
    int ok = 0;
    size_t out_len = 0;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if (ctx && EVP_MAC_init(ctx, key, key_len, params)
        && (a_len == 0 || EVP_MAC_update(ctx, a, a_len))
        && (b_len == 0 || EVP_MAC_update(ctx, b, b_len))
        && (c_len == 0 || EVP_MAC_update(ctx, c, c_len))
        && EVP_MAC_final(ctx, out, &out_len, 32))
        ok = 1;

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

int tls_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    unsigned int out_len = 0;
    return EVP_Digest(data, len, out, &out_len, EVP_sha256(), NULL);
}


/* ------------------------------------------------------------------ */
/*  TLS 1.2 PRF                                                         */
/*                                                                      */
/*  P_SHA256(secret, seed) = HMAC(secret, A(1) + seed) +                */
/*                           HMAC(secret, A(2) + seed) + ...            */
/*  A(0) = seed,  A(i) = HMAC(secret, A(i-1))                           */
/*  PRF(secret, label, seed) = P_SHA256(secret, label + seed)           */
/* ------------------------------------------------------------------ */
int tls_prf(const uint8_t *secret, size_t secret_len, const char *label,
            const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len) {
    size_t label_len = strlen(label);
    uint8_t A[32], block[32];

    // A(1) = HMAC(secret, label + seed)
    if (!hmac_sha256(secret, secret_len, (const uint8_t *)label, label_len, seed, seed_len, NULL, 0, A))
        return 0;

    while (out_len > 0) {
        // block = HMAC(secret, A(i) + label + seed)
        if (!hmac_sha256(secret, secret_len, A, 32, (const uint8_t *)label, label_len, seed, seed_len, block))
            return 0;
        size_t n = out_len < 32 ? out_len : 32;
        memcpy(out, block, n);
        out += n;
        out_len -= n;
        // A(i+1) = HMAC(secret, A(i))
        if (!hmac_sha256(secret, secret_len, A, 32, NULL, 0, NULL, 0, A))
            return 0;
    }
    OPENSSL_cleanse(block, sizeof(block));
    OPENSSL_cleanse(A, sizeof(A));
    return 1;
}


/* ------------------------------------------------------------------ */
/*  RSA signatures (PKCS#1 v1.5 with SHA-256)                           */
/* ------------------------------------------------------------------ */
int rsa_sign_sha256(EVP_PKEY *key, const uint8_t *data, size_t len, uint8_t **sig, size_t *sig_len) {
    int ok = 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    *sig = NULL;
    if (md && EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key) == 1
        && EVP_DigestSign(md, NULL, sig_len, data, len) == 1
        && (*sig = malloc(*sig_len)) != NULL
        && EVP_DigestSign(md, *sig, sig_len, data, len) == 1)
        ok = 1;
    if (!ok) { free(*sig); *sig = NULL; }
    EVP_MD_CTX_free(md);
    return ok;
}

int rsa_verify_sha256(EVP_PKEY *key, const uint8_t *data, size_t len, const uint8_t *sig, size_t sig_len) {
    int ok = 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md && EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA
        && EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, key) == 1
        && EVP_DigestVerify(md, sig, sig_len, data, len) == 1)
        ok = 1;
    EVP_MD_CTX_free(md);
    return ok;
}


/* ------------------------------------------------------------------ */
/*  Ephemeral Diffie-Hellman                                            */
/* ------------------------------------------------------------------ */
void dh_wire_params_free(dh_wire_params *w) {
    free(w->p); free(w->g); free(w->pub);
    memset(w, 0, sizeof(*w));
}

// BIGNUM -> malloc'ed big-endian byte string
static int bn_to_bytes(const BIGNUM *bn, uint8_t **out, size_t *out_len) {
    *out_len = (size_t)BN_num_bytes(bn);
    *out = malloc(*out_len ? *out_len : 1);
    if (!*out) return 0;
    BN_bn2bin(bn, *out);
    return 1;
}

static int export_bn_param(EVP_PKEY *key, const char *name, uint8_t **out, size_t *out_len) {
    BIGNUM *bn = NULL;
    int ok = EVP_PKEY_get_bn_param(key, name, &bn) && bn_to_bytes(bn, out, out_len);
    BN_free(bn);
    return ok;
}

EVP_PKEY *dh_server_keygen(dh_wire_params *out) {
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048", 0),   // RFC 7919 safe-prime group
        OSSL_PARAM_construct_end()
    };
    memset(out, 0, sizeof(*out));

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_params(ctx, params) <= 0
        || EVP_PKEY_generate(ctx, &key) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);

    if (!export_bn_param(key, OSSL_PKEY_PARAM_FFC_P, &out->p, &out->p_len)
        || !export_bn_param(key, OSSL_PKEY_PARAM_FFC_G, &out->g, &out->g_len)
        || !export_bn_param(key, OSSL_PKEY_PARAM_PUB_KEY, &out->pub, &out->pub_len)) {
        dh_wire_params_free(out);
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

EVP_PKEY *dh_keygen_from_params(const uint8_t *p, size_t p_len, const uint8_t *g, size_t g_len,
                                uint8_t **pub, size_t *pub_len) {
    EVP_PKEY *domain = NULL, *key = NULL;
    EVP_PKEY_CTX *ctx = NULL, *kctx = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    BIGNUM *bp = BN_bin2bn(p, (int)p_len, NULL);
    BIGNUM *bg = BN_bin2bn(g, (int)g_len, NULL);

    if (!bld || !bp || !bg) goto done;
    if (BN_num_bits(bp) < TLS_MIN_DH_BITS) {                                 // refuse weak groups (Logjam)
        fprintf(stderr, "Server DH group is too small (%d bits, need >= %d)\n", BN_num_bits(bp), TLS_MIN_DH_BITS);
        goto done;
    }
    if (!BN_is_odd(bp) || BN_cmp(bg, BN_value_one()) <= 0) {
        fprintf(stderr, "Server DH parameters are malformed\n");
        goto done;
    }

    // domain parameters (p, g) -> EVP_PKEY, then generate our key pair in that group
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bp)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bg)
        || !(params = OSSL_PARAM_BLD_to_param(bld))
        || !(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL))
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &domain, EVP_PKEY_KEY_PARAMETERS, params) <= 0
        || !(kctx = EVP_PKEY_CTX_new_from_pkey(NULL, domain, NULL))
        || EVP_PKEY_keygen_init(kctx) <= 0
        || EVP_PKEY_generate(kctx, &key) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(key);
        key = NULL;
        goto done;
    }
    if (!export_bn_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len)) {
        EVP_PKEY_free(key);
        key = NULL;
    }

done:
    BN_free(bp); BN_free(bg);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(domain);
    return key;
}

int dh_derive(EVP_PKEY *own_key, const uint8_t *peer_pub, size_t peer_pub_len,
              uint8_t **secret, size_t *secret_len) {
    int ok = 0;
    BIGNUM *p = NULL, *y = BN_bin2bn(peer_pub, (int)peer_pub_len, NULL);
    BIGNUM *p_minus_1 = BN_new();
    OSSL_PARAM *domain = NULL, *pubp = NULL, *merged = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    EVP_PKEY_CTX *fctx = NULL, *dctx = NULL;
    EVP_PKEY *peer = NULL;
    *secret = NULL;

    // range check: 1 < y < p - 1  (rejects 0, 1 and p-1 small-subgroup values)
    if (!y || !p_minus_1 || !bld || !EVP_PKEY_get_bn_param(own_key, OSSL_PKEY_PARAM_FFC_P, &p)) goto done;
    BN_copy(p_minus_1, p);
    BN_sub_word(p_minus_1, 1);
    if (BN_cmp(y, BN_value_one()) <= 0 || BN_cmp(y, p_minus_1) >= 0) {
        fprintf(stderr, "Peer DH public value is out of range\n");
        goto done;
    }

    // peer key = our domain parameters + the peer's public value
    if (!EVP_PKEY_todata(own_key, EVP_PKEY_KEY_PARAMETERS, &domain)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, y)
        || !(pubp = OSSL_PARAM_BLD_to_param(bld))
        || !(merged = OSSL_PARAM_merge(domain, pubp))
        || !(fctx = EVP_PKEY_CTX_new_from_pkey(NULL, own_key, NULL))
        || EVP_PKEY_fromdata_init(fctx) <= 0
        || EVP_PKEY_fromdata(fctx, &peer, EVP_PKEY_PUBLIC_KEY, merged) <= 0)
        goto done;

    // Z = y ^ x mod p
    if (!(dctx = EVP_PKEY_CTX_new_from_pkey(NULL, own_key, NULL))
        || EVP_PKEY_derive_init(dctx) <= 0
        || EVP_PKEY_derive_set_peer(dctx, peer) <= 0
        || EVP_PKEY_derive(dctx, NULL, secret_len) <= 0
        || !(*secret = malloc(*secret_len))
        || EVP_PKEY_derive(dctx, *secret, secret_len) <= 0)
        goto done;

    // TLS uses Z with leading zero bytes stripped (RFC 5246 section 8.1.2)
    size_t skip = 0;
    while (skip < *secret_len - 1 && (*secret)[skip] == 0) skip++;
    if (skip) {
        memmove(*secret, *secret + skip, *secret_len - skip);
        *secret_len -= skip;
    }
    ok = 1;

done:
    if (!ok) {
        ERR_print_errors_fp(stderr);
        free(*secret);
        *secret = NULL;
    }
    BN_free(p); BN_free(y); BN_free(p_minus_1);
    OSSL_PARAM_free(domain); OSSL_PARAM_free(pubp); OSSL_PARAM_free(merged);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(fctx); EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer);
    return ok;
}


/* ------------------------------------------------------------------ */
/*  Record protection: AES-256-CBC + HMAC-SHA256 (MAC-then-encrypt)     */
/*                                                                      */
/*  MAC = HMAC(mac_key, seq_num(8) + type(1) + version(2) + length(2)   */
/*             + plaintext)                                             */
/*  fragment = IV(16) + AES-CBC(plaintext + MAC + padding + pad_len)    */
/* ------------------------------------------------------------------ */
static void mac_header(uint8_t hdr[13], uint64_t seq, uint8_t type, size_t len) {
    for (int i = 7; i >= 0; i--) { hdr[i] = (uint8_t)(seq & 0xff); seq >>= 8; }
    hdr[8]  = type;
    hdr[9]  = 0x03;                       // TLS 1.2 = {3, 3}
    hdr[10] = 0x03;
    hdr[11] = (uint8_t)(len >> 8);
    hdr[12] = (uint8_t)(len & 0xff);
}

static int aes_cbc(int encrypt, const uint8_t key[32], const uint8_t iv[16],
                   const uint8_t *in, size_t len, uint8_t *out) {
    int ok = 0, n1 = 0, n2 = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx && EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, encrypt) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1                          // TLS does its own padding
        && EVP_CipherUpdate(ctx, out, &n1, in, (int)len) == 1
        && EVP_CipherFinal_ex(ctx, out + n1, &n2) == 1
        && (size_t)(n1 + n2) == len)
        ok = 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int tls_record_encrypt(tls_cipher_state *st, uint8_t content_type, const uint8_t *in, size_t len,
                       uint8_t *out, size_t *out_len) {
    uint8_t hdr[13];
    uint8_t *iv = out, *body = out + TLS_BLOCK_LEN;

    // 1. MAC over the plaintext
    mac_header(hdr, st->seq, content_type, len);
    memcpy(body, in, len);
    if (!hmac_sha256(st->mac_key, TLS_MAC_KEY_LEN, hdr, 13, in, len, NULL, 0, body + len))
        return 0;

    // 2. padding: pad_len+1 bytes each equal to pad_len, so the total is a multiple of 16
    size_t content = len + TLS_MAC_LEN;
    size_t pad_len = TLS_BLOCK_LEN - 1 - (content % TLS_BLOCK_LEN);
    memset(body + content, (int)pad_len, pad_len + 1);
    size_t body_len = content + pad_len + 1;

    // 3. fresh random IV for every record, then encrypt in place
    if (RAND_bytes(iv, TLS_BLOCK_LEN) != 1 || !aes_cbc(1, st->enc_key, iv, body, body_len, body))
        return 0;

    *out_len = TLS_BLOCK_LEN + body_len;
    st->seq++;
    return 1;
}

int tls_record_decrypt(tls_cipher_state *st, uint8_t content_type, uint8_t *buf, size_t len,
                       uint8_t **plain, size_t *plain_len) {
    uint8_t hdr[13], mac[TLS_MAC_LEN];

    // smallest valid record: IV + one block holding MAC(32) + pad byte -> IV + 48
    if (len < TLS_BLOCK_LEN + TLS_MAC_LEN + TLS_BLOCK_LEN || (len - TLS_BLOCK_LEN) % TLS_BLOCK_LEN != 0)
        return 0;

    uint8_t *iv = buf, *body = buf + TLS_BLOCK_LEN;
    size_t body_len = len - TLS_BLOCK_LEN;
    if (!aes_cbc(0, st->enc_key, iv, body, body_len, body))
        return 0;

    // check the padding. Note: failures and MAC errors produce the same alert (bad_record_mac)
    // so a peer cannot tell them apart (padding-oracle mitigation).
    size_t pad_len = body[body_len - 1];
    int good = 1;
    if (pad_len + 1 + TLS_MAC_LEN > body_len) {
        good = 0;
        pad_len = 0;
    }
    for (size_t i = 0; i <= pad_len; i++)
        good &= (body[body_len - 1 - i] == pad_len);

    size_t data_len = body_len - pad_len - 1 - TLS_MAC_LEN;
    mac_header(hdr, st->seq, content_type, data_len);
    if (!hmac_sha256(st->mac_key, TLS_MAC_KEY_LEN, hdr, 13, body, data_len, NULL, 0, mac))
        return 0;
    good &= (CRYPTO_memcmp(mac, body + data_len, TLS_MAC_LEN) == 0);

    if (!good) return 0;
    *plain = body;
    *plain_len = data_len;
    st->seq++;
    return 1;
}

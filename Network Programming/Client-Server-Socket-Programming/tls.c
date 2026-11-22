/* tls.c
 *
 * TLS 1.2 record layer + handshake for TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
 * with mutual certificate authentication (see tls.h).
 *
 *      CLIENT                                              SERVER
 *      ClientHello              -------->
 *                                                     ServerHello
 *                                                     Certificate
 *                                               ServerKeyExchange
 *                                              CertificateRequest
 *                               <--------         ServerHelloDone
 *      Certificate
 *      ClientKeyExchange
 *      CertificateVerify
 *      [ChangeCipherSpec]
 *      Finished                 -------->
 *                                              [ChangeCipherSpec]
 *                               <--------                Finished
 *      Application Data         <------->        Application Data
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "tls.h"
#include "cert_509X.h"

/* Record content types */
#define CT_CHANGE_CIPHER_SPEC  20
#define CT_ALERT               21
#define CT_HANDSHAKE           22
#define CT_APPLICATION_DATA    23

/* Handshake message types */
#define HT_HELLO_REQUEST        0
#define HT_CLIENT_HELLO         1
#define HT_SERVER_HELLO         2
#define HT_CERTIFICATE         11
#define HT_SERVER_KEY_EXCHANGE 12
#define HT_CERTIFICATE_REQUEST 13
#define HT_SERVER_HELLO_DONE   14
#define HT_CERTIFICATE_VERIFY  15
#define HT_CLIENT_KEY_EXCHANGE 16
#define HT_FINISHED            20

/* Alerts */
#define ALERT_WARNING           1
#define ALERT_FATAL             2
#define AD_CLOSE_NOTIFY         0
#define AD_UNEXPECTED_MESSAGE  10
#define AD_BAD_RECORD_MAC      20
#define AD_RECORD_OVERFLOW     22
#define AD_HANDSHAKE_FAILURE   40
#define AD_BAD_CERTIFICATE     42
#define AD_ILLEGAL_PARAMETER   47
#define AD_DECODE_ERROR        50
#define AD_DECRYPT_ERROR       51
#define AD_PROTOCOL_VERSION    70
#define AD_INSUFFICIENT_SECURITY 71
#define AD_INTERNAL_ERROR      80
#define AD_NO_RENEGOTIATION   100
#define AD_UNSUPPORTED_EXT    110

/* Extensions / algorithm identifiers */
#define EXT_SIGNATURE_ALGORITHMS 0x000d
#define EXT_RENEGOTIATION_INFO   0xff01
#define SCSV_EMPTY_RENEGOTIATION 0x00ff
#define HASH_SHA256    4
#define SIG_RSA        1
#define CERT_TYPE_RSA_SIGN 1

#define TLS_VERSION_MAJOR 3
#define TLS_VERSION_MINOR 3                     /* {3,3} = TLS 1.2 */
#define MAX_HANDSHAKE_MSG (64 * 1024)

#define LOG(s, ...) do { if ((s)->verbose) printf(__VA_ARGS__); } while (0)


/* ================================================================== */
/*  Helpers: growing write buffer and bounds-checked reader             */
/* ================================================================== */
typedef struct { uint8_t *d; size_t len, cap; int err; } wbuf;

static void wb_reserve(wbuf *b, size_t extra) {
    if (b->err || b->len + extra <= b->cap) return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra) cap *= 2;
    uint8_t *d = realloc(b->d, cap);
    if (!d) { b->err = 1; return; }
    b->d = d; b->cap = cap;
}
static void put_bytes(wbuf *b, const void *p, size_t n) {
    wb_reserve(b, n);
    if (b->err) return;
    if (n) memcpy(b->d + b->len, p, n);
    b->len += n;
}
static void put_u8(wbuf *b, unsigned v)  { uint8_t x = (uint8_t)v; put_bytes(b, &x, 1); }
static void put_u16(wbuf *b, unsigned v) { uint8_t x[2] = { (uint8_t)(v >> 8), (uint8_t)v }; put_bytes(b, x, 2); }
static void put_u24(wbuf *b, size_t v)   { uint8_t x[3] = { (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v }; put_bytes(b, x, 3); }
static void put_vec16(wbuf *b, const void *p, size_t n) { put_u16(b, (unsigned)n); put_bytes(b, p, n); }
static void put_vec24(wbuf *b, const void *p, size_t n) { put_u24(b, n);           put_bytes(b, p, n); }
static void wb_free(wbuf *b) { free(b->d); memset(b, 0, sizeof(*b)); }

typedef struct { const uint8_t *p; size_t len; int err; } reader;

static const uint8_t *get_bytes(reader *r, size_t n) {
    if (r->err || r->len < n) { r->err = 1; return NULL; }
    const uint8_t *p = r->p;
    r->p += n; r->len -= n;
    return p;
}
static unsigned get_u8(reader *r)  { const uint8_t *p = get_bytes(r, 1); return p ? p[0] : 0; }
static unsigned get_u16(reader *r) { const uint8_t *p = get_bytes(r, 2); return p ? (unsigned)(p[0] << 8 | p[1]) : 0; }
static size_t   get_u24(reader *r) { const uint8_t *p = get_bytes(r, 3); return p ? ((size_t)p[0] << 16 | (size_t)p[1] << 8 | p[2]) : 0; }
static reader get_vec(reader *r, size_t len_bytes) {
    size_t n = len_bytes == 1 ? get_u8(r) : len_bytes == 2 ? get_u16(r) : get_u24(r);
    reader sub = { get_bytes(r, n), n, r->err };
    return sub;
}


/* ================================================================== */
/*  Alerts                                                              */
/* ================================================================== */
static const char *alert_name(unsigned d) {
    switch (d) {
        case AD_CLOSE_NOTIFY:        return "close_notify";
        case AD_UNEXPECTED_MESSAGE:  return "unexpected_message";
        case AD_BAD_RECORD_MAC:      return "bad_record_mac";
        case AD_RECORD_OVERFLOW:     return "record_overflow";
        case AD_HANDSHAKE_FAILURE:   return "handshake_failure";
        case AD_BAD_CERTIFICATE:     return "bad_certificate";
        case 43:                     return "unsupported_certificate";
        case 44:                     return "certificate_revoked";
        case 45:                     return "certificate_expired";
        case 46:                     return "certificate_unknown";
        case AD_ILLEGAL_PARAMETER:   return "illegal_parameter";
        case 48:                     return "unknown_ca";
        case 49:                     return "access_denied";
        case AD_DECODE_ERROR:        return "decode_error";
        case AD_DECRYPT_ERROR:       return "decrypt_error";
        case AD_PROTOCOL_VERSION:    return "protocol_version";
        case 71:                     return "insufficient_security";
        case AD_INTERNAL_ERROR:      return "internal_error";
        case AD_NO_RENEGOTIATION:    return "no_renegotiation";
        case AD_UNSUPPORTED_EXT:     return "unsupported_extension";
        case 116:                    return "certificate_required";
        default:                     return "unknown";
    }
}

static int send_record(tls_session *s, uint8_t type, const uint8_t *data, size_t len);

static void send_alert(tls_session *s, unsigned level, unsigned desc) {
    uint8_t a[2] = { (uint8_t)level, (uint8_t)desc };
    send_record(s, CT_ALERT, a, 2);
}

// report a fatal error locally, tell the peer, and fail
static int fatal(tls_session *s, unsigned desc, const char *why) {
    fprintf(stderr, "TLS error: %s (sending alert: %s)\n", why, alert_name(desc));
    send_alert(s, ALERT_FATAL, desc);
    return -1;
}


/* ================================================================== */
/*  Record layer                                                        */
/*  TLSPlaintext: type(1) | version(2) | length(2) | fragment           */
/* ================================================================== */
static int send_record(tls_session *s, uint8_t type, const uint8_t *data, size_t len) {
    uint8_t rec[5 + TLS_MAX_PLAINTEXT + TLS_BLOCK_LEN + TLS_MAC_LEN + TLS_BLOCK_LEN];

    do {
        size_t chunk = len > TLS_MAX_PLAINTEXT ? TLS_MAX_PLAINTEXT : len;
        size_t frag_len = chunk;

        if (s->write_encrypted) {
            if (!tls_record_encrypt(&s->write_state, type, data, chunk, rec + 5, &frag_len))
                return -1;
        } else {
            memcpy(rec + 5, data, chunk);
        }
        rec[0] = type;
        rec[1] = TLS_VERSION_MAJOR;
        rec[2] = TLS_VERSION_MINOR;
        rec[3] = (uint8_t)(frag_len >> 8);
        rec[4] = (uint8_t)frag_len;
        if (send_all(s->sock, rec, 5 + frag_len) != 0) return -1;

        data += chunk;
        len  -= chunk;
    } while (len > 0);
    return 0;
}

// Read one record. On success *data points into s->rec_buf (decrypted if a cipher is active).
static int recv_record(tls_session *s, uint8_t *type, uint8_t **data, size_t *len) {
    uint8_t *hdr = s->rec_buf;
    if (recv_all(s->sock, hdr, 5) != 0) {
        fprintf(stderr, "TLS error: connection closed by peer\n");
        return -1;
    }
    size_t frag_len = (size_t)hdr[3] << 8 | hdr[4];
    if (hdr[1] != TLS_VERSION_MAJOR)
        return fatal(s, AD_PROTOCOL_VERSION, "record is not TLS");
    if (frag_len > TLS_MAX_PLAINTEXT + 2048)
        return fatal(s, AD_RECORD_OVERFLOW, "record too large");
    if (recv_all(s->sock, s->rec_buf + 5, frag_len) != 0) {
        fprintf(stderr, "TLS error: connection closed in the middle of a record\n");
        return -1;
    }

    *type = hdr[0];
    *data = s->rec_buf + 5;
    *len  = frag_len;
    if (s->read_encrypted) {
        if (!tls_record_decrypt(&s->read_state, *type, s->rec_buf + 5, frag_len, data, len))
            return fatal(s, AD_BAD_RECORD_MAC, "record failed decryption / MAC check");
        if (*len > TLS_MAX_PLAINTEXT)
            return fatal(s, AD_RECORD_OVERFLOW, "decrypted record too large");
    }
    return 0;
}

// The peer sent an alert. Returns 1 if it was close_notify, 0 for a warning, -1 for fatal.
static int handle_alert(tls_session *s, const uint8_t *data, size_t len) {
    if (len != 2) return fatal(s, AD_DECODE_ERROR, "malformed alert");
    if (data[1] == AD_CLOSE_NOTIFY) {
        s->peer_closed = 1;
        return 1;
    }
    fprintf(stderr, "TLS: received %s alert: %s\n",
            data[0] == ALERT_FATAL ? "fatal" : "warning", alert_name(data[1]));
    return data[0] == ALERT_FATAL ? -1 : 0;
}


/* ================================================================== */
/*  Handshake message framing + transcript                              */
/*  Handshake: msg_type(1) | length(3) | body                           */
/* ================================================================== */
static int transcript_add(tls_session *s, const uint8_t *msg, size_t len) {
    if (s->transcript_len + len > s->transcript_cap) {
        size_t cap = s->transcript_cap ? s->transcript_cap : 4096;
        while (cap < s->transcript_len + len) cap *= 2;
        uint8_t *t = realloc(s->transcript, cap);
        if (!t) return -1;
        s->transcript = t;
        s->transcript_cap = cap;
    }
    memcpy(s->transcript + s->transcript_len, msg, len);
    s->transcript_len += len;
    return 0;
}

static const char *hs_name(unsigned t) {
    switch (t) {
        case HT_CLIENT_HELLO:         return "ClientHello";
        case HT_SERVER_HELLO:         return "ServerHello";
        case HT_CERTIFICATE:          return "Certificate";
        case HT_SERVER_KEY_EXCHANGE:  return "ServerKeyExchange";
        case HT_CERTIFICATE_REQUEST:  return "CertificateRequest";
        case HT_SERVER_HELLO_DONE:    return "ServerHelloDone";
        case HT_CERTIFICATE_VERIFY:   return "CertificateVerify";
        case HT_CLIENT_KEY_EXCHANGE:  return "ClientKeyExchange";
        case HT_FINISHED:             return "Finished";
        default:                      return "Unknown";
    }
}

static int send_handshake(tls_session *s, unsigned type, const wbuf *body) {
    wbuf msg = {0};
    put_u8(&msg, type);
    put_vec24(&msg, body->d, body->len);
    int rc = -1;
    if (!msg.err && !body->err && transcript_add(s, msg.d, msg.len) == 0
        && send_record(s, CT_HANDSHAKE, msg.d, msg.len) == 0) {
        LOG(s, "  >> %s%s\n", hs_name(type), s->write_encrypted ? " (encrypted)" : "");
        rc = 0;
    }
    wb_free(&msg);
    return rc;
}

// drop the message returned by the previous read_handshake()
static void hs_compact(tls_session *s) {
    if (s->hs_consume) {
        memmove(s->hs_buf, s->hs_buf + s->hs_consume, s->hs_len - s->hs_consume);
        s->hs_len -= s->hs_consume;
        s->hs_consume = 0;
    }
}

// read one more handshake record and append it to hs_buf
static int hs_fill(tls_session *s) {
    for (;;) {
        uint8_t type, *data;
        size_t len;
        if (recv_record(s, &type, &data, &len) != 0) return -1;
        if (type == CT_ALERT) {
            if (handle_alert(s, data, len) != 0) return -1;
            continue;                                                     // warning alert: keep going
        }
        if (type != CT_HANDSHAKE || len == 0)
            return fatal(s, AD_UNEXPECTED_MESSAGE, "expected a handshake record");

        if (s->hs_len + len > s->hs_cap) {
            size_t cap = s->hs_cap ? s->hs_cap : 8192;
            while (cap < s->hs_len + len) cap *= 2;
            if (cap > 2 * MAX_HANDSHAKE_MSG) return fatal(s, AD_INTERNAL_ERROR, "handshake buffer overflow");
            uint8_t *b = realloc(s->hs_buf, cap);
            if (!b) return fatal(s, AD_INTERNAL_ERROR, "out of memory");
            s->hs_buf = b;
            s->hs_cap = cap;
        }
        memcpy(s->hs_buf + s->hs_len, data, len);
        s->hs_len += len;
        return 0;
    }
}

/* Read the next handshake message (one record may carry several messages, and one message
 * may span several records). On success *msg points at its 4-byte header and stays valid
 * until the next call. The caller decides when to add it to the transcript. */
static int read_handshake(tls_session *s, unsigned expected, uint8_t **msg, size_t *msg_len) {
    hs_compact(s);
    for (;;) {
        if (s->hs_len >= 4) {
            size_t body_len = (size_t)s->hs_buf[1] << 16 | (size_t)s->hs_buf[2] << 8 | s->hs_buf[3];
            if (body_len > MAX_HANDSHAKE_MSG) return fatal(s, AD_ILLEGAL_PARAMETER, "handshake message too large");
            if (s->hs_len >= 4 + body_len) {
                unsigned type = s->hs_buf[0];
                if (type != expected) {
                    char why[96];
                    snprintf(why, sizeof(why), "expected %s but received %s", hs_name(expected), hs_name(type));
                    return fatal(s, AD_UNEXPECTED_MESSAGE, why);
                }
                *msg = s->hs_buf;
                *msg_len = 4 + body_len;
                s->hs_consume = 4 + body_len;
                LOG(s, "  << %s%s\n", hs_name(type), s->read_encrypted ? " (encrypted)" : "");
                return 0;
            }
        }
        if (hs_fill(s) != 0) return -1;
    }
}

// type of the next handshake message, without consuming it
static int peek_handshake_type(tls_session *s, unsigned *type) {
    hs_compact(s);
    while (s->hs_len < 1)
        if (hs_fill(s) != 0) return -1;
    *type = s->hs_buf[0];
    return 0;
}

static int send_change_cipher_spec(tls_session *s) {
    uint8_t one = 1;
    if (send_record(s, CT_CHANGE_CIPHER_SPEC, &one, 1) != 0) return -1;
    s->write_encrypted = 1;                                              // everything after this is encrypted
    s->write_state.seq = 0;
    LOG(s, "  >> ChangeCipherSpec\n");
    return 0;
}

static int read_change_cipher_spec(tls_session *s) {
    hs_compact(s);
    if (s->hs_len != 0)                                                   // CCS must sit on a message boundary
        return fatal(s, AD_UNEXPECTED_MESSAGE, "ChangeCipherSpec in the middle of a handshake flight");
    for (;;) {
        uint8_t type, *data;
        size_t len;
        if (recv_record(s, &type, &data, &len) != 0) return -1;
        if (type == CT_ALERT) { if (handle_alert(s, data, len) != 0) return -1; continue; }
        if (type != CT_CHANGE_CIPHER_SPEC || len != 1 || data[0] != 1)
            return fatal(s, AD_UNEXPECTED_MESSAGE, "expected ChangeCipherSpec");
        break;
    }
    s->read_encrypted = 1;
    s->read_state.seq = 0;
    LOG(s, "  << ChangeCipherSpec\n");
    return 0;
}


/* ================================================================== */
/*  Key schedule                                                        */
/* ================================================================== */
static int derive_keys(tls_session *s, const uint8_t *pre_master, size_t pre_master_len) {
    uint8_t seed[2 * TLS_RANDOM_LEN];
    uint8_t key_block[2 * TLS_MAC_KEY_LEN + 2 * TLS_ENC_KEY_LEN];

    // master_secret = PRF(pre_master_secret, "master secret", client_random + server_random)[0..47]
    memcpy(seed, s->client_random, TLS_RANDOM_LEN);
    memcpy(seed + TLS_RANDOM_LEN, s->server_random, TLS_RANDOM_LEN);
    if (!tls_prf(pre_master, pre_master_len, "master secret", seed, sizeof(seed), s->master_secret, TLS_MASTER_LEN))
        return -1;

    // key_block = PRF(master_secret, "key expansion", server_random + client_random)
    memcpy(seed, s->server_random, TLS_RANDOM_LEN);
    memcpy(seed + TLS_RANDOM_LEN, s->client_random, TLS_RANDOM_LEN);
    if (!tls_prf(s->master_secret, TLS_MASTER_LEN, "key expansion", seed, sizeof(seed), key_block, sizeof(key_block)))
        return -1;

    // key_block = client_MAC | server_MAC | client_key | server_key  (CBC in TLS 1.2 uses explicit IVs)
    const uint8_t *client_mac = key_block;
    const uint8_t *server_mac = key_block + TLS_MAC_KEY_LEN;
    const uint8_t *client_key = key_block + 2 * TLS_MAC_KEY_LEN;
    const uint8_t *server_key = key_block + 2 * TLS_MAC_KEY_LEN + TLS_ENC_KEY_LEN;
    int is_client = (s->role == TLS_ROLE_CLIENT);

    memcpy(s->write_state.mac_key, is_client ? client_mac : server_mac, TLS_MAC_KEY_LEN);
    memcpy(s->write_state.enc_key, is_client ? client_key : server_key, TLS_ENC_KEY_LEN);
    memcpy(s->read_state.mac_key,  is_client ? server_mac : client_mac, TLS_MAC_KEY_LEN);
    memcpy(s->read_state.enc_key,  is_client ? server_key : client_key, TLS_ENC_KEY_LEN);

    OPENSSL_cleanse(key_block, sizeof(key_block));
    LOG(s, "  ** master secret and session keys derived\n");
    return 0;
}

// verify_data = PRF(master_secret, finished_label, SHA256(handshake_messages))[0..11]
static int compute_verify_data(tls_session *s, const char *label, uint8_t out[TLS_VERIFY_DATA_LEN]) {
    uint8_t hash[32];
    return tls_sha256(s->transcript, s->transcript_len, hash)
        && tls_prf(s->master_secret, TLS_MASTER_LEN, label, hash, sizeof(hash), out, TLS_VERIFY_DATA_LEN) ? 0 : -1;
}

static int send_finished(tls_session *s) {
    uint8_t vd[TLS_VERIFY_DATA_LEN];
    const char *label = s->role == TLS_ROLE_CLIENT ? "client finished" : "server finished";
    if (compute_verify_data(s, label, vd) != 0) return -1;
    wbuf body = {0};
    put_bytes(&body, vd, sizeof(vd));
    int rc = send_handshake(s, HT_FINISHED, &body);
    wb_free(&body);
    return rc;
}

static int read_finished(tls_session *s) {
    uint8_t expected[TLS_VERIFY_DATA_LEN], *msg;
    size_t len;
    const char *label = s->role == TLS_ROLE_CLIENT ? "server finished" : "client finished";
    if (compute_verify_data(s, label, expected) != 0) return fatal(s, AD_INTERNAL_ERROR, "PRF failed");
    if (read_handshake(s, HT_FINISHED, &msg, &len) != 0) return -1;
    if (len != 4 + TLS_VERIFY_DATA_LEN) return fatal(s, AD_DECODE_ERROR, "bad Finished length");
    if (CRYPTO_memcmp(msg + 4, expected, TLS_VERIFY_DATA_LEN) != 0)
        return fatal(s, AD_DECRYPT_ERROR, "Finished verify_data mismatch (handshake was tampered with)");
    return transcript_add(s, msg, len);
}


/* ================================================================== */
/*  Certificates                                                        */
/* ================================================================== */
static int send_certificate(tls_session *s) {
    unsigned char *der = NULL;
    int der_len = i2d_X509(s->own_cert, &der);
    if (der_len <= 0) return fatal(s, AD_INTERNAL_ERROR, "cannot encode our certificate");

    wbuf list = {0}, body = {0};
    put_vec24(&list, der, (size_t)der_len);                               // certificate_list = <cert>
    put_vec24(&body, list.d, list.len);
    int rc = send_handshake(s, HT_CERTIFICATE, &body);
    OPENSSL_free(der);
    wb_free(&list);
    wb_free(&body);
    return rc;
}

static int read_certificate(tls_session *s) {
    uint8_t *msg;
    size_t len;
    if (read_handshake(s, HT_CERTIFICATE, &msg, &len) != 0) return -1;

    reader r = { msg + 4, len - 4, 0 };
    reader list = get_vec(&r, 3);
    if (r.err || r.len != 0) return fatal(s, AD_DECODE_ERROR, "malformed Certificate");
    if (list.len == 0)
        return fatal(s, AD_HANDSHAKE_FAILURE, "peer sent no certificate (mutual authentication is required)");

    reader first = get_vec(&list, 3);                                     // the peer's own (leaf) certificate
    if (first.err) return fatal(s, AD_DECODE_ERROR, "malformed certificate entry");
    const unsigned char *p = first.p;
    s->peer_cert = d2i_X509(NULL, &p, (long)first.len);
    if (!s->peer_cert || p != first.p + first.len) return fatal(s, AD_BAD_CERTIFICATE, "cannot parse peer certificate");

    if (s->verbose) print_cert_summary("Peer certificate", s->peer_cert);
    cert_role_t expected = s->role == TLS_ROLE_CLIENT ? CERT_ROLE_SERVER : CERT_ROLE_CLIENT;
    if (!verify_peer_cert(s->peer_cert, s->ca_cert, expected,
                          s->role == TLS_ROLE_CLIENT ? s->expected_peer_ip : NULL))
        return fatal(s, AD_BAD_CERTIFICATE, "peer certificate is not trusted");
    LOG(s, "  ** peer certificate verified (trusted CA, valid dates, correct purpose%s)\n",
        s->role == TLS_ROLE_CLIENT && s->expected_peer_ip ? ", IP matches" : "");

    return transcript_add(s, msg, len);
}


/* ================================================================== */
/*  CLIENT side                                                         */
/* ================================================================== */
static int client_send_hello(tls_session *s) {
    if (RAND_bytes(s->client_random, TLS_RANDOM_LEN) != 1) return -1;

    wbuf body = {0}, ext = {0}, sigalgs = {0};
    put_u8(&body, TLS_VERSION_MAJOR);                                     // client_version = TLS 1.2
    put_u8(&body, TLS_VERSION_MINOR);
    put_bytes(&body, s->client_random, TLS_RANDOM_LEN);                   // random
    put_u8(&body, 0);                                                     // session_id: empty (no resumption)
    put_u16(&body, 4);                                                    // cipher_suites
    put_u16(&body, TLS_CIPHER_SUITE_ID);                                  //   DHE-RSA-AES256-SHA256
    put_u16(&body, SCSV_EMPTY_RENEGOTIATION);                             //   "I support secure renegotiation"
    put_u8(&body, 1);                                                     // compression_methods
    put_u8(&body, 0);                                                     //   null

    // extension: signature_algorithms = { rsa_pkcs1_sha256 }
    put_u16(&sigalgs, 2);
    put_u8(&sigalgs, HASH_SHA256);
    put_u8(&sigalgs, SIG_RSA);
    put_u16(&ext, EXT_SIGNATURE_ALGORITHMS);
    put_vec16(&ext, sigalgs.d, sigalgs.len);
    put_vec16(&body, ext.d, ext.len);

    int rc = send_handshake(s, HT_CLIENT_HELLO, &body);
    wb_free(&body); wb_free(&ext); wb_free(&sigalgs);
    return rc;
}

static int client_read_server_hello(tls_session *s) {
    uint8_t *msg;
    size_t len;
    if (read_handshake(s, HT_SERVER_HELLO, &msg, &len) != 0) return -1;

    reader r = { msg + 4, len - 4, 0 };
    unsigned major = get_u8(&r), minor = get_u8(&r);
    const uint8_t *random = get_bytes(&r, TLS_RANDOM_LEN);
    reader sid = get_vec(&r, 1);
    unsigned suite = get_u16(&r);
    unsigned compression = get_u8(&r);
    if (r.err || sid.len > 32) return fatal(s, AD_DECODE_ERROR, "malformed ServerHello");
    if (major != TLS_VERSION_MAJOR || minor != TLS_VERSION_MINOR)
        return fatal(s, AD_PROTOCOL_VERSION, "server did not select TLS 1.2");
    if (suite != TLS_CIPHER_SUITE_ID)
        return fatal(s, AD_ILLEGAL_PARAMETER, "server selected a cipher suite we did not offer");
    if (compression != 0)
        return fatal(s, AD_ILLEGAL_PARAMETER, "server selected compression");
    memcpy(s->server_random, random, TLS_RANDOM_LEN);

    if (r.len > 0) {                                                       // optional extensions
        reader exts = get_vec(&r, 2);
        while (!exts.err && exts.len > 0) {
            unsigned type = get_u16(&exts);
            reader data = get_vec(&exts, 2);
            if (exts.err) break;
            if (type == EXT_RENEGOTIATION_INFO) {
                if (data.len != 1 || data.p[0] != 0)
                    return fatal(s, AD_HANDSHAKE_FAILURE, "bad renegotiation_info");
                s->secure_renegotiation = 1;
            } else {
                return fatal(s, AD_UNSUPPORTED_EXT, "server sent an extension we did not offer");
            }
        }
        if (exts.err || r.len != 0) return fatal(s, AD_DECODE_ERROR, "malformed ServerHello extensions");
    }
    LOG(s, "  ** server chose TLS 1.2, %s\n", TLS_CIPHER_SUITE_NAME);
    return transcript_add(s, msg, len);
}

/* ServerKeyExchange: dh_p, dh_g, dh_Ys + signature over (client_random + server_random + params) */
static int client_read_server_key_exchange(tls_session *s, EVP_PKEY **dh_key, uint8_t **yc, size_t *yc_len,
                                           uint8_t **ys, size_t *ys_len) {
    uint8_t *msg;
    size_t len;
    if (read_handshake(s, HT_SERVER_KEY_EXCHANGE, &msg, &len) != 0) return -1;

    reader r = { msg + 4, len - 4, 0 };
    const uint8_t *params_start = r.p;
    reader p  = get_vec(&r, 2);
    reader g  = get_vec(&r, 2);
    reader Ys = get_vec(&r, 2);
    size_t params_len = (size_t)(r.p - params_start);
    unsigned hash = get_u8(&r), sig_alg = get_u8(&r);
    reader sig = get_vec(&r, 2);
    if (r.err || r.len != 0 || p.len == 0 || g.len == 0 || Ys.len == 0)
        return fatal(s, AD_DECODE_ERROR, "malformed ServerKeyExchange");
    if (hash != HASH_SHA256 || sig_alg != SIG_RSA)
        return fatal(s, AD_ILLEGAL_PARAMETER, "ServerKeyExchange not signed with rsa_pkcs1_sha256");

    // the server proves it owns the certificate's private key and that the DH values are fresh
    size_t signed_len = 2 * TLS_RANDOM_LEN + params_len;
    uint8_t *signed_data = malloc(signed_len);
    if (!signed_data) return fatal(s, AD_INTERNAL_ERROR, "out of memory");
    memcpy(signed_data, s->client_random, TLS_RANDOM_LEN);
    memcpy(signed_data + TLS_RANDOM_LEN, s->server_random, TLS_RANDOM_LEN);
    memcpy(signed_data + 2 * TLS_RANDOM_LEN, params_start, params_len);
    EVP_PKEY *server_pub = X509_get0_pubkey(s->peer_cert);
    int good = server_pub && rsa_verify_sha256(server_pub, signed_data, signed_len, sig.p, sig.len);
    free(signed_data);
    if (!good) return fatal(s, AD_DECRYPT_ERROR, "ServerKeyExchange signature is invalid");
    LOG(s, "  ** DH parameters signed by the server: OK (%zu-bit group)\n", p.len * 8);

    // generate our own ephemeral DH key in the same group
    *dh_key = dh_keygen_from_params(p.p, p.len, g.p, g.len, yc, yc_len);
    if (!*dh_key) return fatal(s, AD_INSUFFICIENT_SECURITY, "unacceptable DH parameters");

    *ys = malloc(Ys.len);
    if (!*ys) return fatal(s, AD_INTERNAL_ERROR, "out of memory");
    memcpy(*ys, Ys.p, Ys.len);
    *ys_len = Ys.len;
    return transcript_add(s, msg, len);
}

/* CertificateRequest: certificate_types, supported_signature_algorithms, certificate_authorities */
static int client_read_certificate_request(tls_session *s) {
    uint8_t *msg;
    size_t len;
    if (read_handshake(s, HT_CERTIFICATE_REQUEST, &msg, &len) != 0) return -1;

    reader r = { msg + 4, len - 4, 0 };
    reader types = get_vec(&r, 1);
    reader algs  = get_vec(&r, 2);
    reader cas   = get_vec(&r, 2);
    (void)cas;
    if (r.err || r.len != 0) return fatal(s, AD_DECODE_ERROR, "malformed CertificateRequest");

    int rsa_ok = 0, sha256_ok = 0;
    while (types.len > 0) if (get_u8(&types) == CERT_TYPE_RSA_SIGN) rsa_ok = 1;
    while (algs.len >= 2) if (get_u16(&algs) == (HASH_SHA256 << 8 | SIG_RSA)) sha256_ok = 1;
    if (!rsa_ok || !sha256_ok)
        return fatal(s, AD_HANDSHAKE_FAILURE, "server does not accept RSA / SHA-256 client certificates");
    return transcript_add(s, msg, len);
}

static int send_certificate_verify(tls_session *s) {
    // signature over every handshake message so far: proves we own the client certificate's key
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (!rsa_sign_sha256(s->own_key, s->transcript, s->transcript_len, &sig, &sig_len))
        return fatal(s, AD_INTERNAL_ERROR, "cannot sign CertificateVerify");
    wbuf body = {0};
    put_u8(&body, HASH_SHA256);
    put_u8(&body, SIG_RSA);
    put_vec16(&body, sig, sig_len);
    int rc = send_handshake(s, HT_CERTIFICATE_VERIFY, &body);
    wb_free(&body);
    free(sig);
    return rc;
}

static int client_handshake(tls_session *s) {
    EVP_PKEY *dh_key = NULL;
    uint8_t *yc = NULL, *ys = NULL, *pre_master = NULL;
    size_t yc_len = 0, ys_len = 0, pre_master_len = 0;
    int cert_requested = 0, rc = -1;
    unsigned next;

    if (client_send_hello(s) != 0) goto done;
    if (client_read_server_hello(s) != 0) goto done;
    if (read_certificate(s) != 0) goto done;
    if (client_read_server_key_exchange(s, &dh_key, &yc, &yc_len, &ys, &ys_len) != 0) goto done;

    if (peek_handshake_type(s, &next) != 0) goto done;                     // CertificateRequest is optional
    if (next == HT_CERTIFICATE_REQUEST) {
        if (client_read_certificate_request(s) != 0) goto done;
        cert_requested = 1;
    }
    {
        uint8_t *msg; size_t len;
        if (read_handshake(s, HT_SERVER_HELLO_DONE, &msg, &len) != 0) goto done;
        if (len != 4) { fatal(s, AD_DECODE_ERROR, "ServerHelloDone must be empty"); goto done; }
        if (transcript_add(s, msg, len) != 0) goto done;
    }

    if (cert_requested && send_certificate(s) != 0) goto done;

    {   // ClientKeyExchange: our DH public value Yc
        wbuf body = {0};
        put_vec16(&body, yc, yc_len);
        int r = send_handshake(s, HT_CLIENT_KEY_EXCHANGE, &body);
        wb_free(&body);
        if (r != 0) goto done;
    }

    // pre_master_secret = Ys ^ x mod p
    if (!dh_derive(dh_key, ys, ys_len, &pre_master, &pre_master_len)) {
        fatal(s, AD_ILLEGAL_PARAMETER, "DH key agreement failed");
        goto done;
    }
    if (derive_keys(s, pre_master, pre_master_len) != 0) { fatal(s, AD_INTERNAL_ERROR, "key derivation failed"); goto done; }

    if (cert_requested && send_certificate_verify(s) != 0) goto done;
    if (send_change_cipher_spec(s) != 0) goto done;
    if (send_finished(s) != 0) goto done;
    if (read_change_cipher_spec(s) != 0) goto done;
    if (read_finished(s) != 0) goto done;
    rc = 0;

done:
    if (pre_master) { OPENSSL_cleanse(pre_master, pre_master_len); free(pre_master); }
    free(yc);
    free(ys);
    EVP_PKEY_free(dh_key);
    return rc;
}


/* ================================================================== */
/*  SERVER side                                                         */
/* ================================================================== */
static int server_read_client_hello(tls_session *s) {
    uint8_t *msg;
    size_t len;
    if (read_handshake(s, HT_CLIENT_HELLO, &msg, &len) != 0) return -1;

    reader r = { msg + 4, len - 4, 0 };
    unsigned major = get_u8(&r), minor = get_u8(&r);
    const uint8_t *random = get_bytes(&r, TLS_RANDOM_LEN);
    reader sid = get_vec(&r, 1);
    reader suites = get_vec(&r, 2);
    reader comps = get_vec(&r, 1);
    if (r.err || sid.len > 32 || suites.len % 2 != 0) return fatal(s, AD_DECODE_ERROR, "malformed ClientHello");
    if (major != TLS_VERSION_MAJOR || minor < TLS_VERSION_MINOR)
        return fatal(s, AD_PROTOCOL_VERSION, "client does not support TLS 1.2");
    memcpy(s->client_random, random, TLS_RANDOM_LEN);

    int suite_ok = 0, null_comp = 0, sha256_ok = 0;
    while (suites.len >= 2) {
        unsigned cs = get_u16(&suites);
        if (cs == TLS_CIPHER_SUITE_ID) suite_ok = 1;
        if (cs == SCSV_EMPTY_RENEGOTIATION) s->secure_renegotiation = 1;
    }
    while (comps.len > 0) if (get_u8(&comps) == 0) null_comp = 1;

    if (r.len > 0) {                                                        // extensions
        reader exts = get_vec(&r, 2);
        while (!exts.err && exts.len > 0) {
            unsigned type = get_u16(&exts);
            reader data = get_vec(&exts, 2);
            if (exts.err) break;
            if (type == EXT_RENEGOTIATION_INFO) {
                s->secure_renegotiation = 1;
            } else if (type == EXT_SIGNATURE_ALGORITHMS) {
                reader algs = get_vec(&data, 2);
                while (algs.len >= 2) if (get_u16(&algs) == (HASH_SHA256 << 8 | SIG_RSA)) sha256_ok = 1;
            }
            // every other extension is ignored (we simply do not echo it back)
        }
        if (exts.err) return fatal(s, AD_DECODE_ERROR, "malformed ClientHello extensions");
    }

    if (!suite_ok)  return fatal(s, AD_HANDSHAKE_FAILURE, "client does not offer " TLS_CIPHER_SUITE_NAME);
    if (!null_comp) return fatal(s, AD_ILLEGAL_PARAMETER, "client does not offer null compression");
    if (!sha256_ok) return fatal(s, AD_HANDSHAKE_FAILURE, "client does not accept rsa_pkcs1_sha256 signatures");
    LOG(s, "  ** client offers TLS 1.2 and %s\n", TLS_CIPHER_SUITE_NAME);
    return transcript_add(s, msg, len);
}

static int server_send_hello(tls_session *s) {
    if (RAND_bytes(s->server_random, TLS_RANDOM_LEN) != 1) return -1;
    wbuf body = {0};
    put_u8(&body, TLS_VERSION_MAJOR);
    put_u8(&body, TLS_VERSION_MINOR);
    put_bytes(&body, s->server_random, TLS_RANDOM_LEN);
    put_u8(&body, 0);                                                     // session_id: empty (not resumable)
    put_u16(&body, TLS_CIPHER_SUITE_ID);
    put_u8(&body, 0);                                                     // null compression
    if (s->secure_renegotiation) {                                        // RFC 5746: empty renegotiation_info
        wbuf ext = {0};
        put_u16(&ext, EXT_RENEGOTIATION_INFO);
        put_u16(&ext, 1);
        put_u8(&ext, 0);
        put_vec16(&body, ext.d, ext.len);
        wb_free(&ext);
    }
    int rc = send_handshake(s, HT_SERVER_HELLO, &body);
    wb_free(&body);
    return rc;
}

static int server_send_key_exchange(tls_session *s, EVP_PKEY **dh_key) {
    dh_wire_params dh;
    *dh_key = dh_server_keygen(&dh);
    if (!*dh_key) return fatal(s, AD_INTERNAL_ERROR, "DH key generation failed");

    wbuf params = {0}, signed_data = {0}, body = {0};
    put_vec16(&params, dh.p, dh.p_len);                                   // dh_p
    put_vec16(&params, dh.g, dh.g_len);                                   // dh_g
    put_vec16(&params, dh.pub, dh.pub_len);                               // dh_Ys
    put_bytes(&signed_data, s->client_random, TLS_RANDOM_LEN);
    put_bytes(&signed_data, s->server_random, TLS_RANDOM_LEN);
    put_bytes(&signed_data, params.d, params.len);

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    int rc = -1;
    if (!signed_data.err && rsa_sign_sha256(s->own_key, signed_data.d, signed_data.len, &sig, &sig_len)) {
        put_bytes(&body, params.d, params.len);
        put_u8(&body, HASH_SHA256);
        put_u8(&body, SIG_RSA);
        put_vec16(&body, sig, sig_len);
        rc = send_handshake(s, HT_SERVER_KEY_EXCHANGE, &body);
    } else {
        fatal(s, AD_INTERNAL_ERROR, "cannot sign ServerKeyExchange");
    }
    free(sig);
    wb_free(&params); wb_free(&signed_data); wb_free(&body);
    dh_wire_params_free(&dh);
    return rc;
}

static int server_send_certificate_request(tls_session *s) {
    wbuf body = {0}, cas = {0};
    unsigned char *dn = NULL;
    int dn_len = i2d_X509_NAME(X509_get_subject_name(s->ca_cert), &dn);    // "send a cert issued by this CA"
    if (dn_len <= 0) return fatal(s, AD_INTERNAL_ERROR, "cannot encode CA name");
    put_vec16(&cas, dn, (size_t)dn_len);
    OPENSSL_free(dn);

    put_u8(&body, 1);  put_u8(&body, CERT_TYPE_RSA_SIGN);                 // certificate_types
    put_u16(&body, 2); put_u8(&body, HASH_SHA256); put_u8(&body, SIG_RSA);// supported_signature_algorithms
    put_vec16(&body, cas.d, cas.len);                                     // certificate_authorities
    int rc = send_handshake(s, HT_CERTIFICATE_REQUEST, &body);
    wb_free(&body); wb_free(&cas);
    return rc;
}

static int server_read_certificate_verify(tls_session *s) {
    uint8_t *msg;
    size_t len;
    if (read_handshake(s, HT_CERTIFICATE_VERIFY, &msg, &len) != 0) return -1;

    reader r = { msg + 4, len - 4, 0 };
    unsigned hash = get_u8(&r), sig_alg = get_u8(&r);
    reader sig = get_vec(&r, 2);
    if (r.err || r.len != 0) return fatal(s, AD_DECODE_ERROR, "malformed CertificateVerify");
    if (hash != HASH_SHA256 || sig_alg != SIG_RSA)
        return fatal(s, AD_ILLEGAL_PARAMETER, "CertificateVerify not signed with rsa_pkcs1_sha256");

    // the transcript currently ends right before this message, which is exactly what was signed
    EVP_PKEY *client_pub = X509_get0_pubkey(s->peer_cert);
    if (!client_pub || !rsa_verify_sha256(client_pub, s->transcript, s->transcript_len, sig.p, sig.len))
        return fatal(s, AD_DECRYPT_ERROR, "CertificateVerify signature is invalid");
    LOG(s, "  ** client proved ownership of its certificate key\n");
    return transcript_add(s, msg, len);
}

static int server_handshake(tls_session *s) {
    EVP_PKEY *dh_key = NULL;
    uint8_t *pre_master = NULL;
    size_t pre_master_len = 0;
    int rc = -1;

    if (server_read_client_hello(s) != 0) goto done;
    if (server_send_hello(s) != 0) goto done;
    if (send_certificate(s) != 0) goto done;
    if (server_send_key_exchange(s, &dh_key) != 0) goto done;
    if (server_send_certificate_request(s) != 0) goto done;
    {
        wbuf empty = {0};
        if (send_handshake(s, HT_SERVER_HELLO_DONE, &empty) != 0) goto done;
    }

    if (read_certificate(s) != 0) goto done;                               // client certificate (mandatory)

    {   // ClientKeyExchange -> pre_master_secret = Yc ^ y mod p
        uint8_t *msg; size_t len;
        if (read_handshake(s, HT_CLIENT_KEY_EXCHANGE, &msg, &len) != 0) goto done;
        reader r = { msg + 4, len - 4, 0 };
        reader yc = get_vec(&r, 2);
        if (r.err || r.len != 0 || yc.len == 0) { fatal(s, AD_DECODE_ERROR, "malformed ClientKeyExchange"); goto done; }
        if (!dh_derive(dh_key, yc.p, yc.len, &pre_master, &pre_master_len)) {
            fatal(s, AD_ILLEGAL_PARAMETER, "DH key agreement failed");
            goto done;
        }
        if (transcript_add(s, msg, len) != 0) goto done;
    }
    if (derive_keys(s, pre_master, pre_master_len) != 0) { fatal(s, AD_INTERNAL_ERROR, "key derivation failed"); goto done; }

    if (server_read_certificate_verify(s) != 0) goto done;
    if (read_change_cipher_spec(s) != 0) goto done;
    if (read_finished(s) != 0) goto done;
    if (send_change_cipher_spec(s) != 0) goto done;
    if (send_finished(s) != 0) goto done;
    rc = 0;

done:
    if (pre_master) { OPENSSL_cleanse(pre_master, pre_master_len); free(pre_master); }
    EVP_PKEY_free(dh_key);
    return rc;
}


/* ================================================================== */
/*  Public API                                                          */
/* ================================================================== */
void tls_init(tls_session *s, socket_t sock, tls_role role, X509 *own_cert, EVP_PKEY *own_key,
              X509 *ca_cert, const char *expected_peer_ip) {
    memset(s, 0, sizeof(*s));
    s->sock = sock;
    s->role = role;
    s->own_cert = own_cert;
    s->own_key = own_key;
    s->ca_cert = ca_cert;
    s->expected_peer_ip = expected_peer_ip;
    s->verbose = 1;
}

int tls_handshake(tls_session *s) {
    LOG(s, "\n- Starting TLS 1.2 handshake as %s\n", s->role == TLS_ROLE_CLIENT ? "client" : "server");
    int rc = s->role == TLS_ROLE_CLIENT ? client_handshake(s) : server_handshake(s);
    if (rc == 0) {
        s->established = 1;
        LOG(s, "- Handshake complete: TLS 1.2, %s, mutual authentication\n\n", TLS_CIPHER_SUITE_NAME);
    }
    return rc;
}

int tls_write(tls_session *s, const void *data, size_t len) {
    if (!s->established || len == 0) return s->established ? 0 : -1;
    return send_record(s, CT_APPLICATION_DATA, data, len);
}

int tls_read(tls_session *s, void *buf, size_t buf_size) {
    if (!s->established || s->peer_closed) return s->peer_closed ? 0 : -1;

    while (s->app_pending_len == 0) {
        uint8_t type, *data;
        size_t len;
        if (recv_record(s, &type, &data, &len) != 0) return -1;
        if (type == CT_APPLICATION_DATA) {
            s->app_pending = data;
            s->app_pending_len = len;
        } else if (type == CT_ALERT) {
            int a = handle_alert(s, data, len);
            if (a == 1) return 0;                                         // close_notify
            if (a < 0) return -1;
        } else if (type == CT_HANDSHAKE && s->role == TLS_ROLE_CLIENT && len == 4 && data[0] == HT_HELLO_REQUEST) {
            send_alert(s, ALERT_WARNING, AD_NO_RENEGOTIATION);            // we never renegotiate
        } else {
            return fatal(s, AD_UNEXPECTED_MESSAGE, "unexpected record after handshake");
        }
    }

    size_t n = s->app_pending_len < buf_size ? s->app_pending_len : buf_size;
    memcpy(buf, s->app_pending, n);
    s->app_pending += n;
    s->app_pending_len -= n;
    return (int)n;
}

void tls_close(tls_session *s) {
    if (s->established) send_alert(s, ALERT_WARNING, AD_CLOSE_NOTIFY);
    s->established = 0;
}

void tls_free(tls_session *s) {
    X509_free(s->peer_cert);
    free(s->transcript);
    free(s->hs_buf);
    OPENSSL_cleanse(s, sizeof(*s));                                       // wipe keys and secrets
}

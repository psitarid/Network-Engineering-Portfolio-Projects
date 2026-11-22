/* tls.h
 *
 * A from-scratch TLS 1.2 implementation of one cipher suite:
 *
 *     TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   (0x00,0x6B)   "DHE-RSA-AES256-SHA256"
 *
 * with mutual (client + server) certificate authentication.
 * It speaks the real TLS 1.2 wire format (RFC 5246), so it interoperates with
 * standard implementations such as `openssl s_server` / `openssl s_client`.
 *
 * Usage:
 *     tls_session s;
 *     tls_init(&s, sock, TLS_ROLE_CLIENT, my_cert, my_key, ca_cert, "127.0.0.1");
 *     if (tls_handshake(&s) == 0) {
 *         tls_write(&s, data, len);
 *         n = tls_read(&s, buf, sizeof(buf));
 *         tls_close(&s);            // sends close_notify
 *     }
 *     tls_free(&s);
 */
#ifndef TLS_H
#define TLS_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "net.h"
#include "tls_crypto.h"

#define TLS_CIPHER_SUITE_ID    0x006B
#define TLS_CIPHER_SUITE_NAME  "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
#define TLS_MAX_PLAINTEXT      16384           /* 2^14, maximum record payload */

typedef enum { TLS_ROLE_CLIENT, TLS_ROLE_SERVER } tls_role;

typedef struct {
    /* configuration */
    socket_t   sock;
    tls_role   role;
    X509      *own_cert;            /* our certificate (borrowed)                     */
    EVP_PKEY  *own_key;             /* our RSA private key (borrowed)                 */
    X509      *ca_cert;             /* trust anchor for the peer certificate          */
    const char *expected_peer_ip;   /* client only: IP that must be in the server SAN */
    int        verbose;             /* print each handshake step                      */

    /* handshake state */
    uint8_t    client_random[TLS_RANDOM_LEN];
    uint8_t    server_random[TLS_RANDOM_LEN];
    uint8_t    master_secret[TLS_MASTER_LEN];
    int        secure_renegotiation;  /* peer signalled RFC 5746 support */
    X509      *peer_cert;             /* owned */

    /* transcript of all handshake messages (for CertificateVerify and Finished) */
    uint8_t   *transcript;
    size_t     transcript_len, transcript_cap;

    /* buffered handshake bytes not yet parsed into messages */
    uint8_t   *hs_buf;
    size_t     hs_len, hs_cap;

    /* record protection, enabled after ChangeCipherSpec in each direction */
    tls_cipher_state write_state, read_state;
    int        write_encrypted, read_encrypted;

    int        established;
    int        peer_closed;

    /* one incoming record (header + max ciphertext), and unread application data inside it */
    uint8_t    rec_buf[5 + TLS_MAX_PLAINTEXT + 2048];
    uint8_t   *app_pending;
    size_t     app_pending_len;
    size_t     hs_consume;          /* bytes of hs_buf to drop before the next message */
} tls_session;

void tls_init(tls_session *s, socket_t sock, tls_role role, X509 *own_cert, EVP_PKEY *own_key,
              X509 *ca_cert, const char *expected_peer_ip);

/* Run the full handshake. Returns 0 on success, -1 on failure (an alert is sent to the peer). */
int  tls_handshake(tls_session *s);

/* Send application data (split into records of at most 16 KB). Returns 0 on success. */
int  tls_write(tls_session *s, const void *data, size_t len);

/* Receive one record of application data.
 * Returns the number of bytes, 0 if the peer closed the session (close_notify), -1 on error. */
int  tls_read(tls_session *s, void *buf, size_t buf_size);

/* Send close_notify. */
void tls_close(tls_session *s);

/* Free all memory and wipe the key material. Does not close the socket. */
void tls_free(tls_session *s);

#endif /* TLS_H */

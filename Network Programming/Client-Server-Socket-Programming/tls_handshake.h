#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

// SSL connection wrapper structure
typedef struct {
    SOCKET socket;
    SSL *ssl;
    SSL_CTX *ctx;
} ssl_connection_t;


// this function associates my SSL context with the specific socket connection
ssl_connection_t* create_ssl_connection(SSL_CTX *ctx, SOCKET socket) {
    printf("[...] Creating SSL connection object...\n");

    ssl_connection_t *conn = malloc(sizeof(ssl_connection_t));
    if (!conn) {
        printf("ERROR: Failed to allocate memory for SSL connection\n");
        return NULL;
    }

    conn->socket = socket;
    conn->ctx = ctx;

    //Create new SSL object from context
    //This creates per-connection SSL state machine

    conn->ssl = SSL_new(ctx);
    if(!conn->ssl) {
        printf("ERROR: Failed to create SSL object\n");
        free(conn);
        return NULL;
    }

    printf("[ + ] SSL object created successfully\n\n");

    // Associate SSL object with the socket file descriptor
    // This tells OpenSSL to use you socket for network I/O

    if (SSL_set_fd(conn->ssl, socket) != 1) {
        printf("ERROR: Failed to associate SSL with socket\n");
        ERR_print_errors_fp(stderr);
        SSL_free(conn->ssl);
        free(conn);
        return NULL;
    }

    printf("[ + ] SSL object associated successfully with socket (fd: %d)\n\n", socket);
    printf("[ + ] SSL connection object ready for handshake\n\n");

    return conn;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Print detailed information about the completed handshake
void print_handshake_info(ssl_connection_t *conn) {

    // Connection state
    int state = SSL_get_state(conn->ssl);
    printf("[ + ] %s\n\n", SSL_state_string_long(conn->ssl));
    
    const SSL_CIPHER *cipher = SSL_get_current_cipher(conn->ssl);
    
    // Negotiated cipher suite
    const char *cipher_suite_name = SSL_get_cipher(conn->ssl);
    printf("Negotiated Cipher Suite: %s\n\n", cipher_suite_name ? cipher_suite_name : "Unknown");

    // Protocol version
    const char *version = SSL_get_version(conn->ssl);
    printf("* TLS Protocol Version: %s\n", version ? version : "Unknown");

    
    // Key exchange algorithm
    const char *kx_name = "Unknown";
    
    if (strcmp(version, "TLSv1.3") == 0) {
        printf("* Key Exchange Algorithm: ECDHE (TLS 1.3 default)\n");
    } else if (strcmp(version, "TLSv1.2") == 0) {
        int kx_nid = SSL_CIPHER_get_kx_nid(cipher);
        kx_name = kx_nid ? OBJ_nid2sn(kx_nid) : "Unknown";
        kx_name += 2; // skip "Kx"
        
        printf("* Key Exchange Algorithm: %s\n", kx_name);
    }

    // Authentication algorithm
    if(strcmp(version, "TLSv1.3") == 0) {
        printf("* Authentication: RSA (from certificates)\n");
    } else if (strcmp(version, "TLSv1.2") == 0) {
        int auth_nid = SSL_CIPHER_get_auth_nid(cipher);
        const char *auth_name = auth_nid ? OBJ_nid2sn(auth_nid) : "Unknown";
        auth_name += 4; // skip "Au"
        printf("* Authentication: %s\n", auth_name);
    }

    // Bulk encryption algorithm
    int enc_nid = SSL_CIPHER_get_cipher_nid(cipher);
    const char *enc_name_raw = enc_nid ? OBJ_nid2sn(enc_nid) : "Unknown";
    enc_name_raw += 3; // skip "id-"

    // Convert to uppercase
    char enc_name[64];
    snprintf(enc_name, sizeof(enc_name), "%s", enc_name_raw); 
    for (char *p = enc_name; *p; ++p) {
        *p = toupper((unsigned char)*p);
    }
    
    printf("* Bulk Encryption: %s\n", enc_name);

    // HMAC algorithm
    const EVP_MD *md = SSL_CIPHER_get_handshake_digest(cipher);
    const char *hmac_name = md ? EVP_MD_name(md) : "Unknown";
    // hmac_name += 3; // skip "id-"    

    printf("* Hashing: %s\n\n", hmac_name);

    // Session information
    SSL_SESSION *session = SSL_get_session(conn->ssl);
    if (session) {
        printf("[ + ] Session established successfully\n");
    } 
    else {
        printf("[ - ] No session information available\n");
    }

    // Check if session is resumable
    if(SSL_SESSION_is_resumable(session)) {
        printf("[ + ] Session is resumable\n");
    }
    else {
        printf("[ - ] Session is not resumable\n");
    }

    // check for Perfect Forward Secrecy (PFS)
    if(strcmp(version, "TLSv1.3") == 0) {
        printf("[ + ] Perfect Forward Secrecy (PFS) is enabled because of TLSv1.3\n");
        printf("      Even if private keys are compromised later, past communications remain secure.\n\n");
    }
    else if(strcmp(version, "TLSv1.2") == 0) {
        if(strstr(kx_name, "DHE") || strstr(kx_name, "ECDHE")) {
            printf("[ + ] Perfect Forward Secrecy (PFS) is enabled because of %s\n", kx_name);
            printf("      Even if private keys are compromised later, past communications remain secure.\n\n");
        } 
        else {
            printf("[ - ] Warning: Perfect Forward Secrecy (PFS) is NOT enabled because it is not supported by %s!\n\n", kx_name);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Display information about the peer's certificate
void display_peer_cert(ssl_connection_t *conn) {

    X509 *peer_cert = SSL_get1_peer_certificate(conn->ssl);
    if (!peer_cert) {
        printf("[ - ] No peer certificate received\n");
        return;
    }

    char country [256];
    char cn[256];
    char org[256];

    // Common Name (CN)
    int len = X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), NID_commonName, cn, sizeof(cn));
    printf("* Common Name (CN): %.*s\n\n", len, cn);

    // Organization (O)
    len = X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), NID_organizationName, org, sizeof(org));
    printf("* Organization (O): %.*s\n\n", len, org);

    // Country (C)
    len = X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), NID_countryName, country, sizeof(country));
    printf("* Country (C): %.*s\n\n", len, country);

    // Not Before
    const ASN1_TIME *notBefore = X509_get0_notBefore(peer_cert);
    const ASN1_TIME *notAfter  = X509_get0_notAfter(peer_cert);
    
    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, notBefore);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    printf("* Not Before: %.*s\n\n", (int)bptr->length, bptr->data);
    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, notAfter);
    BIO_get_mem_ptr(bio, &bptr);
    printf("* Not After:  %.*s\n\n\n", (int)bptr->length, bptr->data);
    BIO_free(bio);
    
    // Certificate subject (who the certificate is issued to)
    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(peer_cert), subject, sizeof(subject));

    // Certificate issuer (who issued the certificate)
    char issuer [256];
    X509_NAME_oneline(X509_get_issuer_name(peer_cert), issuer, sizeof(issuer));

    // Check if self-signed
    if (strcmp(subject, issuer) == 0) {
        printf("[ i ] This is a self-signed certificate.\n\n");
    }
    else {
        printf("[ i ] This certificate is issued by a CA.\n\n");
    }

    X509_free(peer_cert);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Test basic SSL communication to verify the connection works
int test_ssl_communication(ssl_connection_t *conn, int is_server) {

    if (is_server) {
        printf("[...] Sending test message to client...\n");
        
        // Send a test message to the client
        const char *test_msg = "Hello from the SSL server!";
        int bytes_sent = SSL_write(conn->ssl, test_msg, strlen(test_msg));

        if (bytes_sent <= 0) {
            printf("[ - ] ERROR: Failed to send test message to client\n");
            int ssl_error = SSL_get_error(conn->ssl, bytes_sent);
            printf("[ - ] SSL error: %d\n", ssl_error);
            return 0;
        }

        printf("\n      - Sent encrypted message: \"%s\" (%d bytes)\n\n", test_msg, bytes_sent);

        // Receive response from client
        char buffer[256];
        int bytes_received = SSL_read(conn->ssl, buffer, sizeof(buffer) - 1);
        if (bytes_received <= 0) {
            printf("[ - ] ERROR: Failed to receive response from client\n");
            int ssl_error = SSL_get_error(conn->ssl, bytes_received);
            printf("[ - ] SSL error: %d\n", ssl_error);
            return 0;
        }

        buffer[bytes_received] = '\0';  // Null-terminate the received data
        printf("      - Received encrypted response: \"%s\" (%d bytes)\n\n", buffer, bytes_received);
    }
    else {
        
        printf("[...] Receiving test message from server...\n");

        // Receive a test message from the server
        char buffer[256];
        int bytes_received = SSL_read(conn->ssl, buffer, sizeof(buffer) - 1);
        if (bytes_received <= 0) {
            printf("[ - ] ERROR: Failed to receive test message from server\n");
            int ssl_error = SSL_get_error(conn->ssl, bytes_received);
            printf("[ - ] SSL error: %d\n", ssl_error);
            return 0;
        }

        buffer[bytes_received] = '\0';  // Null-terminate the received data
        printf("\n      - Received encrypted message: \"%s\" (%d bytes)\n\n", buffer, bytes_received);

        // Send response back to server
        const char *response_msg = "Hello from the SSL client!";
        int bytes_sent = SSL_write(conn->ssl, response_msg, strlen(response_msg));

        if (bytes_sent <= 0) {
            printf("[ - ] ERROR: Failed to send response to server\n");
            int ssl_error = SSL_get_error(conn->ssl, bytes_sent);
            printf("[ - ] SSL error: %d\n", ssl_error);
            return 0;
        }

        printf("      - Sent encrypted response: \"%s\" (%d bytes)\n\n", response_msg, bytes_sent);
    }

    printf("[ + ] SSL communication test completed successfully\n\n");

    return 1;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void cleanup_ssl_connection(ssl_connection_t *conn) {
    printf("\n[...] Cleaning up SSL connection...\n");
    
    if (!conn) {
        exit(1);
    }

    if (conn->ssl) {
        
        // Perform two-phase shutdown
        int shutdown_result = SSL_shutdown(conn->ssl); // Send "close notify" alert to peer
        
        // First shutdown phase
        if (shutdown_result == 0) {
            // First phase complete, perform second phase
            printf("\n      [ + ] First shutdown phase complete, performing second phase...\n\n");
        }
        else{
            int ssl_error = SSL_get_error(conn->ssl, shutdown_result);
            printf("[ - ] SSL_shutdown error during first phase: %d\n", ssl_error);
            exit(1);
        }
        
        shutdown_result = SSL_shutdown(conn->ssl);
        
        // Second shutdown phase
        if (shutdown_result < 0) {
            int ssl_error = SSL_get_error(conn->ssl, shutdown_result);
            printf("[ - ] SSL_shutdown error during second phase: %d\n", ssl_error);
            exit(1);
        }
        else if (shutdown_result == 1) {
            printf("      [ + ] Second shutdown phase complete, received close notify from peer.\n\n");
        }

        printf("[ + ] SSL connection shutdown completed successfully\n");

        SSL_free(conn->ssl);

    }
    // Note: Do not close the socket here; it should be closed by the caller
    free(conn);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#endif // TLS_HANDSHAKE_H
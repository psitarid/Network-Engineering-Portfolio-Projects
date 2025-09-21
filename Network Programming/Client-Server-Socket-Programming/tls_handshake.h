#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
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

    printf("[ + ] SSL object created successfully\n");

    // Associate SSL object with the socket file descriptor
    // This tells OpenSSL to use you socket for network I/O

    if (SSL_set_fd(conn->ssl, socket) != 1) {
        printf("ERROR: Failed to associate SSL with socket\n");
        ERR_print_errors_fp(stderr);
        SSL_free(conn->ssl);
        free(conn);
        return NULL;
    }

    printf("[ + ] SSL object associated successfully with socket (fd: %d)\n", socket);
    printf("[ + ] SSL connection object ready for handshake\n\n");

    return conn;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Print detailed information about the completed handshake
void print_handshake_info(ssl_connection_t *conn) {
    printf("--- Handshake Information:\n");

    // Protocol version
    const char *version = SSL_get_version(conn->ssl);
    printf("- TLS Protocol Version: %s\n", version ? version : "Unknown");

    // Negotiated cipher suite
    const char *cipher = SSL_get_cipher(conn->ssl);
    printf("- Negotiated Cipher Suite: %s\n", cipher ? cipher : "Unknown");

    // Verify this matches your expected cipher suite
    if (cipher && strstr(cipher, "TLS_AES_256_GCM_SHA384")) {
        printf("[ + ] Cipher suite matches expected value: %s\n", cipher);

    } else {
        printf("[ - ] Warning: Cipher suite does not match expected value!\n");
        printf("    Expected: TLS_AES_256_GCM_SHA384\n");
        printf("    Got: %s\n", cipher ? cipher : "Unknown");
    }

    // Connection state
    int state = SSL_get_state(conn->ssl);
    printf("- SSL Connection State: %s\n", SSL_state_string_long(conn->ssl));


    // Security level information
    int security_bits = SSL_get_cipher_bits(conn->ssl, NULL);
    printf("- Security Level: %d bits\n", security_bits);

    // Session information
    SSL_SESSION *session = SSL_get_session(conn->ssl);
    if (session) {
        printf("[ + ] Session established successfully\n");
    } else {
        printf("[ - ] No session information available\n");
    }

    // Check if session is resumable
    if(SSL_SESSION_is_resumable(session)) {
        printf(" [ + ] Session is resumable\n");
    }
    else {
        printf(" [ - ] Session is not resumable\n");
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Verify that the negotiated cipher suite meets your requirements

void verify_cipher_suite(ssl_connection_t *conn) {
    printf("\n[...] Verifying negotiated cipher suite...\n");

    const char *cipher_name = SSL_get_cipher(conn->ssl);
    const SSL_CIPHER *cipher = SSL_get_current_cipher(conn->ssl);

    if (!cipher) {
        printf("ERROR: No cipher suite negotiated\n");
        exit(1);
    }

    //Get detailed cipher information
    char cipher_description[256];
    SSL_CIPHER_description(cipher, cipher_description, sizeof(cipher_description));
    printf("- Cipher Description: %s\n", cipher_description);

    // Verify key exchange algorithm
    const char *kx_name = SSL_CIPHER_get_kx_nid(cipher) ? "DHE" : "Unknown";
    printf("- Key Exchange: %s\n", kx_name);

    // Verify authentication algorithm
    const char *auth_name = SSL_CIPHER_get_auth_nid(cipher) ? "RSA" : "Unknown";
    printf("- Authentication: %s\n", auth_name);

    // Verify encryption algorithm and key size
    int alg_bits, strength_bits;
    strength_bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
    printf("- Encryption: %d-bit algorithm, %d-bit effective strength\n", alg_bits, strength_bits);

    // check for Perfect Forward Secrecy (PFS)
    if(strstr(cipher_name, "DHE") || strstr(cipher_name, "ECDHE")) {
        printf("[ + ] Perfect Forward Secrecy (PFS) is enabled with %s\n", cipher_name);
        printf("  * Even if private keys are compromised later, past communications remain secure\n");
    } else {
        printf("[ - ] Warning: Perfect Forward Secrecy (PFS) is NOT enabled!\n");
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Display information about the peer's certificate
void display_peer_cert(ssl_connection_t *conn) {
    printf("\n---- Peer Certificate Information:\n");

    X509 *peer_cert = SSL_get1_peer_certificate(conn->ssl);
    if (!peer_cert) {
        printf("[ - ] No peer certificate received\n");
        return;
    }

    // Certificate subject (who the certificate is issued to)
    char subject[512];
    X509_NAME_oneline(X509_get_subject_name(peer_cert), subject, sizeof(subject));
    printf("- Certificate Subject: %s\n", subject);

    // Certificate issuer (who issued the certificate)
    char issuer [512];
    X509_NAME_oneline(X509_get_issuer_name(peer_cert), issuer, sizeof(issuer));
    printf("- Certificate Issuer: %s\n", issuer);

    // Check if self-signed
    if (strcmp(subject, issuer) == 0) {
        printf("  * Note: This is a self-signed certificate\n");
    }
    else {
        printf("  * Note: This certificate is issued by a CA\n");
    }

    // Check certificate validity
    if (check_cert_validity(peer_cert) == 1) {
        printf("[ + ] Certificate is valid\n");
    } else {
        printf("[ - ] Certificate is NOT valid\n");
    }

    X509_free(peer_cert);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Test basic SSL communication to verify the connection works
int test_ssl_communication(ssl_connection_t *conn, int is_server) {
    printf("\n---- SSL communication Test\n");

    if (is_server) {
        printf("--- Testing as Server ---\n");
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

        printf("- Sent encrypted message: \"%s\" (%d bytes)\n", test_msg, bytes_sent);

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
        printf("- Received encrypted response: \"%s\" (%d bytes)\n", buffer, bytes_received);
    }
    else {
        printf("--- Testing as Client ---\n");
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
        printf("- Received encrypted message: \"%s\" (%d bytes)\n", buffer, bytes_received);

        // Send response back to server
        const char *response_msg = "Hello from the SSL client!";
        int bytes_sent = SSL_write(conn->ssl, response_msg, strlen(response_msg));

        if (bytes_sent <= 0) {
            printf("[ - ] ERROR: Failed to send response to server\n");
            int ssl_error = SSL_get_error(conn->ssl, bytes_sent);
            printf("[ - ] SSL error: %d\n", ssl_error);
            return 0;
        }

        printf("- Sent encrypted response: \"%s\" (%d bytes)\n", response_msg, bytes_sent);
    }

    printf("[ + ] SSL communication test completed successfully\n");
    printf("- Data was encrypted with AES-256-CBC and authenticated with SHA-256\n");

    return 1;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void cleanup_ssl_connection(ssl_connection_t *conn) {
    printf("\n[...] Cleaning up SSL connection...\n");
    
    if (!conn) {
        exit(1);
    }

    if (conn->ssl) {
        printf("[...] Shutting down SSL connection...\n");
        
        // Perform two-phase shutdown
        int shutdown_result = SSL_shutdown(conn->ssl); // Send "close notify" alert to peer
        
        // First shutdown phase
        if (shutdown_result == 0) {
            // First phase complete, perform second phase
            printf("- First shutdown phase complete, performing second phase...\n");
            shutdown_result = SSL_shutdown(conn->ssl);
        }
        
        // Second shutdown phase
        if (shutdown_result < 0) {
            int ssl_error = SSL_get_error(conn->ssl, shutdown_result);
            printf("[ - ] SSL_shutdown error during second phase: %d\n", ssl_error);
        }
        else if (shutdown_result == 1) {
            printf("[ + ] SSL connection shutdown completed successfully\n");
        }

        SSL_free(conn->ssl);
        printf("- SSL object freed\n");

    }
    // Note: Do not close the socket here; it should be closed by the caller
    free(conn);
    printf("[ + ] SSL connection cleaned up successfully\n");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#endif // TLS_HANDSHAKE_H
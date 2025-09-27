#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>   
#include "../common.h"
#include "../tls_handshake.h"
#include <openssl/ssl.h>        // SSL_CTX, SSL, SSL_METHOD, SSL functions
#include <openssl/err.h>        // Error printing: ERR_print_errors_fp, print_ssl_error
#include <openssl/dh.h>         // DH, DH_new, DH_set0_pqg, SSL_CTX_set_tmp_dh
#include <openssl/bn.h>         // BIGNUM, BN_new, BN_hex2bn, BN_set_word
#include <openssl/x509.h>       // X509, certificate functions (if you use cert checks)
#include <openssl/x509_vfy.h>   // X509_STORE_CTX, verification callbacks
#include <openssl/evp.h>        // EVP_PKEY (for key checks)

void connect_to_server(SOCKET client_socket, struct sockaddr *server_address) {
    if (connect(client_socket, server_address, sizeof(struct sockaddr)) < 0) {
        printf("Connection failed\n");
        closesocket(client_socket);
        WSACleanup();
        exit(1);
    }
    else {
        printf("[ + ] Connected to server successfully.\n\n");
    }
}

/**
 * Create and configure SSL context for client
 */
SSL_CTX* create_client_context() {
    printf("[...] Creating client SSL context...\n");
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Use TLS client method
    method = TLS_client_method();
    
    // Create new context
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        print_ssl_error("[ - ] Unable to create SSL context");
        return NULL;
    }
    
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // Set the same cipher suite preference
    const char *cipher_suites_1_2;
    const char *cipher_suites_1_3;
    
    cipher_suites_1_2 = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    cipher_suites_1_3 = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256";
    
    if(SSL_CTX_set_cipher_list(ctx, cipher_suites_1_2) != 1) {
        print_ssl_error("[ - ]Failed to set cipher list");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    if (SSL_CTX_set_ciphersuites(ctx, cipher_suites_1_3) != 1) {
        print_ssl_error("[ - ]Failed to set cipher list");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // // printf("Cipher suite set to: %s\n", cipher_list);
    // printf("      -> Key Exchange: ECDHE (automatic)\n");
    // printf("      -> Authentication: RSA (from certificates)\n");
    // printf("      -> Encryption: AES-256-GCM\n");
    // printf("      -> Hash: SHA384\n");

    // For testing with self-signed certificates, we'll disable peer verification
    // In production, you'd want to properly verify the peer certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    
    // Disable SSLv2 and SSLv3 for security
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    
    printf("[ + ] Client SSL context created successfully\n\n");
    return ctx;
}

/**
 * Configure client context with certificate and private key
 */
void configure_client_context(SSL_CTX *ctx, const char *client_cert, const char *client_key) {
    printf("[...] Configuring client context with certificates...\n");
    
    // Load client certificate into the context
    if (SSL_CTX_use_certificate_file(ctx, client_cert, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load client certificate");
        exit(1);
    }
    printf("      -> Client certificate loaded: %s\n", client_cert);

    // Load client private key into the context
    if (SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load client private key");
        exit(1);
    }
    printf("      -> Client private key loaded: %s\n", client_key);

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate public key\n");
        exit(1);
    }
    printf("      -> Private key matches certificate\n");    
    
    printf("[ + ] Client context configuration complete\n\n");
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int client_handshake(ssl_connection_t *conn) {
    
    printf("[...] Starting TLS handshake as a client...\n");

    int handshake_result = SSL_connect(conn->ssl);

    if(handshake_result <= 0) {
        int ssl_error = SSL_get_error(conn->ssl, handshake_result);
        printf("Handshake failed with error code: %d\n", ssl_error);

        switch (ssl_error) {
            case SSL_ERROR_WANT_READ:
                printf("- Handshake needs more data from client (network issue?)\n");
                break;
                
            case SSL_ERROR_WANT_WRITE:
                printf("- Handshake needs to send more data to client (network issue?)\n");
                break;
                
            case SSL_ERROR_SYSCALL: {
                int wsa_error = WSAGetLastError();
                printf("- System call error during handshake: %d\n", wsa_error);
                if (wsa_error == 0) {
                    printf("- Connection closed unexpectedly by client\n");
                }
                break;
            }
                
            case SSL_ERROR_SSL:
                printf("- SSL protocol error during handshake:\n");
                ERR_print_errors_fp(stderr);
                break;
                
            case SSL_ERROR_ZERO_RETURN:
                printf("- Connection closed cleanly during handshake\n");
                break;
                
            default:
                printf("- Unknown SSL error: %d\n", ssl_error);
                ERR_print_errors_fp(stderr);
                break;
        }
        return 0;
    }
    else {
        printf("[ + ] TLS handshake completed successfully\n");
        printf("[ + ] Secure connection established\n\n");
    
        return 1;
    }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // TCP_CLIENT_H
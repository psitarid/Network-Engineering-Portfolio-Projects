#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>   
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
    
    // Set minimum protocol version to TLS 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // Set the same cipher suite preference
    const char *cipher_list = "DHE-RSA-AES256-SHA256";
    if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1) {
        print_ssl_error("[ - ]Failed to set cipher list");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    printf("Cipher suite preference set to: %s\n", cipher_list);
    
    // For testing with self-signed certificates, we'll disable peer verification
    // In production, you'd want to properly verify the peer certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    
    // Disable SSLv2 and SSLv3 for security
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    
    printf("[ + ] Client SSL context created successfully\n");
    return ctx;
}

/**
 * Configure client context with certificate and private key
 */
void configure_client_context(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
    printf("- Configuring client context with certificates...\n");
    
    // Load client certificate into the context
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load client certificate");
        exit(1);
    }
    printf("  -> Client certificate loaded: %s\n", cert_file);
    
    // Load client private key into the context
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load client private key");
        exit(1);
    }
    printf("  -> Client private key loaded: %s\n", key_file);
    
    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate public key\n");
        exit(1);
    }
    printf("  -> Private key matches certificate\n");
    
    printf("[ + ] Client context configuration complete\n");
}

#endif // TCP_CLIENT_H
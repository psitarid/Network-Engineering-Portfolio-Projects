#ifndef SSL_SERVER_H
#define SSL_SERVER_H


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
#include "../common.h"
#include "../tls_handshake.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// check binding
void bind_socket(SOCKET listening_socket, struct sockaddr_in listening_address) {
    int bind_result = bind(listening_socket, (struct sockaddr *)&listening_address, sizeof(listening_address));
    if (bind_result == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(listening_socket);
        WSACleanup();
        exit(1);
    }
    printf("[ + ] Binding successful.\n");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// check listening status
void listen_for_client(SOCKET listening_socket) {
    int listen_status = listen(listening_socket, 5);
    if (listen_status == SOCKET_ERROR) {
        printf("Listening failed: %d\n", WSAGetLastError());
        closesocket(listening_socket);
        WSACleanup();
        exit(1);
    }
    printf("[ + ] Waiting for incoming connections...\n");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// check accepted socket
void accept_socket(SOCKET *connection_socket, struct sockaddr_in connection_address, SOCKET listening_socket){
    int client_len = sizeof(connection_address);
    *connection_socket = accept(listening_socket, (struct sockaddr *)&connection_address, &client_len);
    if (*connection_socket == INVALID_SOCKET) {
        printf("Accept failed: %d\n", WSAGetLastError());
        closesocket(listening_socket);
        WSACleanup();
        exit(1);
    }
    printf("- Connection received from %s:%d\n\n",
           inet_ntoa(connection_address.sin_addr),
           ntohs(connection_address.sin_port));
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Create and configure SSL context for server to hold all the configuration and certificates
SSL_CTX* create_server_context() {
    
    const SSL_METHOD *method = TLS_server_method();                // create new server-method instance
    SSL_CTX *ctx = SSL_CTX_new(method);                            // create new context from method

    if (!ctx) {                                                    // check for errors in context creation
        printf("Unable to create SSL context\n");
        cleanup_openssl();
        exit(1);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);            // set minimum protocol version to TLS 1.2 for security
    
    const char *cipher_list = "DHE-RSA-AES256-SHA256";             // configure the specific cipher suite(Diffie-Hellman Ephemeral key exchange, RSA authentication (using your RSA certificates), AES 256-bit encryption in CBC mode, SHA-256 for MAC (message authentication))
    
    if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1) {          // set the cipher list and check for errors
        printf("Failed to set cipher list");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    printf("Cipher suite set to: %s\n", cipher_list);
    printf("  -> Key Exchange: DHE\n");
    printf("  -> Authentication: RSA\n");
    printf("  -> Bulk Encryption: AES-256-CBC\n");
    printf("  -> MAC: SHA-256\n\n");
    
    if(SSL_CTX_set_dh_auto(ctx, 1) != 1) {                         // set up Diffie-Hellman parameters for DHE key exchange
        printf("Failed to enable auto DH parameters");
        SSL_CTX_free(ctx);
        return NULL;
    }
    printf("[ + ] Diffie-Hellman parameters configured\n");
    
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);   // Disable SSLv2 and SSLv3 for security
    
    printf("[ + ] Server SSL context created successfully\n\n");
    
    return ctx;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void configure_server_context(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
    printf("[...] Configuring server context with certificates...\n");
    
    // Load server certificate into the context
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load server certificate");
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(1);
    }
    printf("    -> Server certificate loaded: %s\n", cert_file);
    
    // Load server private key into the context
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load server private key");
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(1);
    }
    printf("    -> Server private key loaded: %s\n", key_file);
    
    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate public key\n");
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(1);
    }
    printf("    -> Private key matches certificate\n");
    
    // Enable client certificate verification for mutual authentication
    // The client will need to present its certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);

    printf("[ + ] Server context configuration complete\n\n");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int server_handshake(ssl_connection_t *conn) {

    printf("[...] Starting TLS handshake as server...\n");
    
    // Perform the handshake
    int handshake_result = SSL_accept(conn->ssl);

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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // SSL_SERVER_H
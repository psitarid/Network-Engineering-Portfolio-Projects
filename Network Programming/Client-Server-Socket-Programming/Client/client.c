#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "../common.h"
#include "client.h"
#include "../cert_X509_pem.h"
#include "../tls_handshake.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>    // X.509 certificate structures and functions
#include <openssl/pem.h>      // PEM format encoding/decoding
#include <openssl/rsa.h>     // RSA key generation and operations
#include <openssl/evp.h>     // High-level cryptographic functions
#include <openssl/bn.h>      // Big number arithmetic

#pragma comment(lib, "ws2_32.lib")                                                                 // link with Winsock library

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {                                                                 // take server IP address from command-line argument

    if (argc < 2) {                                                                                // ensure server IP address is provided on execution
        printf("Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

// PHASE1: Key Generation and Certificate Creation
    printf("\n\n------------------------- Key and Certificate Generation -------------------------\n\n\n");

    EVP_PKEY *client_key;
    X509 *client_cert;
    int cert_validity = 0;

    if (check_cert_exists("client_cert.pem") == 1) {                                             // check if client certificate already exists
        client_cert = load_certificate("client_cert.pem");                                       // load existing client certificate
        client_key = load_private_key("client_key.pem");                                         // load existing client private key
        cert_validity = check_cert_validity(client_cert);                                        // check certificate validity
    }

    if ((cert_validity == 0)) {                                                                  // if certificate does not exist or is invalid, create a new one along with keys.
        printf("Creating new client certificate and key...\n");
        client_key = rsa_key_gen();                                                              // RSA key generation
        client_cert = X509_new();                                                                // create client certificate
        set_cert_version_and_serial(client_cert);                                                // set certificate version and serial number
        set_cert_validity(client_cert);
        set_cert_names(client_cert);                                                             // set certificate details
        X509_set_pubkey(client_cert, client_key);                                                // assign client public key to the certificate
        X509_sign(client_cert, client_key, EVP_sha256());                                        // sign the client certificate

        output_cert("client_cert.pem", client_cert);                                             // output the client certificate to a file
        output_private_key("client_key.pem", client_key);                                        // output the client private key to a file
    }


// PHASE 2: TCP Connection Setup
    printf("\n\n---------------------- Socket Setup and Connection Handling ----------------------\n\n\n");

    WSADATA wsa;
    winsock_init(&wsa);                                                                            // initialize Winsock and check for errors

    char server_reply[BUFFER_SIZE];                                                                // buffer for the server reply
    char client_message[BUFFER_SIZE] = "Can I have your certificate?";                             // allocate memory for client message

    struct sockaddr_in server_address;                                                             // create server address
    char address_type[] = "IPv4";                                                                  // specify address type
    int server_port = 9002;                                                                        // specify server port

    server_address_constructor(&server_address, argv[1], address_type, server_port);               // setup server address

    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);                                        // create client socket
    check_socket_creation(client_socket);                                                          // check for client socket errors

    connect_to_server(client_socket, (struct sockaddr *)&server_address);                          // connect to server



// PHASE 3: SSL/TLS Setup and Secure Communication
    printf("\n\n--------------------- SSL/TLS Setup and Secure Communication ---------------------\n\n\n");
    initialize_openssl();                                                                        // initialize OpenSSL library
    SSL_CTX *ssl_ctx = create_client_context();                                                  // create SSL context
    configure_client_context(ssl_ctx, "client_cert.pem", "client_key.pem");                      // configure the client context with certificate and key
    
    // Create SSL connection object
    ssl_connection_t *ssl_conn;
    ssl_conn = create_ssl_connection(ssl_ctx, client_socket);   
    if (!ssl_conn) {
        printf("Failed to create SSL connection\n");
        closesocket(client_socket);
        SSL_CTX_free(ssl_ctx);
        cleanup_openssl();
        WSACleanup();

    }
// PHASE 4: TLS Handshake and Secure Data Exchange
    // Perform TLS handshake as client
    printf("\n\n--------------------- TLS Handshake and Secure Data Exchange ---------------------\n\n\n");
    if(client_handshake(ssl_conn) <= 0) {                                                                   // perform TLS handshake as client
        printf("[ - ] TLS handshake failed\n");
        SSL_free(ssl_conn->ssl);
        free(ssl_conn);
        closesocket(client_socket);
        SSL_CTX_free(ssl_ctx);
        cleanup_openssl();
        WSACleanup();
    }

    // Print detailed handshake information
    printf("\n\n----------------------------- Handshake Information ------------------------------\n\n\n");
    print_handshake_info(ssl_conn);                                                              // print detailed handshake information
    
    // Display the peer (server) certificate information
    printf("\n\n-------------------------- Peer Certificate Information --------------------------\n\n\n");
    display_peer_cert(ssl_conn);

    // Test SSL communication
    printf("\n\n------------------------- Testing Encrypted Communication -------------------------\n\n\n");
    if (!test_ssl_communication(ssl_conn, 0)) {                                                  // test SSL
        printf("[ - ]SSL communication test failed\n");
    }

    // send_message(&client_socket, client_message, strlen(client_message) + 1);                                     // send message to server

    // receive_message(&client_socket, server_reply, BUFFER_SIZE);                                    // receive message from server

    // receive_file(&client_socket, "server_cert.pem");                                             // receive server certificate file

    // send_file(&client_socket, "client_cert.pem");                                                   // send client certificate file

    // check_cert_validity(load_certificate("server_cert.pem"));                                 // check server certificate validity

    // Cleanup
    printf("\n\n------------------------------------- Cleanup ------------------------------------\n\n");
    cleanup_ssl_connection(ssl_conn);
    closesocket(client_socket);
    WSACleanup();
    X509_free(client_cert);
    EVP_PKEY_free(client_key);
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    return 0;
}




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "tcp_server.h"
#include "../common.h"
#include "../cert_X509_pem.h"
#include <openssl/x509.h>    // X.509 certificate structures and functions
#include <openssl/pem.h>      // PEM format encoding/decoding
#include <openssl/rsa.h>     // RSA key generation and operations
#include <openssl/evp.h>     // High-level cryptographic functions
#include <openssl/bn.h>      // Big number arithmetic
#include <openssl/err.h>     // Error handling
#include <openssl/dh.h>      // Diffie-Hellman key exchange

#pragma comment(lib, "ws2_32.lib")                                                               // link with Winsock library

#define BUFFER_SIZE 1024

/* tcp_server.c
 * 

 * This file implements a simple TCP server using Winsock on Windows.
 * The server listens for incoming client connections, receives a message,
 * and responds with a predefined message. It demonstrates basic socket
 * programming concepts such as socket creation, binding, listening,
 * accepting connections, and sending/receiving data.
 */



int main() {

    // PHASE 1: Certificate and Key Generation
    EVP_PKEY *server_key;
    X509 *server_cert;
    int cert_validity = 0;

    if (check_cert_exists("server_cert.pem") == 1) {                                             // check if server certificate already exists
        server_cert = load_certificate("server_cert.pem");                                       // load existing server certificate
        server_key = load_private_key("server_key.pem");                                         // load existing server private key
        cert_validity = check_cert_validity(server_cert);                                        // check certificate validity
    }

    if ((cert_validity == 0)) {                                                                  // if certificate does not exist or is invalid, create a new one along with keys.
        printf("- Creating new server certificate and key...\n");
        server_key = rsa_key_gen();                                                              // RSA key generation
        server_cert = X509_new();                                                                // create server certificate
        set_cert_version_and_serial(server_cert);                                                // set certificate version and serial number
        set_cert_validity(server_cert);
        set_cert_names(server_cert);                                                             // set certificate details
        X509_set_pubkey(server_cert, server_key);                                                // assign server public key to the certificate
        X509_sign(server_cert, server_key, EVP_sha256());                                        // sign the server certificate

        output_cert("server_cert.pem", server_cert);                                             // output the server certificate to a file
        output_private_key("server_key.pem", server_key);                                        // output the server private key to a file
    }

    initialize_openssl();                                                                        // initialize OpenSSL library                     

    SSL_CTX *ssl_ctx = create_server_context();                                                  // create SSL context 

    configure_server_context(ssl_ctx, "server_cert.pem", "server_key.pem");                      // configure the server context with certificate and key    

// PHASE 2: COMMUNICATION WITH CLIENT
    WSADATA wsa;
    winsock_init(&wsa);                                                                          // initialize winsock and check for errors

    SOCKET connection_socket;                                                                    // create connection socket
    struct sockaddr_in connection_address;                                                       // create connection address

    struct sockaddr_in listening_address;                                                        // create listening address
<<<<<<< HEAD:Network Programming/Client-Server-Socket-Programming/tcp_server.c
<<<<<<< HEAD
    char listening_ip[] = "192.168.1.6";
=======
    char listening_ip[] = "192.168.1.6";                                                     
>>>>>>> 7e29bbf6043319a32ea6f4741a4e3505fa05233e
=======
    char listening_ip[] = "192.168.1.4";                                                     
>>>>>>> 5003d1a26440226c98bb10bad48ff3197628f563:Network Programming/Client-Server-Socket-Programming/Server/tcp_server.c
    char address_type[] = "IPv4";
    int listening_port = 9002;

    server_address_constructor(&listening_address, listening_ip, address_type, listening_port);  // setup listening address

    char client_message[BUFFER_SIZE];                                                            // buffer for the client message
    char server_message[BUFFER_SIZE] = "I'm sending my certificate called server_cert.pem";      // message for the client

    SOCKET listening_socket = socket(AF_INET, SOCK_STREAM, 0);                                   // create listening socket
    check_socket_creation(listening_socket);                                                     // check for listening socket errors

    bind_socket(listening_socket, listening_address);                                            // bind the listening socket

    listen_for_client(listening_socket);                                                         // listen for incoming connections

    accept_socket(&connection_socket, connection_address, listening_socket);                     // accept a client connection

    receive_message(&connection_socket, client_message, BUFFER_SIZE);                            // receive message from client

    send_message(&connection_socket, server_message, strlen(server_message) + 1);                // send message to client

    send_file(&connection_socket, "server_cert.pem");                                            // send server certificate file

    receive_file(&connection_socket, "client_cert.pem");                                         // receive client certificate file

    check_cert_validity(load_certificate("client_cert.pem"));                                    // check client certificate validity
    
    closesocket(connection_socket);                                                              // close the connection socket
    closesocket(listening_socket);                                                               // close the listening socket
    WSACleanup();
    X509_free(server_cert);                                                                      // free the server certificate
    EVP_PKEY_free(server_key);                                                                   // free the server private key
    SSL_CTX_free(ssl_ctx);                                                                       // free the SSL context
    cleanup_openssl();                                                                           // cleanup OpenSSL
    return 0;

}
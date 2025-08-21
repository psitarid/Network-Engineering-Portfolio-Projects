#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "tcp_server.h"
#include "common.h"
#include "cert_509X.h"
#include "tcp_client.h"
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

    // PHASE 1: Key Generation and Certificate Creation
    EVP_PKEY *client_key = rsa_key_gen();                                                        // RSA key generation
    
    X509 *client_cert = X509_new();                                                              // create server certificate
    set_cert_version_and_serial(client_cert);                                                   // set certificate version and serial number
    set_cert_names(client_cert);                                                                // set certificate details
    X509_set_pubkey(client_cert, client_key);                                                    // assign server public key to the certificate
    X509_sign(client_cert, client_key, EVP_sha256());                                            // sign the server certificate

    output_cert("client_cert.pem", client_cert);                                                 // output the client certificate to a file
    output_private_key("client_key.pem", client_key);

    // PHASE 2: Communication with the Server
    WSADATA wsa;
    winsock_init(&wsa);                                                                            // initialize Winsock and check for errors

    struct sockaddr_in server_address;                                                             // create server address
    char address_type[] = "IPv4";                                                                  // specify address type
    int server_port = 9002;                                                                        // specify server port

    server_address_constructor(&server_address, argv[1], address_type, server_port);               // setup server address

    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);                                        // create client socket
    check_socket_creation(client_socket);                                                          // check for client socket errors

    char server_reply[BUFFER_SIZE];                                                                // buffer for the server reply
    char client_message[BUFFER_SIZE] = "Is anyone there?";                                         // allocate memory for client message

    connect_to_server(client_socket, (struct sockaddr *)&server_address);                          // connect to server

    send_message(&client_socket, client_message, BUFFER_SIZE);                                     // send message to server

    receive_message(&client_socket, server_reply, BUFFER_SIZE);                                    // receive message from server

    // Cleanup
    closesocket(client_socket);
    WSACleanup();
    return 0;
}


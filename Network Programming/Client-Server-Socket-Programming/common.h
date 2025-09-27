#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "cert_X509_pem.h"

#define BUFFER_SIZE 1024

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// check Winsock initialization
void winsock_init(WSADATA *wsa) {
    if (WSAStartup(MAKEWORD(2,2), wsa) != 0) {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }
    else {
        printf("[ + ] Winsock initialization successful.\n");
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void initialize_openssl() {
    printf("[...] Initializing OpenSSL library...\n");

    // initialize the SSL library
    SSL_library_init();


    // load all SSL error messages
    SSL_load_error_strings();

    // load all cryptographic algorithms
    OpenSSL_add_all_algorithms();

    // initialize random number generator (for key generation)
    if (RAND_poll() == 0) {
        printf("RAND_poll failed - random number generator not properly seeded.\n");
        exit(1);
    }

    printf("[ + ] OpenSSL library initialized successfully.\n\n");
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// check socket creation
void check_socket_creation(SOCKET socket) {
    if (socket == INVALID_SOCKET) {
        printf("Could not create socket: %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }
    else {
        printf("[ + ] Socket creation successfully.\n");
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// send message
void send_message(SOCKET *sender_socket,  char *message, int message_size) {
    int send_check = send(*sender_socket, message, message_size, 0);
    if (send_check == SOCKET_ERROR) {
        printf("Send failed: %d\n", WSAGetLastError());
    } else {
        printf("Message sent: %s\n\n", message);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// receive message
void receive_message(SOCKET *receiver_socket, char *incoming_message, int message_size) {
    int recv_size = recv(*receiver_socket, incoming_message, message_size - 1, 0);
    if (recv_size == SOCKET_ERROR) {
        printf("Receiving failed: %d\n", WSAGetLastError());
        closesocket(*receiver_socket);
        WSACleanup();
        exit(1);
    } else if (recv_size > 0) {
        incoming_message[recv_size] = '\0';                    // Null-terminate the received message
        printf("Received message: %s\n\n", incoming_message);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//send file
void send_file(SOCKET *sender_socket, const char *filename) {
    size_t bytes_read;
    char buffer [BUFFER_SIZE];

    FILE *fp = fopen(filename, "rb")    ;
    if (fp == NULL) {
        printf("Could not open file %s for reading.\n", filename);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    uint32_t filesize = (uint32_t)ftell(fp);
    rewind(fp);

    uint32_t network_filesize = htonl(filesize); // Convert to network byte order
        if (send(*sender_socket, (char*)&network_filesize, sizeof(network_filesize), 0) == SOCKET_ERROR) {
        printf("Failed to send file size: %d\n", WSAGetLastError());
        fclose(fp);
        exit(1);
    }
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        size_t total_sent = 0;
        while (total_sent < bytes_read) {
            int sent = send(*sender_socket, buffer + total_sent, bytes_read - total_sent, 0);
            if (sent == SOCKET_ERROR) {
                printf("Failed to send file data: %d\n", WSAGetLastError());
                fclose(fp);
                exit(1);
            }
            total_sent += sent;
        }
    }

    printf("File %s sent successfully (%u bytes).\n", filename, filesize);
    fclose(fp);
}

//receive file
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//receive file
void receive_file(SOCKET *receiver_socket, const char *filename) {
    char buffer[BUFFER_SIZE];
    
    // Open the file for writing in binary mode
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        printf("Could not open file %s for writing.\n", filename);
        exit(1);
    }

    // Receive the file size first
    uint32_t network_filesize;
    int bytes_received;
    size_t total_size_received = 0;
    const size_t size_of_filesize = sizeof(network_filesize);

    // Loop until the entire file size (4 bytes) is received
    while (total_size_received < size_of_filesize) {
        bytes_received = recv(*receiver_socket, (char*)&network_filesize + total_size_received, size_of_filesize - total_size_received, 0);
        
        if (bytes_received <= 0) {
            printf("Failed to receive file size or connection closed: %d\n", WSAGetLastError());
            fclose(fp);
            exit(1);
        }
        total_size_received += bytes_received;
    } 
    
    // Convert from network byte order to host byte order
    uint32_t filesize = ntohl(network_filesize);
    
    // Receive the file data in chunks
    uint32_t total_received = 0;
    while (total_received < filesize) {
        // Calculate the number of bytes to receive in this chunk
        int bytes_to_receive = (filesize - total_received > BUFFER_SIZE) ? BUFFER_SIZE : (filesize - total_received);
        
        bytes_received = recv(*receiver_socket, buffer, bytes_to_receive, 0);
        
        if (bytes_received == SOCKET_ERROR) {
            printf("Receive failed: %d\n", WSAGetLastError());
            fclose(fp);
            return;
        } else if (bytes_received == 0) {
            printf("Connection closed before file was fully received.\n");
            break;
        }
        
        fwrite(buffer, 1, bytes_received, fp);
        total_received += bytes_received;
    }

    fclose(fp);
    if (total_received == filesize) {
        printf("File %s received successfully (%u bytes)\n", filename, total_received);
    } else {
        printf("File transfer incomplete: expected %u, got %u bytes.\n", filesize, total_received);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// construct server address
void server_address_constructor(struct sockaddr_in *server_address, const char *ip, const char *address_type, int server_port) {
    if(strcmp(address_type, "IPv4") == 0){
        server_address->sin_family = AF_INET;           // AF_INET -> for IPv4
    }
    server_address->sin_port = htons(server_port);      // htons -> convert port number to network byte order
    server_address->sin_addr.s_addr = inet_addr(ip);    // set server IP address
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Print SSL error messages for debugging
 */
void print_ssl_error(const char *msg) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    printf("SSL Error: %s - %s\n", msg, err_buf);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Cleanup OpenSSL library
 */
void cleanup_openssl() {
    // Clean up error strings
    ERR_free_strings();
    // Clean up algorithms
    EVP_cleanup();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    // You can add custom verification logic here if needed
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    return check_cert_validity(cert) ? 1 : 0;                       // Return the result of the validity check
}











#endif // COMMON_H
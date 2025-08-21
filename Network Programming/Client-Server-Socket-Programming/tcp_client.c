#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "tcp_client.h"
#include "common.h"

#pragma comment(lib, "ws2_32.lib")                                                                 // link with Winsock library

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {                                                                 // take server IP address from command-line argument

    if (argc < 2) {                                                                                // ensure server IP address is provided on execution
        printf("Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }
    
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

    connect_to_server(client_socket, (struct sockaddr *)&server_address);                         // connect to server

    send_message(&client_socket, client_message, BUFFER_SIZE);                                     // send message to server

    receive_message(&client_socket, server_reply, BUFFER_SIZE);                                    // receive message from server

    // Cleanup
    closesocket(client_socket);
    WSACleanup();
    return 0;
}


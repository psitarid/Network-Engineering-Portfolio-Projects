#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "tcp_server.h"
#include "common.h"

#pragma comment(lib, "ws2_32.lib")                                                          // link with Winsock library

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
    
    WSADATA wsa;
    winsock_init(&wsa);                                                                          // initialize winsock and check for errors

    SOCKET connection_socket;                                                                    // create connection socket
    struct sockaddr_in connection_address;                                                       // create connection address

    struct sockaddr_in listening_address;                                                        // create listening address
    char listening_ip[] = "192.168.178.124";
    char address_type[] = "IPv4";
    int listening_port = 9002;
    
    server_address_constructor(&listening_address, listening_ip, address_type, listening_port);  // setup listening address
 
    char client_message[BUFFER_SIZE];                                                            // buffer for the client message
    char server_message[BUFFER_SIZE] = "You have reached the server!";                           // message for the client

    SOCKET listening_socket = socket(AF_INET, SOCK_STREAM, 0);                                   // create listening socket
    check_socket_creation(listening_socket);                                                     // check for listening socket errors
    
    bind_socket(listening_socket, listening_address);                                            // bind the listening socket

    listen_for_client(listening_socket);                                                         // listen for incoming connections

    accept_socket(&connection_socket, connection_address, listening_socket);                     // accept a client connection

    receive_message(&connection_socket, client_message, BUFFER_SIZE);                            // receive message from client

    send_message(&connection_socket, server_message, BUFFER_SIZE);                               // send message to client

    closesocket(listening_socket);                                                               // close the listening socket
    WSACleanup();

    return 0;
}
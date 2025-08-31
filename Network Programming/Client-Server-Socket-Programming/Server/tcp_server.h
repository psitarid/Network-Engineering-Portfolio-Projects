#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>


// check binding
void bind_socket(SOCKET listening_socket, struct sockaddr_in listening_address) {
    int bind_result = bind(listening_socket, (struct sockaddr *)&listening_address, sizeof(listening_address));
    if (bind_result == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(listening_socket);
        WSACleanup();
        exit(1);
    }
    printf("- Binding successful.\n");
}


// check listening status
void listen_for_client(SOCKET listening_socket) {
    int listen_status = listen(listening_socket, 5);
    if (listen_status == SOCKET_ERROR) {
        printf("Listening failed: %d\n", WSAGetLastError());
        closesocket(listening_socket);
        WSACleanup();
        exit(1);
    }
    printf("- Waiting for incoming connections...\n");
}

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
    // Print client info
    printf("- Connection received from %s:%d\n",
           inet_ntoa(connection_address.sin_addr),
           ntohs(connection_address.sin_port));
}
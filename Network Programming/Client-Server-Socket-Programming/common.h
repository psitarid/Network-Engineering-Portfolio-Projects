#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

// check Winsock initialization
void winsock_init(WSADATA *wsa) {
    printf("- Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2,2), wsa) != 0) {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }
    else {
        printf("- Initialization successful.\n");
    }
}


// check socket creation
void check_socket_creation(SOCKET socket) {
    if (socket == INVALID_SOCKET) {
        printf("Could not create socket: %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }
    else {
        printf("- Socket created successfully.\n");
    }
}

// send message
void send_message(SOCKET *sender_socket,  char *message, int message_size) {
    int send_check = send(*sender_socket, message, message_size, 0);
    if (send_check == SOCKET_ERROR) {
        printf("Send failed: %d\n", WSAGetLastError());
    } else {
        printf("- Message sent.\n");
    }
}

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
        printf("- Received message: %s\n", incoming_message);
    }
}

// construct server address
void server_address_constructor(struct sockaddr_in *server_address, const char *ip, const char *address_type, int server_port) {
    if(strcmp(address_type, "IPv4") == 0){
        server_address->sin_family = AF_INET;           // AF_INET -> for IPv4
    }
    server_address->sin_port = htons(server_port);      // htons -> convert port number to network byte order
    server_address->sin_addr.s_addr = inet_addr(ip);    // set server IP address
}
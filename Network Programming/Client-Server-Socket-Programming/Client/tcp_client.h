#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

void connect_to_server(SOCKET client_socket, struct sockaddr *server_address) {
    if (connect(client_socket, server_address, sizeof(struct sockaddr)) < 0) {
        printf("Connection failed\n");
        closesocket(client_socket);
        WSACleanup();
        exit(1);
    }
    else {
        printf("- Connected to server successfully.\n\n");
    }
}

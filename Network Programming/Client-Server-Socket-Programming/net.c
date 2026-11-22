/* net.c - cross-platform socket helpers (see net.h). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "net.h"

void net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    printf("- Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        exit(1);
    }
    printf("- Initialization successful.\n");
#endif
}

void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

int net_last_error(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

void net_close(socket_t s) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

static void fail(const char *what, socket_t s) {
    printf("%s failed: %d\n", what, net_last_error());
    if (s != NET_INVALID_SOCKET) net_close(s);
    net_cleanup();
    exit(1);
}

void server_address_constructor(struct sockaddr_in *address, const char *ip, int port) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;                                   // AF_INET -> IPv4
    address->sin_port   = htons((unsigned short)port);               // host -> network byte order
    if (inet_pton(AF_INET, ip, &address->sin_addr) != 1) {           // dotted string -> binary
        printf("Invalid IPv4 address: %s\n", ip);
        net_cleanup();
        exit(1);
    }
}

socket_t create_tcp_socket(void) {
    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == NET_INVALID_SOCKET) fail("Socket creation", NET_INVALID_SOCKET);
    printf("- Socket created successfully.\n");
    return s;
}

void bind_socket(socket_t listening_socket, const struct sockaddr_in *address) {
    int yes = 1;                                                     // allow quick restarts on the same port
    setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    if (bind(listening_socket, (const struct sockaddr *)address, sizeof(*address)) != 0)
        fail("Bind", listening_socket);
    printf("- Binding successful.\n");
}

void listen_for_client(socket_t listening_socket) {
    if (listen(listening_socket, 5) != 0) fail("Listen", listening_socket);
    printf("- Waiting for incoming connections...\n");
}

socket_t accept_socket(socket_t listening_socket, struct sockaddr_in *peer_address) {
    socklen_t len = sizeof(*peer_address);
    socket_t s = accept(listening_socket, (struct sockaddr *)peer_address, &len);
    if (s == NET_INVALID_SOCKET) fail("Accept", listening_socket);

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_address->sin_addr, ip, sizeof(ip));
    printf("- Connection received from %s:%d\n", ip, ntohs(peer_address->sin_port));
    return s;
}

void connect_to_server(socket_t client_socket, const struct sockaddr_in *server_address) {
    if (connect(client_socket, (const struct sockaddr *)server_address, sizeof(*server_address)) != 0)
        fail("Connection", client_socket);
    printf("- Connected to server successfully.\n");
}

int send_all(socket_t s, const unsigned char *buf, size_t len) {
    while (len > 0) {
        int n = send(s, (const char *)buf, (int)len, 0);
        if (n <= 0) return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

int recv_all(socket_t s, unsigned char *buf, size_t len) {
    while (len > 0) {
        int n = recv(s, (char *)buf, (int)len, 0);
        if (n <= 0) return -1;                                       // error or peer closed the connection
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

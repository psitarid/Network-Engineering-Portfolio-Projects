/* net.h
 *
 * Thin, cross-platform wrapper around the BSD socket API.
 * On Windows it uses Winsock2, on Linux/macOS it uses POSIX sockets,
 * so the rest of the project never has to care which one is underneath.
 */
#ifndef NET_H
#define NET_H

#include <stddef.h>

#ifdef _WIN32
    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0600   /* Vista+ : needed for inet_pton / inet_ntop */
    #endif
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    #define NET_INVALID_SOCKET INVALID_SOCKET
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    typedef int socket_t;
    #define NET_INVALID_SOCKET (-1)
#endif

#define DEFAULT_PORT 9002

/* Library start-up / shutdown (WSAStartup / WSACleanup on Windows, no-op elsewhere). */
void net_init(void);
void net_cleanup(void);

/* Last socket error code (WSAGetLastError() or errno). */
int  net_last_error(void);

void net_close(socket_t s);

/* Build an IPv4 socket address from a dotted string and a port. Exits on a bad IP. */
void server_address_constructor(struct sockaddr_in *address, const char *ip, int port);

/* Socket creation and server/client set-up. All of these exit on failure. */
socket_t create_tcp_socket(void);
void     bind_socket(socket_t listening_socket, const struct sockaddr_in *address);
void     listen_for_client(socket_t listening_socket);
socket_t accept_socket(socket_t listening_socket, struct sockaddr_in *peer_address);
void     connect_to_server(socket_t client_socket, const struct sockaddr_in *server_address);

/* Reliable I/O: loop until exactly `len` bytes are sent / received.
 * Return 0 on success, -1 on error or if the peer closed the connection. */
int send_all(socket_t s, const unsigned char *buf, size_t len);
int recv_all(socket_t s, unsigned char *buf, size_t len);

#endif /* NET_H */

/* tcp_server.c
 *
 * TLS 1.2 server (DHE-RSA-AES256-SHA256, mutual authentication).
 *
 *   PHASE 1: load the server certificate, private key and the trusted CA
 *   PHASE 2: listen on TCP, accept clients one at a time
 *   PHASE 3: run the TLS handshake (the client must present a CA-signed certificate)
 *   PHASE 4: exchange encrypted messages until the client closes the session
 *
 * Usage: tcp_server [bind_ip] [port]        (defaults: 0.0.0.0 9002)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <signal.h>
#endif
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "net.h"
#include "cert_509X.h"
#include "tls.h"

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#define BUFFER_SIZE TLS_MAX_PLAINTEXT

static void serve_client(socket_t connection_socket, X509 *cert, EVP_PKEY *key, X509 *ca) {
    tls_session tls;
    tls_init(&tls, connection_socket, TLS_ROLE_SERVER, cert, key, ca, NULL);

    if (tls_handshake(&tls) != 0) {
        printf("- Handshake failed, dropping the connection.\n");
        tls_free(&tls);
        return;
    }

    char client_message[BUFFER_SIZE + 1];
    char server_message[BUFFER_SIZE + 64];
    int n;
    while ((n = tls_read(&tls, client_message, BUFFER_SIZE)) > 0) {      // receive (decrypt) from client
        client_message[n] = '\0';
        printf("- Received message: %s\n", client_message);

        if (strcmp(client_message, "Is anyone there?") == 0)
            snprintf(server_message, sizeof(server_message), "You have reached the server!");
        else
            snprintf(server_message, sizeof(server_message), "Server received: %s", client_message);

        if (tls_write(&tls, server_message, strlen(server_message)) != 0) break;   // send (encrypt) reply
        printf("- Message sent.\n");
    }
    if (n == 0) printf("- Client closed the session (close_notify).\n");
    tls_close(&tls);
    tls_free(&tls);
}

int main(int argc, char *argv[]) {
    const char *listening_ip = argc > 1 ? argv[1] : "0.0.0.0";
    int listening_port = argc > 2 ? atoi(argv[2]) : DEFAULT_PORT;
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);                                             // a dropped client must not kill the server
#endif

    setvbuf(stdout, NULL, _IONBF, 0);                                     // show output immediately

// PHASE 1: Certificates
    X509 *ca_cert = load_cert("ca_cert.pem");
    X509 *server_cert = load_cert("server_cert.pem");
    EVP_PKEY *server_key = load_private_key("server_key.pem");
    if (!ca_cert || !server_cert || !server_key) {
        fprintf(stderr, "Missing certificates. Run `certgen` first.\n");
        return 1;
    }
    if (X509_check_private_key(server_cert, server_key) != 1) {
        fprintf(stderr, "server_key.pem does not match server_cert.pem\n");
        return 1;
    }
    printf("- Loaded certificates:\n");
    print_cert_summary("Server certificate", server_cert);

// PHASE 2: TCP
    net_init();
    struct sockaddr_in listening_address;
    server_address_constructor(&listening_address, listening_ip, listening_port);

    socket_t listening_socket = create_tcp_socket();
    bind_socket(listening_socket, &listening_address);
    listen_for_client(listening_socket);
    printf("- Listening on %s:%d (Ctrl+C to stop)\n", listening_ip, listening_port);

// PHASE 3 + 4: TLS session per client
    for (;;) {
        struct sockaddr_in connection_address;
        socket_t connection_socket = accept_socket(listening_socket, &connection_address);
        serve_client(connection_socket, server_cert, server_key, ca_cert);
        net_close(connection_socket);
        printf("- Connection closed. Waiting for the next client...\n\n");
    }

    // not reached
    net_close(listening_socket);
    net_cleanup();
    X509_free(server_cert);
    X509_free(ca_cert);
    EVP_PKEY_free(server_key);
    return 0;
}

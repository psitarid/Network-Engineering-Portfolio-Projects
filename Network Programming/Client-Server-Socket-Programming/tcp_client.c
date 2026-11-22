/* tcp_client.c
 *
 * TLS 1.2 client (DHE-RSA-AES256-SHA256, mutual authentication).
 *
 *   PHASE 1: load the client certificate, private key and the trusted CA
 *   PHASE 2: connect to the server over TCP
 *   PHASE 3: run the TLS handshake (the server certificate must be CA-signed and contain the server IP)
 *   PHASE 4: send encrypted messages typed by the user, print the encrypted replies
 *
 * Usage: tcp_client <server_ip> [port]      (default port: 9002)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "net.h"
#include "cert_509X.h"
#include "tls.h"

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#define BUFFER_SIZE TLS_MAX_PLAINTEXT

// send one message and print the server's reply; returns 0 on success
static int exchange(tls_session *tls, const char *message) {
    char server_reply[BUFFER_SIZE + 1];
    if (tls_write(tls, message, strlen(message)) != 0) return -1;
    printf("- Message sent: %s\n", message);

    int n = tls_read(tls, server_reply, BUFFER_SIZE);
    if (n <= 0) return -1;
    server_reply[n] = '\0';
    printf("- Received message: %s\n", server_reply);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {                                                       // server IP is required
        printf("Usage: %s <server_ip> [port]\n", argv[0]);
        return 1;
    }
    const char *server_ip = argv[1];
    int server_port = argc > 2 ? atoi(argv[2]) : DEFAULT_PORT;

    setvbuf(stdout, NULL, _IONBF, 0);                                     // show output immediately

// PHASE 1: Certificates
    X509 *ca_cert = load_cert("ca_cert.pem");
    X509 *client_cert = load_cert("client_cert.pem");
    EVP_PKEY *client_key = load_private_key("client_key.pem");
    if (!ca_cert || !client_cert || !client_key) {
        fprintf(stderr, "Missing certificates. Run `certgen` first.\n");
        return 1;
    }
    if (X509_check_private_key(client_cert, client_key) != 1) {
        fprintf(stderr, "client_key.pem does not match client_cert.pem\n");
        return 1;
    }
    printf("- Loaded certificates:\n");
    print_cert_summary("Client certificate", client_cert);

// PHASE 2: TCP
    net_init();
    struct sockaddr_in server_address;
    server_address_constructor(&server_address, server_ip, server_port);
    socket_t client_socket = create_tcp_socket();
    connect_to_server(client_socket, &server_address);

// PHASE 3: TLS handshake (verifies that the server certificate is valid for server_ip)
    tls_session tls;
    tls_init(&tls, client_socket, TLS_ROLE_CLIENT, client_cert, client_key, ca_cert, server_ip);
    int rc = 1;
    if (tls_handshake(&tls) != 0) {
        printf("- Handshake failed.\n");
        goto cleanup;
    }

// PHASE 4: encrypted communication
    if (exchange(&tls, "Is anyone there?") != 0) goto cleanup;

    printf("\nType a message and press Enter (\"quit\" or Ctrl+D / Ctrl+Z to exit).\n");
    char line[BUFFER_SIZE];
    for (;;) {
        printf("> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, "quit") == 0) break;
        if (line[0] == '\0') continue;
        if (exchange(&tls, line) != 0) goto cleanup;
    }
    tls_close(&tls);                                                      // send close_notify
    printf("- Session closed.\n");
    rc = 0;

cleanup:
    tls_free(&tls);
    net_close(client_socket);
    net_cleanup();
    X509_free(client_cert);
    X509_free(ca_cert);
    EVP_PKEY_free(client_key);
    return rc;
}

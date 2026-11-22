/* certgen.c
 *
 * Generates the keys and certificates the server and client need:
 *
 *   certgen ca       -> ca_cert.pem / ca_key.pem          (self-signed Certificate Authority)
 *   certgen server   -> server_cert.pem / server_key.pem  (signed by the CA, serverAuth, IP SANs)
 *   certgen client   -> client_cert.pem / client_key.pem  (signed by the CA, clientAuth)
 *   certgen all      -> all of the above (default)
 *
 * Both peers trust the CA, so each one can verify the other's certificate
 * during the handshake (mutual authentication).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "cert_509X.h"

#define CA_CERT_FILE "ca_cert.pem"
#define CA_KEY_FILE  "ca_key.pem"

// "127.0.0.1, 192.168.1.10" -> "IP:127.0.0.1,IP:192.168.1.10"
static void build_ip_san(const char *input, char *out, size_t out_size) {
    char copy[512];
    strncpy(copy, input, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    out[0] = '\0';
    for (char *tok = strtok(copy, ", "); tok; tok = strtok(NULL, ", ")) {
        if (out[0]) strncat(out, ",", out_size - strlen(out) - 1);
        strncat(out, "IP:", out_size - strlen(out) - 1);
        strncat(out, tok, out_size - strlen(out) - 1);
    }
}

static int make_ca(void) {
    printf("\n=== Creating Certificate Authority ===\n");
    EVP_PKEY *key = rsa_key_gen();
    X509_NAME *subject = key ? prompt_cert_subject("CA") : NULL;
    X509 *cert = subject ? build_certificate(CERT_ROLE_CA, key, subject, NULL, NULL, NULL) : NULL;

    int ok = cert && output_cert(CA_CERT_FILE, cert) && output_private_key(CA_KEY_FILE, key);
    if (ok) print_cert_summary("CA certificate", cert);

    X509_free(cert);
    X509_NAME_free(subject);
    EVP_PKEY_free(key);
    return ok;
}

static int make_leaf(cert_role_t role) {
    const char *label     = role == CERT_ROLE_SERVER ? "server" : "client";
    const char *cert_file = role == CERT_ROLE_SERVER ? "server_cert.pem" : "client_cert.pem";
    const char *key_file  = role == CERT_ROLE_SERVER ? "server_key.pem"  : "client_key.pem";

    printf("\n=== Creating %s certificate ===\n", label);
    X509 *ca_cert = load_cert(CA_CERT_FILE);                                // the CA signs the new certificate
    EVP_PKEY *ca_key = ca_cert ? load_private_key(CA_KEY_FILE) : NULL;
    if (!ca_cert || !ca_key) {
        X509_free(ca_cert);
        return 0;
    }

    char san[600] = "";
    if (role == CERT_ROLE_SERVER) {                                         // which IPs the server answers on
        char ips[512];
        printf("  Server IP address(es), comma-separated [127.0.0.1]: ");
        fflush(stdout);
        if (!fgets(ips, sizeof(ips), stdin)) ips[0] = '\0';
        ips[strcspn(ips, "\r\n")] = '\0';
        build_ip_san(ips[0] ? ips : "127.0.0.1", san, sizeof(san));
    }

    EVP_PKEY *key = rsa_key_gen();
    X509_NAME *subject = key ? prompt_cert_subject(label) : NULL;
    X509 *cert = subject ? build_certificate(role, key, subject, ca_cert, ca_key, san) : NULL;

    int ok = cert && output_cert(cert_file, cert) && output_private_key(key_file, key);
    if (ok) {
        print_cert_summary(role == CERT_ROLE_SERVER ? "Server certificate" : "Client certificate", cert);
        if (san[0]) printf("    SAN     : %s\n", san);
    }

    X509_free(cert);
    X509_NAME_free(subject);
    EVP_PKEY_free(key);
    EVP_PKEY_free(ca_key);
    X509_free(ca_cert);
    return ok;
}

int main(int argc, char *argv[]) {
    const char *mode = argc > 1 ? argv[1] : "all";
    int ok;

    if      (strcmp(mode, "ca") == 0)     ok = make_ca();
    else if (strcmp(mode, "server") == 0) ok = make_leaf(CERT_ROLE_SERVER);
    else if (strcmp(mode, "client") == 0) ok = make_leaf(CERT_ROLE_CLIENT);
    else if (strcmp(mode, "all") == 0)    ok = make_ca() && make_leaf(CERT_ROLE_SERVER) && make_leaf(CERT_ROLE_CLIENT);
    else {
        printf("Usage: %s [ca | server | client | all]\n", argv[0]);
        return 1;
    }

    if (!ok) {
        fprintf(stderr, "\nCertificate generation failed.\n");
        return 1;
    }
    printf("\nDone.\n");
    return 0;
}

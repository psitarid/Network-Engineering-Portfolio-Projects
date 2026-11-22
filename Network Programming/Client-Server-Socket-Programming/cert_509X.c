/* cert_509X.c - RSA keys and X.509 certificates with OpenSSL (see cert_509X.h). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "cert_509X.h"


// RSA Key Generation
EVP_PKEY *rsa_key_gen(void) {
    EVP_PKEY *pkey = NULL;                                                   // pointer to hold the generated key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);             // key generation context for RSA keys

    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {                  // 2048-bit modulus
        fprintf(stderr, "Failed to set key length\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;                                                            // RSA key pair (private + public)
}


// Version (X509v3) and a random 64-bit positive serial number
int set_cert_version_and_serial(X509 *cert) {
    int ok = 0;
    BIGNUM *bn = BN_new();
    ASN1_INTEGER *serial = NULL;

    if (bn && BN_rand(bn, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)          // random serial -> unique per certificate
        && (serial = BN_to_ASN1_INTEGER(bn, NULL)) != NULL
        && X509_set_serialNumber(cert, serial)
        && X509_set_version(cert, 2)) {                                     // value 2 = X509v3
        ok = 1;
    }
    ASN1_INTEGER_free(serial);
    BN_free(bn);
    if (!ok) fprintf(stderr, "Failed to set certificate version and serial number\n");
    return ok;
}


// Validity Period: notBefore = now, notAfter = now + days
int set_cert_validity(X509 *cert, long days) {
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L * days)) {
        fprintf(stderr, "Failed to set certificate validity period\n");
        return 0;
    }
    return 1;
}


// Subject (who the certificate belongs to) and Issuer (who signed it)
int set_cert_names(X509 *cert, X509_NAME *subject, X509_NAME *issuer) {
    if (!X509_set_subject_name(cert, subject)) {
        fprintf(stderr, "Failed to set certificate subject name\n");
        return 0;
    }
    if (!X509_set_issuer_name(cert, issuer)) {
        fprintf(stderr, "Failed to set certificate issuer name\n");
        return 0;
    }
    return 1;
}


// read one line from stdin, strip the newline, fall back to a default if empty
static int read_line(const char *prompt, const char *default_value, char *out, size_t out_size) {
    printf("  %s [%s]: ", prompt, default_value);
    fflush(stdout);
    if (!fgets(out, (int)out_size, stdin)) out[0] = '\0';
    out[strcspn(out, "\r\n")] = '\0';
    if (out[0] == '\0') {
        strncpy(out, default_value, out_size - 1);
        out[out_size - 1] = '\0';
    }
    return 1;
}

X509_NAME *prompt_cert_subject(const char *role_label) {
    char country[100], org[100], cn[100];
    X509_NAME *name = X509_NAME_new();
    if (!name) {
        fprintf(stderr, "Failed to create X509_NAME structure\n");
        return NULL;
    }

    printf("\nCertificate details for the %s (press Enter to keep the default):\n", role_label);
    read_line("Country (2 letters)", "GR", country, sizeof(country));
    read_line("Organization", "Network Portfolio", org, sizeof(org));
    read_line("Common Name", role_label, cn, sizeof(cn));

    if (strlen(country) != 2) {
        fprintf(stderr, "Country must be exactly 2 letters (e.g. GR)\n");
        X509_NAME_free(name);
        return NULL;
    }

    if (!X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_UTF8, (unsigned char *)country, -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_UTF8, (unsigned char *)org,     -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (unsigned char *)cn,      -1, -1, 0)) {
        fprintf(stderr, "Failed to add entries to X509_NAME structure\n");
        X509_NAME_free(name);
        return NULL;
    }
    return name;
}


// add one X509v3 extension, e.g. ("basicConstraints", "critical,CA:TRUE")
static int add_extension(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ext) {
        fprintf(stderr, "Failed to create extension %s = %s\n", OBJ_nid2sn(nid), value);
        return 0;
    }
    int ok = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return ok;
}

X509 *build_certificate(cert_role_t role, EVP_PKEY *subject_key, X509_NAME *subject,
                        X509 *issuer_cert, EVP_PKEY *issuer_key, const char *subject_alt_names) {
    X509 *cert = X509_new();
    if (!cert) return NULL;

    int is_ca = (role == CERT_ROLE_CA);
    if (is_ca) {                                                            // a CA signs itself
        issuer_cert = cert;
        issuer_key  = subject_key;
    }
    X509_NAME *issuer_name = is_ca ? subject : X509_get_subject_name(issuer_cert);

    int ok = set_cert_version_and_serial(cert)
          && set_cert_validity(cert, is_ca ? CERT_VALIDITY_DAYS_CA : CERT_VALIDITY_DAYS_LEAF)
          && set_cert_names(cert, subject, issuer_name)
          && X509_set_pubkey(cert, subject_key);                            // attach the subject's public key

    // X509v3 extensions: what the certificate is allowed to be used for
    if (ok) {
        ok = add_extension(cert, issuer_cert, NID_subject_key_identifier, "hash");
        if (ok && !is_ca)
            ok = add_extension(cert, issuer_cert, NID_authority_key_identifier, "keyid:always");
        if (ok && is_ca) {
            ok = add_extension(cert, issuer_cert, NID_basic_constraints, "critical,CA:TRUE,pathlen:0")
              && add_extension(cert, issuer_cert, NID_key_usage, "critical,keyCertSign,cRLSign");
        } else if (ok) {
            ok = add_extension(cert, issuer_cert, NID_basic_constraints, "critical,CA:FALSE")
              && add_extension(cert, issuer_cert, NID_key_usage, "critical,digitalSignature,keyEncipherment")
              && add_extension(cert, issuer_cert, NID_ext_key_usage,
                               role == CERT_ROLE_SERVER ? "serverAuth" : "clientAuth");
        }
        if (ok && subject_alt_names && subject_alt_names[0])
            ok = add_extension(cert, issuer_cert, NID_subject_alt_name, subject_alt_names);
    }

    if (ok && !X509_sign(cert, issuer_key, EVP_sha256())) {                 // sign with SHA-256 + issuer's RSA key
        fprintf(stderr, "Failed to sign certificate\n");
        ok = 0;
    }
    if (!ok) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return NULL;
    }
    return cert;
}


// PEM output via BIO
int output_cert(const char *filename, X509 *cert) {
    BIO *bio = BIO_new_file(filename, "w");
    if (!bio) {
        fprintf(stderr, "Unable to create BIO for certificate file %s\n", filename);
        return 0;
    }
    int result = PEM_write_bio_X509(bio, cert);
    BIO_free(bio);
    if (!result) fprintf(stderr, "Failed to write certificate to %s\n", filename);
    else         printf("- Certificate written to %s\n", filename);
    return result;
}

int output_private_key(const char *filename, EVP_PKEY *pkey) {
    BIO *bio = BIO_new_file(filename, "w");
    if (!bio) {
        fprintf(stderr, "Unable to create BIO for private key file %s\n", filename);
        return 0;
    }
    int result = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_free(bio);
    if (!result) fprintf(stderr, "Failed to write private key to %s\n", filename);
    else         printf("- Private key written to %s\n", filename);
    return result;
}

X509 *load_cert(const char *filename) {
    BIO *bio = BIO_new_file(filename, "r");
    if (!bio) {
        fprintf(stderr, "Cannot open %s (run certgen first)\n", filename);
        return NULL;
    }
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) fprintf(stderr, "Failed to parse certificate %s\n", filename);
    return cert;
}

EVP_PKEY *load_private_key(const char *filename) {
    BIO *bio = BIO_new_file(filename, "r");
    if (!bio) {
        fprintf(stderr, "Cannot open %s (run certgen first)\n", filename);
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) fprintf(stderr, "Failed to parse private key %s\n", filename);
    return pkey;
}


void print_cert_summary(const char *label, X509 *cert) {
    char subject[256], issuer[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));

    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_printf(out, "  %s\n    subject : %s\n    issuer  : %s\n    valid   : ", label, subject, issuer);
    ASN1_TIME_print(out, X509_get0_notBefore(cert));
    BIO_printf(out, "  ->  ");
    ASN1_TIME_print(out, X509_get0_notAfter(cert));
    BIO_printf(out, "\n");
    BIO_free(out);
}


int verify_peer_cert(X509 *peer_cert, X509 *ca_cert, cert_role_t expected_role, const char *expected_ip) {
    int trusted = 0;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    if (!store || !ctx || !X509_STORE_add_cert(store, ca_cert)) {           // the CA is our only trust anchor
        fprintf(stderr, "Failed to set up certificate store\n");
        goto done;
    }
    if (!X509_STORE_CTX_init(ctx, store, peer_cert, NULL)) {
        fprintf(stderr, "Failed to initialise verification context\n");
        goto done;
    }

    // require serverAuth / clientAuth in the extendedKeyUsage
    X509_STORE_CTX_set_purpose(ctx, expected_role == CERT_ROLE_SERVER ? X509_PURPOSE_SSL_SERVER
                                                                      : X509_PURPOSE_SSL_CLIENT);
    // optionally require the server's IP address in subjectAltName
    if (expected_ip && !X509_VERIFY_PARAM_set1_ip_asc(X509_STORE_CTX_get0_param(ctx), expected_ip)) {
        fprintf(stderr, "Invalid IP address for verification: %s\n", expected_ip);
        goto done;
    }

    // checks the CA signature, the validity period (notBefore / notAfter), purpose and IP
    if (X509_verify_cert(ctx) == 1) {
        trusted = 1;
    } else {
        int err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "Certificate verification failed: %s\n", X509_verify_cert_error_string(err));
    }

done:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return trusted;
}

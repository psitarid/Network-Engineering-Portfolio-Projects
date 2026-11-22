/* cert_509X.h
 *
 * RSA key generation and X.509 certificate handling built on OpenSSL's libcrypto:
 *   - generate RSA-2048 key pairs
 *   - build X.509 v3 certificates (version, serial, validity, subject/issuer, extensions)
 *   - create a self-signed Certificate Authority (CA) and issue server/client certificates
 *   - save / load certificates and keys in PEM format
 *   - verify a peer certificate against the trusted CA
 */
#ifndef CERT_509X_H
#define CERT_509X_H

#include <openssl/x509.h>
#include <openssl/evp.h>

#define CERT_VALIDITY_DAYS_CA    3650   /* 10 years */
#define CERT_VALIDITY_DAYS_LEAF  365    /*  1 year  */

typedef enum { CERT_ROLE_CA, CERT_ROLE_SERVER, CERT_ROLE_CLIENT } cert_role_t;

/* Key generation */
EVP_PKEY *rsa_key_gen(void);

/* Individual certificate fields (each returns 1 on success, 0 on error) */
int set_cert_version_and_serial(X509 *cert);
int set_cert_validity(X509 *cert, long days);
int set_cert_names(X509 *cert, X509_NAME *subject, X509_NAME *issuer);

/* Interactive prompt for Country / Organization / Common Name. NULL on error. */
X509_NAME *prompt_cert_subject(const char *role_label);

/* Build a complete, signed certificate.
 *   role == CERT_ROLE_CA     : self-signed CA (issuer_cert / issuer_key ignored)
 *   role == CERT_ROLE_SERVER : signed by the CA, may carry subjectAltName entries (e.g. "IP:127.0.0.1")
 *   role == CERT_ROLE_CLIENT : signed by the CA
 */
X509 *build_certificate(cert_role_t role, EVP_PKEY *subject_key, X509_NAME *subject,
                        X509 *issuer_cert, EVP_PKEY *issuer_key, const char *subject_alt_names);

/* PEM file I/O (output_* return 1 on success) */
int       output_cert(const char *filename, X509 *cert);
int       output_private_key(const char *filename, EVP_PKEY *pkey);
X509     *load_cert(const char *filename);
EVP_PKEY *load_private_key(const char *filename);

/* Print a one-line summary of a certificate (subject, issuer, validity). */
void print_cert_summary(const char *label, X509 *cert);

/* Verify a peer certificate:
 *   - it chains to `ca_cert` and the CA signature is valid
 *   - it is inside its validity period
 *   - it is meant for `expected_role` (serverAuth / clientAuth)
 *   - if `expected_ip` is not NULL, the certificate's subjectAltName contains that IP
 * Returns 1 if the certificate is trusted, 0 otherwise (the reason is printed). */
int verify_peer_cert(X509 *peer_cert, X509 *ca_cert, cert_role_t expected_role, const char *expected_ip);

#endif /* CERT_509X_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>


// RSA Key Generation
EVP_PKEY* rsa_key_gen() {
    EVP_PKEY *pkey = NULL;                                                   // pointer to hold the generated key            
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);             // creates a key generation context to hold info for RSA keys
    
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");                  // check for errors in context creation
        return NULL;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation\n");            // check for errors in key generation initialization
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    // Set key length to 2048 bits
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {                  // check for errors in setting key length
        fprintf(stderr, "Failed to set key length\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    // Generate the key
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key\n");                        // check for errors in key generation
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;                                                            // Return the EVP_PKEY structure containing the RSA key pair
}


// set version and serial number
void set_cert_version_and_serial(X509 *cert) {
    int error = 1;

    ASN1_INTEGER *serial = ASN1_INTEGER_new();

    if (!serial) {                                                          // check for errors in serial number creation
        error = 0;
    }

    if (!ASN1_INTEGER_set(serial, 1)) {                                     // set serial number to 1 and check for errors
        ASN1_INTEGER_free(serial);
        error = 0;
    }

    if (!X509_set_serialNumber(cert, serial)) {                             // set the serial number in the certificate
        ASN1_INTEGER_free(serial);
        error = 0;
    }
    
    ASN1_INTEGER_free(serial);
    
    // Set version to 3 (X509v3)
    if (!X509_set_version(cert, 2)) {                                       // Version 2 = X509v3
        error = 0;
    }

    if(error == 0){                                                         // return success
        fprintf(stderr, "Failed to set certificate version and serial number\n");
    }                                                                  
}

// Validity Period
void set_cert_validity(X509 *cert) {
    int error = 1;
    
    ASN1_TIME *not_before = ASN1_TIME_new();                                // create new ASN1_TIME for notBefore
    ASN1_TIME *not_after = ASN1_TIME_new();                                 // create new ASN1_TIME for notAfter

    if (!not_before || !not_after) {                                        // check for errors in time creation
        ASN1_TIME_free(not_before);
        ASN1_TIME_free(not_after);
        error = 0;
    }

    // set notBefore to current time
    if (!X509_gmtime_adj(not_before, 0)) {                                  // check for errors in setting notBefore
        ASN1_TIME_free(not_before);
        ASN1_TIME_free(not_after);
        error = 0;
    }

    // set notAfter to one year from now
    long sec_in_a_year = 60L * 60L * 24L * 365L;
    if (!X509_gmtime_adj(not_after, sec_in_a_year)) {                       // check for errors in setting notAfter
        ASN1_TIME_free(not_before);
        ASN1_TIME_free(not_after);
        error = 0;
    }

    // set notBefore and notAfter in the certificate
    if (!X509_set1_notBefore(cert, not_before) ||                           // check for errors in setting notBefore
        !X509_set1_notAfter(cert, not_after)) {
        ASN1_TIME_free(not_before);
        ASN1_TIME_free(not_after);
        error = 0;
    }

    // free the ASN1_TIME structures
    ASN1_TIME_free(not_before);
    ASN1_TIME_free(not_after);

    if (error == 0) {
        fprintf(stderr, "Failed to set certificate validity period\n");
    }
}

void set_cert_names(X509 *cert) {
    X509_NAME *name = X509_NAME_new();                                      // create a new X509_NAME structure            
    char country[100];
    char org[100];
    char cn[100];
    
    
    if (!name) {                                                            // check for errors in name creation    
        fprintf(stderr, "Failed to create X509_NAME structure\n");
        return;  // Early return - can't continue without name

    }

    printf("  Set certificate Country using 2 letters(e.g. GR): ");                                    // prompt for country
    if (scanf("%99s", country) != 1) {
        fprintf(stderr, "Failed to read country input\n");
        X509_NAME_free(name);
        return;
    }
    
    printf("  Set certificate Organization: ");
    if (scanf("%99s", org) != 1) {
        fprintf(stderr, "Failed to read organization input\n");
        X509_NAME_free(name);
        return;
    }

    printf("  Set certificate Common Name: ");                                // prompt for common name
    if (scanf("%99s", cn) != 1) {
        fprintf(stderr, "Failed to read common name input\n");
        X509_NAME_free(name);
        return;
    }
    
    // Add entries to the name
    int name_status = X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)country, -1, -1, 0);         // 1 for successs, 0 for error
    int org_status = X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)org, -1, -1, 0);
    int cn_status = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0);

    if (!name_status) {
        fprintf(stderr, "Failed to add country to X509_NAME structure\n");
        X509_NAME_free(name);
        return;
    }
    if (!org_status) {
        fprintf(stderr, "Failed to add organization to X509_NAME structure\n");
        X509_NAME_free(name);
        return;
    }
    if (!cn_status) {
        fprintf(stderr, "Failed to add common name to X509_NAME structure\n");
        X509_NAME_free(name);
        return;
    }
    
    if (!X509_set_subject_name(cert, name)) {                                       // Set both subject and issuer (self-signed)
        printf("Failed to set certificate subject name\n");
        X509_NAME_free(name);
        return;
    }
    else if (!X509_set_issuer_name(cert, name)) {
        printf("Failed to set certificate issuer name\n");
        X509_NAME_free(name);
        return;
    }

    X509_NAME_free(name);
}

// Modified output_cert function using BIO
void output_cert(char *filename, X509 *cert) {
    BIO *bio = BIO_new_file(filename, "w");
    if (!bio) {
        fprintf(stderr, "Unable to create BIO for certificate file\n");
        return;
    }
    
    int result = PEM_write_bio_X509(bio, cert);
    BIO_free(bio);
    
    if (!result) {
        fprintf(stderr, "Failed to write certificate to file\n");
    } else {
        printf("\n- Certificate written to %s successfully.\n", filename);
    }
}

// Modified output_private_key function using BIO
void output_private_key(char *filename, EVP_PKEY *pkey) {
    BIO *bio = BIO_new_file(filename, "w");
    if (!bio) {
        fprintf(stderr, "Unable to create BIO for private key file\n");
        return;
    }
    
    int result = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_free(bio);
    
    if (!result) {
        fprintf(stderr, "Failed to write private key to file\n");
    } else {
        printf("- Private key written to %s successfully.\n", filename);
    }
}


// // output the cert info to a file
// void output_cert(char *filename, X509 *cert) {
    
//     FILE *fp = fopen(filename, "wb");
//     if (fp == NULL) {
//         perror("Unable to open file for writing");
//     }
//     int output_result = PEM_write_X509(fp, cert);  // Write the certificate in PEM format
//     fclose(fp);
    
//     if(!output_result){
//         fprintf(stderr, "Failed to write certificate to file\n");  // check for errors in writing the certificate
//     } 
    
//     else {
//         printf("Certificate written to %s successfully.\n", filename);
//     }

// }

// // output the private key to a file
// void output_private_key(char *filename, EVP_PKEY *pkey) {
//     FILE *fp = fopen(filename, "wb");
//     if (fp == NULL) {
//         perror("Unable to open file for writing the key");
//     }

//     int result = PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
//     fclose(fp);

//     if(!result) {
//         fprintf(stderr, "Failed to write private key to file\n");
//     }
//     else {
//         printf("Private key written to %s successfully.\n", filename);
//     }
// }


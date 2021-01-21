#ifndef _RA_COMMON_H_
#define _RA_COMMON_H_

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LIBENCLAVE_TLS_SGX "libenclave-tls-sgx.so"

// function pointer definitions
typedef void (*generate_certificate_func)(RsaKey*, uint8_t*, int*, const struct ra_tls_options*);

// dynamically resolved functions from libraries
typedef struct code_type_function_table {
        generate_certificate_func	generate_certificate;
} code_type_function_table;

/* global function table */
code_type_function_table ctab;

void sha256_rsa_pubkey(unsigned char hash[SHA256_DIGEST_SIZE], RsaKey *key);

#endif

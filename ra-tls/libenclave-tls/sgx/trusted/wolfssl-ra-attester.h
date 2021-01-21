/* Code to create an RA-TLS certificate with wolfSSL. */

#ifndef _WOLFSSL_RA_ATTESTER_H_
#define _WOLFSSL_RA_ATTESTER_H_

#define _GNU_SOURCE // for memmem()

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "ra.h"
#include "ra-attester.h"
#include "ra-attester_private.h"
#include "ra_private.h"

void generate_epid_certificate
(
        RsaKey* genKey,
        uint8_t* der_cert,
        int* der_cert_len,
        const struct ra_tls_options* opts
);

#endif

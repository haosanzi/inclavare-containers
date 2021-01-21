/* *INDENT-OFF* */
#ifndef _WOLFSSL_RA_ATTESTER_COMMON_H_
#define _WOLFSSL_RA_ATTESTER_COMMON_H_
/* *INDENT-ON* */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <stdint.h>

#define REPORT_DATA_SIZE 64

typedef struct report_data_t {
	uint8_t d[REPORT_DATA_SIZE];
} report_data_t;

typedef struct _spid_t {
	uint8_t id[16];
} sgx_spid_t;

typedef enum {
	SGX_UNLINKABLE_SIGNATURE,
	SGX_LINKABLE_SIGNATURE
} sgx_quote_sign_type_t;

struct ra_tls_options {
	sgx_spid_t spid;
	sgx_quote_sign_type_t quote_type;
	/* NULL-terminated string of domain name/IP, port and path prefix,
	   e.g., api.trustedservices.intel.com/sgx/dev for development and
	   api.trustedservices.intel.com/sgx for production. */
	const char ias_server[512];
	const char subscription_key[32];
};

void create_key_and_x509(WOLFSSL_CTX *ctx, const struct ra_tls_options *opts);
void generate_x509(RsaKey *key, uint8_t *der_crt, int *der_crt_len,
		   const struct ra_tls_options *opts);

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */

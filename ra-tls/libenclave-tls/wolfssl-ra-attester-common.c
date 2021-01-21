#include "wolfssl-ra-attester-common.h"
#include <assert.h>
#include "ra-common.h"

void create_key_and_x509(WOLFSSL_CTX *ctx, const struct ra_tls_options *opts)
{
	uint8_t key[2048];
	uint8_t crt[8192];
	int key_len = sizeof(key);
	int crt_len = sizeof(crt);
	wolfssl_create_key_and_x509(key, &key_len, crt, &crt_len, opts);

	int ret =
		wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, key_len,
						  SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);

	ret = wolfSSL_CTX_use_certificate_buffer(ctx, crt, crt_len,
						 SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);
}

void wolfssl_create_key_and_x509(uint8_t *der_key, int *der_key_len,
				 uint8_t *der_cert, int *der_cert_len,
				 const struct ra_tls_options *opts)
{
	/* Generate key. */
	RsaKey genKey;
	RNG rng;
	int ret;

	wc_InitRng(&rng);
	wc_InitRsaKey(&genKey, 0);
	ret = wc_MakeRsaKey(&genKey, 3072, 65537, &rng);
	assert(ret == 0);

	uint8_t der[4096];
	int derSz = wc_RsaKeyToDer(&genKey, der, sizeof(der));
	assert(derSz >= 0);
	assert(derSz <= (int) *der_key_len);

	*der_key_len = derSz;
	memcpy(der_key, der, derSz);

	ctab.generate_certificate(&genKey, der_cert, der_cert_len, opts);
}

void generate_x509(RsaKey *key, uint8_t *der_crt, int *der_crt_len,
		   const struct ra_tls_options *opts)
{
	report_data_t report_data = { 0, };
	sha256_rsa_pubkey(report_data.d, key);

	Cert crt;
	wc_InitCert(&crt);

	RNG rng;
	wc_InitRng(&rng);

	int certSz = wc_MakeSelfCert(&crt, der_crt, *der_crt_len, key, &rng);
	assert(certSz > 0);
	*der_crt_len = certSz;
}

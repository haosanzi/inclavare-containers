#define _GNU_SOURCE		// for memmem()

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/rsa.h>

static const int rsa_3072_der_len = 1766;
static const int rsa_pub_3072_pcks_der_len = 422;
static const int rsa_pub_3072_pcks_header_len = 24;
static const int rsa_pub_3072_raw_der_len = 398;	/* rsa_pub_3072_pcks_der_len - pcks_nr_1_header_len */

void sha256_rsa_pubkey(unsigned char hash[SHA256_DIGEST_SIZE], RsaKey *key)
{
	// Expect a 3072 bit RSA key.
	assert(key->n.used == 48 /* == 3072 / 8 / 8 */ );

	uint8_t buf[1024];
	/* SetRsaPublicKey() only exports n and e without wrapping them in
	   additional ASN.1 (PKCS#1). */
	int pub_rsa_key_der_len = SetRsaPublicKey(buf, key, sizeof(buf), 0);
	assert(pub_rsa_key_der_len == rsa_pub_3072_raw_der_len);

	Sha256 sha;
	wc_InitSha256(&sha);
	wc_Sha256Update(&sha, buf, pub_rsa_key_der_len);
	wc_Sha256Final(&sha, hash);
}

#define _GNU_SOURCE		// for memmem()

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <wolfssl/wolfcrypt/rsa.h>
#include "wolfssl-ra-common.h"
#include "ra-common.h"

#if SGX_SDK
/* SGX SDK does not have this. */
void *memmem(const void *h0, size_t k, const void *n0, size_t l);
#endif

/**
 * @return Returns -1 if OID not found. Otherwise, returns 1;
 */
int find_oid(const unsigned char *ext, size_t ext_len, const unsigned char *oid,
	     size_t oid_len, unsigned char **val, size_t *len)
{
	uint8_t *p = memmem(ext, ext_len, oid, oid_len);
	if (p == NULL) {
		return -1;
	}

	p += oid_len;

	int i = 0;

	// Some TLS libraries generate a BOOLEAN for the criticality of the extension.
	if (p[i] == 0x01) {
		assert(p[i++] == 0x01);	// tag, 0x01 is ASN1 Boolean
		assert(p[i++] == 0x01);	// length
		assert(p[i++] == 0x00);	// value (0 is non-critical, non-zero is critical)
	}

	// Now comes the octet string
	assert(p[i++] == 0x04);	// tag for octet string
	assert(p[i++] == 0x82);	// length encoded in two bytes
	*len = p[i++] << 8;
	*len += p[i++];
	*val = &p[i++];

	return 1;
}

/**
 * @return Returns -1 if OID was not found. Otherwise, returns 1;
 */
int extract_x509_extension(const uint8_t *ext, int ext_len,
			   const uint8_t *oid, size_t oid_len, uint8_t *data,
			   uint32_t *data_len, uint32_t data_max_len)
{
	uint8_t *ext_data;
	size_t ext_data_len;

	int rc = find_oid(ext, ext_len, oid, oid_len, &ext_data, &ext_data_len);
	if (rc == -1)
		return -1;

	assert(ext_data != NULL);
	assert(ext_data_len <= data_max_len);
	memcpy(data, ext_data, ext_data_len);
	*data_len = ext_data_len;

	return 1;
}

typedef void (*printf_identity_func)(unsigned char *, int);

void printf_identity(unsigned char *der, int derSz)
{
	printf("Peer's identity:\n");

	// Even host is not SGX platform, it still can get quote
	// infomation form epid cert as long as install dynamic library. 
	// In addition, need add oid in cert to identify the certificate type.
	if (derSz > 3000) {
		void *handle = dlopen(LIBENCLAVE_TLS_SGX, RTLD_LAZY);
		if (NULL == handle) {
			printf("open error:%s\n", dlerror());
		}
		printf_identity_func printf_identity =
			dlsym(handle, "printf_identity_sgx");
		printf_identity(der, derSz);
		dlclose(handle);
	}
}

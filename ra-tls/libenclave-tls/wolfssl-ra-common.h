/* *INDENT-OFF* */
#ifndef _WOLFSSL_RA_COMMON_H_
#define _WOLFSSL_RA_COMMON_H_
/* *INDENT-ON* */

int extract_x509_extension(const uint8_t * ext, int ext_len,
			   const uint8_t * oid, size_t oid_len, uint8_t * data,
			   uint32_t * data_len, uint32_t data_max_len);
void printf_identity(unsigned char *der, int derSz);

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */

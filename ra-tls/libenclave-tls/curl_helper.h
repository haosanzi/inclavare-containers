/* *INDENT-OFF* */
#ifndef _CURL_H_
#define _CURL_H_
/* *INDENT-ON* */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#if defined(USE_OPENSSL)
#  include <openssl/evp.h>	// for base64 encode/decode
#elif defined(USE_WOLFSSL)
#  include <wolfssl/options.h>
#  include <wolfssl/wolfcrypt/coding.h>
#elif defined(USE_MBEDTLS)
#  include <mbedtls/base64.h>
#else
#  error Must use one of OpenSSL/wolfSSL/mbedtls
#endif

struct buffer_and_size {
	char *data;
	size_t len;
};

void http_get(CURL *curl, const char *url, struct buffer_and_size *header,
	      struct buffer_and_size *body, struct curl_slist *request_headers,
	      char *request_body);

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */

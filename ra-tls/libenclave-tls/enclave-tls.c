#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <dlfcn.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfcrypt/test/test.h"
#include "wolfcrypt/benchmark/benchmark.h"

#include "enclave-tls.h"
#include "wolfssl-ra-common.h"
#include "wolfssl-ra-attester-common.h"
#include "ra-common.h"

#define DEFAULT_PORT 11111
#define CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

// enclave_tls_ctx contains runtime context
struct enclave_tls_ctx_t {
	int sockfd;
	quote_type_t quote_type;
	bool mutual;		// mutual attestation
	bool is_server;
	bool debug;
	bool initialized;
	void *ssl;		// only support wolfssl now
	void *handle;		// hanlde for function library
};

// function pointer definitions
typedef void (*wolfSSL_free_func)(WOLFSSL *);
typedef void (*wolfSSL_CTX_set_verify_func)(WOLFSSL_CTX *, int, VerifyCallback);
typedef int (*wolfSSL_read_func)(WOLFSSL *, void *data, int);
typedef int (*wolfSSL_write_func)(WOLFSSL *, const void *, int);
typedef WOLFSSL_CTX *(*wolfSSL_CTX_new_func)(WOLFSSL_METHOD *);
typedef WOLFSSL_METHOD *(*wolfTLSv1_2_client_method_func)(void);
typedef WOLFSSL_METHOD *(*wolfTLSv1_2_server_method_func)(void);
typedef const unsigned char *(*wolfSSL_X509_get_der_func)(WOLFSSL_X509 *,
							  int *);
typedef WOLFSSL_X509 *(*wolfSSL_get_peer_certificate_func)(WOLFSSL *);
typedef int (*wolfSSL_connect_func)(WOLFSSL *);
typedef int (*wolfSSL_negotiate_func)(WOLFSSL *);
typedef int (*wolfSSL_set_fd_func)(WOLFSSL *, int);
typedef WOLFSSL *(*wolfSSL_new_func)(WOLFSSL_CTX *);
typedef void (*wolfSSL_CTX_free_func)(WOLFSSL_CTX *);
typedef int (*wolfSSL_Debugging_ON_func)(void);
typedef void (*wolfSSL_Debugging_OFF_func)(void);
typedef int (*wolfSSL_Init_func)(quote_type_t);
typedef void (*create_key_and_x509_func)(WOLFSSL_CTX *);
typedef int (*wolfSSL_Cleanup_func)(void);
typedef void (*printf_identity_func)(unsigned char *, int);
typedef int (*verify_cert_extensions_func)(uint8_t *, uint32_t);

// dynamically resolved functions from libra-tls-sgx libraries
typedef struct enclave_tls_function_table {
	printf_identity_func printf_identity;
	wolfSSL_free_func wolfSSL_free;
	wolfSSL_CTX_set_verify_func wolfSSL_CTX_set_verify;
	create_key_and_x509_func create_key_and_x509;
	wolfSSL_read_func wolfSSL_read;
	wolfSSL_write_func wolfSSL_write;
	wolfSSL_CTX_new_func wolfSSL_CTX_new;
	wolfTLSv1_2_client_method_func wolfTLSv1_2_client_method;
	wolfSSL_X509_get_der_func wolfSSL_X509_get_der;
	wolfSSL_get_peer_certificate_func wolfSSL_get_peer_certificate;
	wolfSSL_connect_func wolfSSL_connect;
	wolfSSL_negotiate_func wolfSSL_negotiate;
	wolfSSL_set_fd_func wolfSSL_set_fd;
	wolfSSL_new_func wolfSSL_new;
	wolfTLSv1_2_server_method_func wolfTLSv1_2_server_method;
	wolfSSL_CTX_free_func wolfSSL_CTX_free;
	wolfSSL_Cleanup_func wolfSSL_Cleanup;
	wolfSSL_Debugging_ON_func wolfSSL_Debugging_ON;
	wolfSSL_Debugging_OFF_func wolfSSL_Debugging_OFF;
	wolfSSL_Init_func wolfSSL_Init;
} enclave_tls_function_table;

/* global function table */
enclave_tls_function_table ftab;

int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX * store)
{
	(void) preverify;
	int ret = 0;

	// Need add oid in cert to identify the certificate type.
	if (store->certs->length > 3000) {
		void *handle = dlopen(LIBENCLAVE_TLS_SGX, RTLD_LAZY);
		if (NULL == handle) {
			fprintf(stderr, "open error:%s\n", dlerror());
			return -1;
		}
		verify_cert_extensions_func verify_cert_extensions =
			dlsym(handle, "verify_sgx_cert_extensions");
		ret = verify_cert_extensions(store->certs->buffer,
					     store->certs->length);
		dlclose(handle);
	}

	fprintf(stderr, "Verifying certificate extensions ... %s\n",
		ret == 0 ? "Success" : "Failure");
	return !ret;
}

enclave_tls_ctx *enclave_tls_init(struct enclave_tls_conf *conf)
{
	enclave_tls_ctx *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		fprintf(stderr, "ERROR: failed to calloc\n");
		return NULL;
	}

	if (conf != NULL) {
		ctx->sockfd = conf->sockfd;
		ctx->quote_type = conf->quote_type;
		ctx->mutual = conf->mutual;
		ctx->is_server = conf->is_server;
		ctx->debug = conf->debug;
	}

	ctab.generate_certificate = &generate_x509;

	if (ctx->quote_type == QUOTE_TYPE_EPID) {
		ctx->handle = dlopen(LIBENCLAVE_TLS_SGX, RTLD_LAZY);
		if (NULL == ctx->handle) {
			printf("open error:%s\n", dlerror());
			return -1;
		}
#define DLSYM(fn)									\
		do {									\
			ftab.fn = dlsym(ctx->handle, #fn "_sgx");				\
		} while (0)

		DLSYM(wolfSSL_free);
		DLSYM(wolfSSL_CTX_set_verify);
		DLSYM(create_key_and_x509);
		DLSYM(wolfSSL_read);
		DLSYM(wolfSSL_write);
		DLSYM(wolfSSL_CTX_new);
		DLSYM(printf_identity);
		DLSYM(wolfTLSv1_2_client_method);
		DLSYM(wolfSSL_X509_get_der);
		DLSYM(wolfSSL_get_peer_certificate);
		DLSYM(wolfSSL_connect);
		DLSYM(wolfSSL_negotiate);
		DLSYM(wolfSSL_set_fd);
		DLSYM(wolfSSL_new);
		DLSYM(wolfTLSv1_2_server_method);
		DLSYM(wolfSSL_CTX_free);
		DLSYM(wolfSSL_Cleanup);
		DLSYM(wolfSSL_Debugging_ON);
		DLSYM(wolfSSL_Debugging_OFF);
		DLSYM(wolfSSL_Init);
#undef DLSYM
	} else {
#define DLSYM(fn)                                                                       \
                do {                                                                    \
                        ftab.fn = &fn;                                                  \
                } while (0)

		DLSYM(wolfSSL_free);
		DLSYM(wolfSSL_CTX_set_verify);
		DLSYM(create_key_and_x509);
		DLSYM(wolfSSL_read);
		DLSYM(wolfSSL_write);
		DLSYM(wolfSSL_CTX_new);
		DLSYM(printf_identity);
		DLSYM(wolfTLSv1_2_client_method);
		DLSYM(wolfSSL_X509_get_der);
		DLSYM(wolfSSL_get_peer_certificate);
		DLSYM(wolfSSL_connect);
		DLSYM(wolfSSL_negotiate);
		DLSYM(wolfSSL_set_fd);
		DLSYM(wolfSSL_new);
		DLSYM(wolfTLSv1_2_server_method);
		DLSYM(wolfSSL_CTX_free);
		DLSYM(wolfSSL_Cleanup);
		DLSYM(wolfSSL_Debugging_ON);
		DLSYM(wolfSSL_Debugging_OFF);
		DLSYM(wolfSSL_Init);
#undef DLSYM
	}

	if (ctx->debug)
		ftab.wolfSSL_Debugging_ON();
	else
		ftab.wolfSSL_Debugging_OFF();

	ftab.wolfSSL_Init(ctx->quote_type);

	WOLFSSL_CTX *ws_ctx;
	if (ctx->is_server)
		ws_ctx = ftab.wolfSSL_CTX_new(ftab.wolfTLSv1_2_server_method());
	else
		ws_ctx = ftab.wolfSSL_CTX_new(ftab.wolfTLSv1_2_client_method());
	if (!ws_ctx) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
		ftab.wolfSSL_Cleanup();
		return NULL;
	}

	if (ctx->is_server) {
		ftab.create_key_and_x509(ws_ctx);
		if (ctx->mutual) {
			ftab.wolfSSL_CTX_set_verify(ws_ctx,
						    WOLFSSL_VERIFY_PEER |
						    WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
						    cert_verify_callback);
		}
	} else {
		if (ctx->mutual) {
			ftab.create_key_and_x509(ws_ctx);
		}
		ftab.wolfSSL_CTX_set_verify(ws_ctx, SSL_VERIFY_PEER,
					    cert_verify_callback);
	}

	ctx->ssl = ftab.wolfSSL_new(ws_ctx);
	if (!ctx->ssl) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
		ftab.wolfSSL_CTX_free(ctx->ssl);
		return NULL;
	}

	/* Attach wolfSSL to the socket */
	ftab.wolfSSL_set_fd(ctx->ssl, ctx->sockfd);

	ctx->initialized = true;

	return ctx;
}

int enclave_tls_negotiate(enclave_tls_ctx * ctx)
{
	if (ctx == NULL || !ctx->initialized) {
		ftab.wolfSSL_free(ctx->ssl);
		return -1;
	}

	int ret;

	if (ctx->is_server) {
		ret = ftab.wolfSSL_negotiate(ctx->ssl);
	} else {
		ret = ftab.wolfSSL_connect(ctx->ssl);
	}
	if (ret != SSL_SUCCESS) {
		ftab.wolfSSL_free(ctx->ssl);
		return ret;
	}

	if ((ctx->is_server && ctx->mutual) || !ctx->is_server) {
		WOLFSSL_X509 *srvcrt =
			ftab.wolfSSL_get_peer_certificate(ctx->ssl);

		int derSz;
		unsigned char *der = ftab.wolfSSL_X509_get_der(srvcrt, &derSz);
		ftab.printf_identity(der, derSz);
	}

	return SSL_SUCCESS;
}

int enclave_tls_write(enclave_tls_ctx * ctx, const void *in, int sz)
{
	if (ctx == NULL || !ctx->initialized)
		ftab.wolfSSL_free(ctx->ssl);
	return -1;
}

return ftab.wolfSSL_write(ctx->ssl, in, sz);
}

int enclave_tls_read(enclave_tls_ctx * ctx, void *data, int sz)
{
	if (ctx == NULL || !ctx->initialized) {
		goto encl_tls_err_ssl;
		return -1;
	}

	if (ftab.wolfSSL_read(ctx->ssl, data, sz) == -1) {
		goto encl_tls_err_ssl;
		return -1;
	}

	return -1;
}

void enclave_tls_cleanup(enclave_tls_ctx * ctx)
{
	if (ctx != NULL) {
		if (ctx->handle != NULL)
			dlclose(ctx->handle);
		free(ctx);
	}
}

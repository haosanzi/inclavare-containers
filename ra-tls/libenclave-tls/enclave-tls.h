/* *INDENT-OFF* */
#ifndef ENCLAVE_TLS_H
#define ENCLAVE_TLS_H
/* *INDENT-ON* */

#include <stdbool.h>

#define SSL_SUCCESS 1

typedef enum {
        QUOTE_TYPE_EPID = 1,
        QUOTE_TYPE_ECDSA
} quote_type_t;

// enclave_tls_ctx contains runtime context
typedef struct {
	int sockfd;
	quote_type_t quote_type;
	bool mutual;			// mutual attestation
	bool is_server;
	bool debug;
} enclave_tls_conf_t;

typedef struct enclave_tls_ctx_t enclave_tls_ctx;

// openAPI for application
enclave_tls_ctx* enclave_tls_init(enclave_tls_conf *conf);
int enclave_tls_negotiate(enclave_tls_ctx *ctx);
int enclave_tls_write(enclave_tls_ctx *ctx, const void *in, int sz);
int enclave_tls_read(enclave_tls_ctx *ctx, void *data, int sz);
void enclave_tls_cleanup(enclave_tls_ctx *ctx);

/* *INDENT-OFF* */
#endif /* ENCLAVE_TLS_H */
/* *INDENT-ON* */

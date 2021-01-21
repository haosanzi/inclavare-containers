#include <assert.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Wolfssl_Enclave_t.h"

#include "sgx_trts.h"

#include "wolfssl-ra-attester.h"
#include "../libenclave-tls/ra-common.h"

int wc_test(void* args)
{
#ifdef HAVE_WOLFSSL_TEST
	return wolfcrypt_test(args);
#else
    /* wolfSSL test not compiled in! */
    return -1;
#endif /* HAVE_WOLFSSL_TEST */
}

int wc_benchmark_test(void* args)
{

#ifdef HAVE_WOLFSSL_BENCHMARK
    return benchmark_test(args);
#else
    /* wolfSSL benchmark not compiled in! */
    return -1;
#endif /* HAVE_WOLFSSL_BENCHMARK */
}

void enc_wolfSSL_Debugging_ON(void)
{
    wolfSSL_Debugging_ON();
}

void enc_wolfSSL_Debugging_OFF(void)
{
    wolfSSL_Debugging_OFF();
}

int enc_wolfSSL_Init(quote_type_t quote_type)
{
    if (quote_type == QUOTE_TYPE_EPID) {
	ctab.generate_certificate = &generate_epid_certificate;
    }
    return wolfSSL_Init();
}

WOLFSSL_METHOD* enc_wolfTLSv1_2_client_method(void)
{
    return wolfTLSv1_2_client_method();
}

WOLFSSL_METHOD* enc_wolfTLSv1_2_server_method(void)
{
    return wolfTLSv1_2_server_method();
}


WOLFSSL_CTX* enc_wolfSSL_CTX_new(WOLFSSL_METHOD* method)
{
    if(sgx_is_within_enclave(method, wolfSSL_METHOD_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_new(method);
}

static int ssl_ctx_set_verify_callback(int mode, WOLFSSL_X509_STORE_CTX *store)
{
    (void)mode;
    int result;
    int ret = ocall_verify_sgx_cert_extensions(&result, store->certs->buffer, store->certs->length);
    return !ret;
}

void enc_wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_GetObjectSize()) != 1)
        abort();

    int (*cb)(int, WOLFSSL_X509_STORE_CTX*);
    cb = ssl_ctx_set_verify_callback;
    wolfSSL_CTX_set_verify(ctx, mode, cb);
}

int enc_wolfSSL_negotiate (WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_negotiate(ssl);
}

WOLFSSL_X509* enc_wolfSSL_get_peer_certificate(WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_get_peer_certificate(ssl);
}

unsigned char* enc_wolfSSL_X509_get_der(WOLFSSL_X509* x509, int* outSz) {
    if(sgx_is_within_enclave(x509, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_X509_get_der(x509, outSz);
}

void encl_get_der_content(char* source, char* buf, size_t len)
{
    memcpy(buf, source, len);
}

int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx,
        const unsigned char* buf, long sz, int type)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx,
        const unsigned char* buf, long sz, int type)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_use_certificate_buffer(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf,
                                            long sz, int type)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_use_PrivateKey_buffer(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
                                       long sz, int format)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_load_verify_buffer(ctx, in, sz, format);
}

int enc_wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list) {
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_set_cipher_list(ctx, list);
}

WOLFSSL* enc_wolfSSL_new( WOLFSSL_CTX* ctx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_new(ctx);
}

int enc_wolfSSL_set_fd(WOLFSSL* ssl, int fd)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_set_fd(ssl, fd);
}

int enc_wolfSSL_connect(WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_connect(ssl);
}

int enc_wolfSSL_write(WOLFSSL* ssl, const void* in, int sz)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_write(ssl, in, sz);
}

int enc_wolfSSL_get_error(WOLFSSL* ssl, int ret)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_get_error(ssl, ret);
}

int enc_wolfSSL_read(WOLFSSL* ssl, void* data, int sz)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_read(ssl, data, sz);
}

void enc_wolfSSL_free(WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    wolfSSL_free(ssl);
}

void enc_wolfSSL_CTX_free(WOLFSSL_CTX* ctx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    wolfSSL_CTX_free(ctx);
}

int enc_wolfSSL_Cleanup(void)
{
    wolfSSL_Cleanup();
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return ret;
}

double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}

extern struct ra_tls_options my_ra_tls_options;

void enc_create_key_and_x509(WOLFSSL_CTX* ctx) {
    create_key_and_x509(ctx, &my_ra_tls_options);
}

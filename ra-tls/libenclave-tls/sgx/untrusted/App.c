/* App.c
*
* Copyright (C) 2006-2016 wolfSSL Inc.
*
* This file is part of wolfSSL.
*
* wolfSSL is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* wolfSSL is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/

#include "stdafx.h"
#include "App.h"		/* contains include of Enclave_u.h which has wolfSSL header files */

/* Use Debug SGX ? */
#if _DEBUG
#  define DEBUG_VALUE SGX_DEBUG_FLAG
#else
#  define DEBUG_VALUE 1
#endif

int ret;
int sgxStatus;
sgx_enclave_id_t eid;

static double current_time()
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (double) (1000000 * tv.tv_sec + tv.tv_usec) / 1000000.0;
}

void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate 
	 * the input string to prevent buffer overflow. 
	 */
	printf("%s", str);
}

void ocall_current_time(double *time)
{
	if (!time)
		return;

	*time = current_time();

	return;
}

void ocall_low_res_time(int *time)
{
	if (!time)
		return;

	struct timeval tv;
	*time = tv.tv_sec;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
	return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
	return send(sockfd, buf, len, flags);
}

sgx_enclave_id_t load_enclave(void)
{
	sgx_launch_token_t t;
	memset(t, 0, sizeof(t));

	sgx_enclave_id_t id;
	int updated = 0;
	int ret =
		sgx_create_enclave("Wolfssl_Enclave.signed.so", 1, &t, &updated,
				   &id, NULL);
	if (ret != SGX_SUCCESS) {
		fprintf(stderr, "Failed to create Enclave: error %d\n", ret);
		return -1;
	}

	return id;
}

int wolfSSL_Debugging_ON_sgx()
{
	enc_wolfSSL_Debugging_ON(eid);
}

void wolfSSL_Debugging_OFF_sgx()
{
	enc_wolfSSL_Debugging_OFF(eid);
}

int wolfSSL_Init_sgx(quote_type_t quote_type)
{
	eid = load_enclave();
	sgxStatus = enc_wolfSSL_Init(eid, &ret, quote_type);
	if (sgxStatus != SGX_SUCCESS || ret != WOLFSSL_SUCCESS)
		return -1;
	return WOLFSSL_SUCCESS;
}

WOLFSSL_METHOD *wolfTLSv1_2_client_method_sgx()
{
	WOLFSSL_METHOD *method;
	sgxStatus = enc_wolfTLSv1_2_client_method(eid, &method);
	if (sgxStatus != SGX_SUCCESS || !method)
		return NULL;
	return method;
}

WOLFSSL_METHOD *wolfTLSv1_2_server_method_sgx()
{
	WOLFSSL_METHOD *method;
	sgxStatus = enc_wolfTLSv1_2_server_method(eid, &method);
	if (sgxStatus != SGX_SUCCESS || !method)
		return NULL;
	return method;
}

void create_key_and_x509_sgx(WOLFSSL_CTX *ctx)
{
	sgxStatus = enc_create_key_and_x509(eid, ctx);
	if (sgxStatus != SGX_SUCCESS)
		fprintf(stderr, "ERROR: failed to create key and X509\n");
}

const unsigned char *wolfSSL_X509_get_der_sgx(WOLFSSL_X509 *srvcrt, int *outSz)
{
	const unsigned char *der;
	sgxStatus = enc_wolfSSL_X509_get_der(eid, &der, srvcrt, outSz);
	if (sgxStatus != SGX_SUCCESS) {
		fprintf(stderr, "ERROR: failed to get X509 struct\n");
		return NULL;
	}
	const unsigned char *buf = malloc(*outSz);
	sgxStatus = encl_get_der_content(eid, der, buf, *outSz);
	if (sgxStatus != SGX_SUCCESS) {
		fprintf(stderr, "ERROR: failed to get der content\n");
	}
	return buf;
}

int wolfSSL_write_sgx(WOLFSSL *ssl, const void *in, int sz)
{
	sgxStatus = enc_wolfSSL_write(eid, &ret, ssl, in, sz);
	if (sgxStatus != SGX_SUCCESS || ret != sz) {
		fprintf(stderr, "ERROR: failed to write\n");
		return -1;
	}
}

WOLFSSL_X509 *wolfSSL_get_peer_certificate_sgx(WOLFSSL *ssl)
{
	WOLFSSL_X509 *srvcrt;
	sgxStatus = enc_wolfSSL_get_peer_certificate(eid, &srvcrt, ssl);
	if (sgxStatus != SGX_SUCCESS) {
		fprintf(stderr, "ERROR: failed to get peer certificate\n");
		return NULL;
	}
	return srvcrt;
}

int wolfSSL_negotiate_sgx(WOLFSSL *ssl)
{
	sgxStatus = enc_wolfSSL_negotiate(eid, &ret, ssl);
	if (sgxStatus != SGX_SUCCESS || ret != WOLFSSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to negotiate to wolfSSL\n");
		return -1;
	}
	return WOLFSSL_SUCCESS;
}

int wolfSSL_connect_sgx(WOLFSSL *ssl)
{
	sgxStatus = enc_wolfSSL_connect(eid, &ret, ssl);
	if (sgxStatus != SGX_SUCCESS || ret != WOLFSSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
		return -1;
	}
	return WOLFSSL_SUCCESS;
}

int wolfSSL_set_fd_sgx(WOLFSSL *ssl, int fd)
{
	sgxStatus = enc_wolfSSL_set_fd(eid, &ret, ssl, fd);
	if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
		return -1;
	}
	return WOLFSSL_SUCCESS;
}

WOLFSSL *wolfSSL_new_sgx(WOLFSSL_CTX *ctx)
{
	WOLFSSL *ssl;
	sgxStatus = enc_wolfSSL_new(eid, &ssl, ctx);
	if (sgxStatus != SGX_SUCCESS || !ssl) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
		return NULL;
	}
	return ssl;
}

int wolfSSL_CTX_set_verify_sgx(WOLFSSL_CTX *ctx, int mode)
{
	sgxStatus = enc_wolfSSL_CTX_set_verify(eid, ctx, mode);
	if (sgxStatus != SGX_SUCCESS || !ctx) {
		return -1;
	}
	return WOLFSSL_SUCCESS;
}

int wolfSSL_read_sgx(WOLFSSL *ssl, void *data, int sz)
{
	sgxStatus = enc_wolfSSL_read(eid, &ret, ssl, data, sz);
	if (sgxStatus != SGX_SUCCESS || ret == -1) {
		fprintf(stderr, "ERROR: failed to read %d : %d\n", ret, sz);
		return -1;
	}
}

WOLFSSL_CTX *wolfSSL_CTX_new_sgx(WOLFSSL_METHOD *method)
{
	WOLFSSL_CTX *ctx;
	sgxStatus = enc_wolfSSL_CTX_new(eid, &ctx, method);
	if (sgxStatus != SGX_SUCCESS || !ctx)
		return NULL;
	return ctx;
}

void printf_identity_sgx(unsigned char *der, int derSz)
{
	sgx_quote_t quote;
	get_quote_from_cert(der, derSz, &quote);
	sgx_report_body_t *body = &quote.report_body;
	printf("Peer's SGX identity:\n");
	printf("  . MRENCLAVE = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i)
		printf("%02x", body->mr_enclave.m[i]);
	printf("\n");

	printf("  . MRSIGNER  = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i)
		printf("%02x", body->mr_signer.m[i]);
	printf("\n");
}

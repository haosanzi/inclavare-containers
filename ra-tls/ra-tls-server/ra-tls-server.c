#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ra-tls-server.h"

#define DEFAULT_PORT 11111

#define CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

int ra_tls_server_startup(int connd, quote_type_t quote_type, bool mutual, bool debug)
{
	int ret;
	enclave_tls_conf conf = { connd, quote_type, mutual, true, debug};

	enclave_tls_ctx *ctx = enclave_tls_init(&conf);
	if (ctx == NULL) {
		fprintf(stderr, "ERROR: failed to initialization.\n");
	}

	ret = enclave_tls_negotiate(ctx);
	if (ret != SSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to negotiate.\n");
	}

	printf("Client connected successfully\n");

	char buff[256];
	size_t len;
	memset(buff, 0, sizeof(buff));

	if (enclave_tls_read(ctx, buff, sizeof(buff) - 1) == -1) {
		fprintf(stderr, "ERROR: failed to read.\n");
	}

	printf("Client: %s\n", buff);

	/* Write our reply into buff */
	memset(buff, 0, sizeof(buff));
	memcpy(buff, "I hear ya fa shizzle!\n", sizeof(buff));
	len = strnlen(buff, sizeof(buff));

	/* Reply back to the client */
	if (enclave_tls_write(ctx, buff, len) != (int) len) {
		fprintf(stderr, "ERROR: failed to write.\n");
	}

	enclave_tls_cleanup(ctx);

	return 0;
}

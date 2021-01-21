#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ra-tls-client.h"

int ra_tls_echo(int sockfd, quote_type_t quote_type, bool mutual, bool debug)
{
	int ret;
	enclave_tls_conf conf = { sockfd, quote_type, mutual, false, debug};

	enclave_tls_ctx *ctx = enclave_tls_init(&conf);
	if (ctx == NULL) {
		fprintf(stderr, "ERROR: failed to initialization.\n");
	}

	ret = enclave_tls_negotiate(ctx);
	if (ret != SSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to negotiate.\n");
	}

	const char *http_request = "GET / HTTP/1.0\r\n\r\n";
	size_t len = strlen(http_request);
	if (enclave_tls_write(ctx, http_request, len) != (int) len) {
		fprintf(stderr, "ERROR: failed to write.\n");
	}

	char buff[256];
	memset(buff, 0, sizeof(buff));
	if (enclave_tls_read(ctx, buff, sizeof(buff) - 1) == -1) {
		fprintf(stderr, "ERROR: failed to read.\n");
	}
	printf("Server:\n%s\n", buff);

	enclave_tls_cleanup(ctx);

	return 0;
}

#include <stdio.h>
#include <string.h>
#include "sgx_urts.h"

/* socket includes */
#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h>

extern int ra_tls_server_startup(sgx_enclave_id_t id, int sockfd);

static sgx_enclave_id_t load_enclave(void)
{
        sgx_launch_token_t t;
        memset(t, 0, sizeof(t));

        sgx_enclave_id_t id;
        int updated = 0;
        int ret = sgx_create_enclave("Wolfssl_Enclave.signed.so", 1, &t, &updated, &id, NULL);
        if (ret != SGX_SUCCESS) {
                fprintf(stderr, "Failed to create Enclave: error %d\n", ret);
                return -1;
        }

        return id;
}

int main(){

	sgx_enclave_id_t eid;
	eid = load_enclave();

	const char *SOCKNAME = "/run/rune/ra-tls.sock";
	int sockfd;
	int connd;
	struct sockaddr_un servAddr;
	
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("Failed to create the socket.");
		return -1;
	}

	/* Initialize the server address struct with zeros */
	memset(&servAddr, 0, sizeof(servAddr));
	/* Fill in the server address */
	servAddr.sun_family = AF_UNIX;
	strncpy(servAddr.sun_path, SOCKNAME, sizeof(servAddr.sun_path)-1);
	
	/* Bind the server socket*/
	if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
		perror("Failed to bind.");
		return -1;
	}

	/* Listen for a new connection, allow 5 pending connections */
	if (listen(sockfd, 5) == -1) {
		perror("Failed to listen.");
		return -1;
	}

	printf("Waiting for a connection...\n");
	
	/* Accept client connections */
	if ((connd = accept(sockfd, NULL, NULL)) == -1) {
		perror("Failed to accept the connection.");
		return -1;
	}

	ra_tls_server_startup(eid, connd);
	
	return 0;
}


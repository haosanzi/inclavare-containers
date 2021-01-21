#ifndef RA_TLS_CLIENT_H
#define RA_TLS_CLIENT_H

#include "enclave-tls.h"

int ra_tls_echo(int sockfd, quote_type_t quote_type, bool mutual);

#endif /* RA_TLS_CLIENT_H */

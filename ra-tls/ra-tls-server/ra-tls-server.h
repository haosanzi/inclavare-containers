#ifndef RA_TLS_SERVER_H
#define RA_TLS_SERVER_H

#include "enclave-tls.h"

int ra_tls_server_startup(int connd, quote_type_t quote_type, bool mutual);

#endif /* RA_TLS_SERVER_H */

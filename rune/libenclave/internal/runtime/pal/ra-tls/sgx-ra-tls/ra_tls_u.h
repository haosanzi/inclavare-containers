#ifndef RA_TLS_U_H__
#define RA_TLS_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "ra.h"
#include "ra-attester.h"
#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_SGX_INIT_QUOTE_DEFINED__
#define OCALL_SGX_INIT_QUOTE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_init_quote, (sgx_target_info_t* target_info));
#endif
#ifndef OCALL_REMOTE_ATTESTATION_DEFINED__
#define OCALL_REMOTE_ATTESTATION_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remote_attestation, (sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report));
#endif

sgx_status_t dummy(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

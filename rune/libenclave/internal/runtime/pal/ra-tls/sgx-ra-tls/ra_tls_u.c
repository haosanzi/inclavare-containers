#include "ra_tls_u.h"
#include <errno.h>

typedef struct ms_ocall_sgx_init_quote_t {
	sgx_target_info_t* ms_target_info;
} ms_ocall_sgx_init_quote_t;

typedef struct ms_ocall_remote_attestation_t {
	sgx_report_t* ms_report;
	const struct ra_tls_options* ms_opts;
	attestation_verification_report_t* ms_attn_report;
} ms_ocall_remote_attestation_t;

static sgx_status_t SGX_CDECL ra_tls_ocall_sgx_init_quote(void* pms)
{
	ms_ocall_sgx_init_quote_t* ms = SGX_CAST(ms_ocall_sgx_init_quote_t*, pms);
	ocall_sgx_init_quote(ms->ms_target_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ra_tls_ocall_remote_attestation(void* pms)
{
	ms_ocall_remote_attestation_t* ms = SGX_CAST(ms_ocall_remote_attestation_t*, pms);
	ocall_remote_attestation(ms->ms_report, ms->ms_opts, ms->ms_attn_report);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_ra_tls = {
	2,
	{
		(void*)ra_tls_ocall_sgx_init_quote,
		(void*)ra_tls_ocall_remote_attestation,
	}
};
sgx_status_t dummy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_ra_tls, NULL);
	return status;
}


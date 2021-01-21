/**
 * Code common to all challenger implementations (i.e., independent of
 * the TLS library).
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sgx_quote.h>

#include "ra.h"
#include "ra_private.h"

#if SGX_SDK
/* SGX SDK does not have this. */
void *memmem(const void *h0, size_t k, const void *n0, size_t l);
#endif

#include "ra-challenger_private.h"
#include "ra-challenger.h"

void get_quote_from_extension
(
    const uint8_t* exts,
    size_t exts_len,
    sgx_quote_t* q
)
{
    uint8_t report[2048];
    uint32_t report_len;
    
    int rc = extract_x509_extension(exts, exts_len,
                                    ias_response_body_oid, ias_oid_len,
                                    report, &report_len, sizeof(report));

    if (rc == 1) {
        get_quote_from_report(report, report_len, q);
        return;
    }

    rc = extract_x509_extension(exts, exts_len,
                                quote_oid, ias_oid_len,
                                report, &report_len, sizeof(report));
    //assert(rc == 1);
    memcpy(q, report, sizeof(*q));
}

/**
 * Extract all extensions.
 */
void extract_x509_extensions
(
    const uint8_t* ext,
    int ext_len,
    attestation_verification_report_t* attn_report
)
{
    extract_x509_extension(ext, ext_len,
                           ias_response_body_oid, ias_oid_len,
                           attn_report->ias_report,
                           &attn_report->ias_report_len,
                           sizeof(attn_report->ias_report));

    extract_x509_extension(ext, ext_len,
                           ias_root_cert_oid, ias_oid_len,
                           attn_report->ias_sign_ca_cert,
                           &attn_report->ias_sign_ca_cert_len,
                           sizeof(attn_report->ias_sign_ca_cert));

    extract_x509_extension(ext, ext_len,
                           ias_leaf_cert_oid, ias_oid_len,
                           attn_report->ias_sign_cert,
                           &attn_report->ias_sign_cert_len,
                           sizeof(attn_report->ias_sign_cert));

    extract_x509_extension(ext, ext_len,
                           ias_report_signature_oid, ias_oid_len,
                           attn_report->ias_report_signature,
                           &attn_report->ias_report_signature_len,
                           sizeof(attn_report->ias_report_signature));
}

/**
 * @return 1 if it is an EPID-based attestation RA-TLS
 * certificate. Otherwise, 0.
 */
int is_epid_ratls_cert
(
    const uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    uint8_t* ext_data;
    size_t ext_data_len;
    int rc;

    rc = find_oid(der_crt, der_crt_len,
                  ias_response_body_oid, ias_oid_len,
                  &ext_data, &ext_data_len);
    if (1 == rc) return 1;

    rc = find_oid(der_crt, der_crt_len,
                   quote_oid, ias_oid_len,
                   &ext_data, &ext_data_len);
    if (1 == rc) return 0;

    /* Something is fishy. Neither EPID nor ECDSA RA-TLC cert?! */
    assert(0);
    // Avoid compiler error: control reaches end of non-void function
    // [-Werror=return-type]
    return -1;
}

/**
 * Extract ECDSA related extensions from X509.
 */
void ecdsa_extract_x509_extensions
(
    uint8_t* ext,
    int ext_len,
    ecdsa_attestation_evidence_t* evidence
)
{
    extract_x509_extension(ext, ext_len, quote_oid, ias_oid_len,
                           evidence->quote, &evidence->quote_len,
                           sizeof(evidence->quote));

    extract_x509_extension(ext, ext_len, pck_crt_oid, ias_oid_len,
                           evidence->pck_crt, &evidence->pck_crt_len,
                           sizeof(evidence->pck_crt));

    extract_x509_extension(ext, ext_len, pck_sign_chain_oid, ias_oid_len,
                           evidence->pck_sign_chain, &evidence->pck_sign_chain_len,
                           sizeof(evidence->pck_sign_chain));

    extract_x509_extension(ext, ext_len, tcb_info_oid, ias_oid_len,
                           evidence->tcb_info, &evidence->tcb_info_len,
                           sizeof(evidence->tcb_info));
    
    extract_x509_extension(ext, ext_len, tcb_sign_chain_oid, ias_oid_len,
                           evidence->tcb_sign_chain, &evidence->tcb_sign_chain_len,
                           sizeof(evidence->tcb_sign_chain));

    extract_x509_extension(ext, ext_len, qe_identity_oid, ias_oid_len,
                           evidence->qe_identity, &evidence->qe_identity_len,
                           sizeof(evidence->qe_identity));

    extract_x509_extension(ext, ext_len, root_ca_crl_oid, ias_oid_len,
                           evidence->root_ca_crl, &evidence->root_ca_crl_len,
                           sizeof(evidence->root_ca_crl));

    extract_x509_extension(ext, ext_len, pck_crl_oid, ias_oid_len,
                           evidence->pck_crl, &evidence->pck_crl_len,
                           sizeof(evidence->pck_crl));
}

/**
 * Pretty-print information of EPID-based RA-TLS certificate to file descriptor.
 */
static
void dprintf_epid_ratls_cert
(
    int fd,
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    attestation_verification_report_t report;
    extract_x509_extensions(der_crt, der_crt_len, &report);
    dprintf(fd, "\nIntel Attestation Service Report\n");
    dprintf(fd, "%.*s\n", report.ias_report_len, report.ias_report);
}

/**
 * Pretty-print information of ECDSA-based RA-TLS certificate to file descriptor.
 */
static
void dprintf_ecdsa_ratls_cert
(
    int fd,
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    ecdsa_attestation_evidence_t evidence;
    ecdsa_extract_x509_extensions(der_crt, der_crt_len, &evidence);

    dprintf(fd, "\nTCB info: ");
    dprintf(fd, "%.*s\n", evidence.tcb_info_len, evidence.tcb_info);
    dprintf(fd, "\nPCK Certificate:\n");
    dprintf(fd, "%.*s\n", evidence.pck_crt_len, evidence.pck_crt);
}

void dprintf_ratls_cert
(
    int fd,
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    if (is_epid_ratls_cert(der_crt, der_crt_len)) {
        dprintf_epid_ratls_cert(fd, der_crt, der_crt_len);
    } else {
        dprintf_ecdsa_ratls_cert(fd, der_crt, der_crt_len);
    }

    sgx_quote_t quote;
    get_quote_from_cert(der_crt, der_crt_len, &quote);
    sgx_report_body_t* body = &quote.report_body;

    dprintf(fd, "MRENCLAVE = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) dprintf(fd, "%02x", body->mr_enclave.m[i]);
    dprintf(fd, "\n");
    
    dprintf(fd, "MRSIGNER  = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) dprintf(fd, "%02x", body->mr_signer.m[i]);
    dprintf(fd, "\n");
}

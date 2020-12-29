#include "ra-attester.h"

struct ra_tls_options my_ra_tls_options = {
    // SPID format is 32 hex-character string, e.g., 0123456789abcdef0123456789abcdef
    .spid = {{0x66,0xDB,0x39,0x14,0xB9,0xFB,0x79,0xAC,0x7F,0xF2,0xB3,0xB0,0xF2,0xC5,0x11,0x8F,}},
    .quote_type = SGX_UNLINKABLE_SIGNATURE,
    .ias_server = "api.trustedservices.intel.com/sgx/dev",
    // EPID_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = "510647a662f2498697fa532411b104a8"
};

struct ecdsa_ra_tls_options my_ecdsa_ra_tls_options = {
    // ECDSA_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = ""
};

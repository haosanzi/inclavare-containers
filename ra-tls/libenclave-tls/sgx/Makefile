SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_WOLFSSL_LIB ?= ./

all: libenclave-tls-sgx.so libsgx_ra_tls_wolfssl.a

libenclave-tls-sgx.so:
	$(MAKE) -ef sgx_u.mk all

libsgx_ra_tls_wolfssl.a:
	$(MAKE) -ef sgx_t.mk all

clean:
	$(MAKE) -ef sgx_u.mk clean
	$(MAKE) -ef sgx_t.mk clean

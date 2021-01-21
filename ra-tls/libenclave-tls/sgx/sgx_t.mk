# Makefile to build the wolfSSL-based remote attestation TLS library.

######## Intel(R) SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

TOPDIR = ../..
WOLFSSL_ROOT := $(shell readlink -f $(TOPDIR)/wolfssl)
THISDIR := $(shell pwd)

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_CFLAGS += -O0 -g -ggdb
else
    SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Library_Name := sgx_ra_tls_wolfssl

# -DFP_MAX_BITS=8192 required for RSA keys > 2048 bits to work
Wolfssl_C_Extra_Flags := -DSGX_SDK -DWOLFSSL_SGX -DWOLFSSL_SGX_ATTESTATION -DUSER_TIME -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192

Wolfssl_C_Files := \
	trusted/wolfssl-ra-attester.c \
	trusted/sgxsdk-ra-attester_t.c \
	trusted/ra_tls_t.c \
	trusted/ra_tls_options.c

Wolfssl_Include_Paths := \
	-I$(WOLFSSL_ROOT) \
	-I$(WOLFSSL_ROOT)/wolfcrypt \
	-I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc \
	-I$(SGX_SDK)/include/stlport \
	-I/usr/include/linux

Compiler_Warnings := -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow
Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=default -fpie -fstack-protector $(Wolfssl_Include_Paths) -fno-builtin-printf -I.
Wolfssl_C_Flags := $(Compiler_Warnings) $(Flags_Just_For_C) $(Common_C_Cpp_Flags) $(Wolfssl_C_Extra_Flags)

Wolfssl_C_Objects := $(Wolfssl_C_Files:.c=.o)
CFLAGS += $(Wolfssl_C_Flags)

.PHONY: all run clean mrproper

all: libsgx_ra_tls_wolfssl.a
######## Library Objects ########

trusted/ra_tls_t.c : trusted/ra_tls.edl
	cd ./trusted && $(SGX_EDGER8R) --trusted ra_tls.edl --search-path $(SGX_SDK)/include

trusted/ra-common.o: ../ra-common.c
	$(CC) $(CFLAGS) -c $< -o $@ 

trusted/wolfssl-ra-attester-common.o: ../wolfssl-ra-attester-common.c
	 $(CC) $(CFLAGS) -c $< -o $@

libsgx_ra_tls_wolfssl.a: trusted/ra-common.o trusted/wolfssl-ra-attester-common.o trusted/ra_tls_t.o $(Wolfssl_C_Objects)
	ar rcs $@ $(Wolfssl_C_Objects) trusted/ra-common.o trusted/wolfssl-ra-attester-common.o
	@echo "LINK =>  $@"
	cp libsgx_ra_tls_wolfssl.a $(TOPDIR)/build/lib

trusted/ra_tls_options.c: trusted/ra_tls_options.c.sh
	bash $^ > $@

clean:
	@rm -f $(Wolfssl_C_Objects)
	@rm -f trusted/ra_tls_options.c trusted/ra_tls_t.* trusted/libsgx_ra_tls_wolfssl.a *.a

mrproper: clean
	@rm -f trusted/ra_tls_options.c trusted/ra_tls_t.c trusted/ra_tls_t.h trusted/lib*_ra_tls_wolfssl.a *.a

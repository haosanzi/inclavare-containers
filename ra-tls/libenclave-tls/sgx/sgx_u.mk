######## Intel(R) SGX SDK Settings ########
TOPDIR ?= ../..
LIBDIR ?= $(TOPDIR)/build/lib
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_DEBUG ?= 1
SGX_ARCH ?= x64
WOLFSSL_ROOT ?= $(shell readlink -f $(TOPDIR)/wolfssl)
SGX_WOLFSSL_LIB ?= $(shell readlink -f $(WOLFSSL_ROOT)/IDE/LINUX-SGX)
SGX_RA_TLS_ROOT ?= $(shell readlink -f $(TOPDIR)/libenclave-tls/sgx/trusted)

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g -ggdb -DSGX_DEBUG
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Wolfssl_C_Extra_Flags := -DWOLFSSL_SGX -DUSE_WOLFSSL
Wolfssl_Include_Paths := -I$(WOLFSSL_ROOT) \
	-I$(WOLFSSL_ROOT)/wolfcrypt

ifeq ($(HAVE_WOLFSSL_TEST), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/test
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_TEST
endif

ifeq ($(HAVE_WOLFSSL_BENCHMARK), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/benchmark
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_BENCHMARK
endif

App_C_Files := untrusted/App.c \
	untrusted/ra.c \
	untrusted/sgxsdk-ra-attester_u.c \
	untrusted/ias-ra.c \
	untrusted/wolfssl-ra-challenger.c \
	untrusted/ra-challenger.c \
	untrusted/ias_sign_ca_cert.c
App_Include_Paths := $(Wolfssl_Include_Paths) -I$(SGX_SDK)/include -I$(SGX_RA_TLS_ROOT) -I$(INCDIR) -I$(shell readlink -f .)

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -shared -Wno-attributes -Wall -Wno-unused-const-variable $(App_Include_Paths) $(Wolfssl_C_Extra_Flags)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_C_Objects := $(App_C_Files:.c=.o)

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

HOST_LDFLAGS := -fPIC -shared -Wl,-Bsymbolic

.PHONY: all

all: libenclave-tls-sgx.so

untrusted/Wolfssl_Enclave_u.c: $(SGX_EDGER8R) $(TOPDIR)/stub-enclave/Wolfssl_Enclave.edl
	@cd untrusted && $(SGX_EDGER8R) --untrusted $(TOPDIR)/stub-enclave/Wolfssl_Enclave.edl --search-path $(TOPDIR)/stub-enclave --search-path $(SGX_SDK)/include --search-path $(SGX_RA_TLS_ROOT)
	@echo "GEN  =>  $@"

untrusted/Wolfssl_Enclave_u.o: untrusted/Wolfssl_Enclave_u.c
	@echo $(CC) $(App_C_Flags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

untrusted/%.o: untrusted/%.c
	@echo $(CC) $(App_C_Flags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

libenclave-tls-sgx.so: untrusted/Wolfssl_Enclave_u.o $(App_C_Objects) $(LIBDIR)/libcurl-wolfssl.a $(LIBDIR)/libwolfssl.a
	$(CC) $(HOST_LDFLAGS) -o $@ $^ -lm -lz -lsgx_urts -lsgx_uae_service -L../ -lenclave-tls

.PHONY: clean

clean:
	@rm -f untrusted/libenclave-tls-sgx.so libenclave-tls-sgx.so $(App_C_Objects) untrusted/Wolfssl_Enclave_u.*

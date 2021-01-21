######## Intel(R) SGX SDK Settings ########
TOPDIR ?= ..
LIBDIR ?= $(TOPDIR)/build/lib
INCDIR ?= $(TOPDIR)/build/include
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_DEBUG ?= 1
SGX_ARCH ?= x64
WOLFSSL_ROOT ?= $(shell readlink -f $(TOPDIR)/wolfssl)
SGX_WOLFSSL_LIB ?= $(shell readlink -f $(WOLFSSL_ROOT)/IDE/LINUX-SGX)
SGX_RA_TLS_ROOT ?= $(shell readlink -f $(TOPDIR)/sgx-ra-tls)

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

App_C_Files := enclave-tls.c \
	wolfssl-ra-attester-common.c \
	wolfssl-ra-common.c \
	curl_helper.c \
	ra-common.c

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

.PHONY: all install

all: libenclave-tls.so

%.o: %.c
	@echo $(CC) $(App_C_Flags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

libenclave-tls.so: $(App_C_Objects) $(LIBDIR)/libwolfssl.a $(LIBDIR)/libcurl-wolfssl.a
	$(CC) $(HOST_LDFLAGS) -o $@ $^ -ldl -lm -lz

install:
	cp enclave-tls.h $(INCDIR)
	cp libenclave-tls.so $(LIBDIR)

.PHONY: clean

clean:
	@rm -f libenclave-tls.so $(App_C_Objects)

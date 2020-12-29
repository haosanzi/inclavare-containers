TOPDIR := $(shell readlink -f ..)
DEBUG ?=
EXTRA_FLAGS ?=

PREFIX ?= $(TOPDIR)/build
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
INCDIR := $(PREFIX)/include

SGX_SDK ?= /opt/intel/sgxsdk
SGX_RA_TLS := $(TOPDIR)/sgx-ra-tls

ifdef ECDSA
  SGX_DCAP_URI := https://github.com/intel/SGXDataCenterAttestationPrimitives
  SGX_DCAP_COMMIT := bfab1376480f760757738092399d0d99b22f4dfd
  SGX_DCAP ?= SGXDataCenterAttestationPrimitives
  SGX_DCAP_INC := -I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/common/inc -I$(SGX_DCAP)/QuoteGeneration/pce_wrapper/inc -I$(SGX_DCAP)/QuoteVerification/Src/AttestationLibrary/include
endif

#EPID_SDK := $(SGX_SDK)/external/epid-sdk

CFLAGS += -std=gnu99 -I$(SGX_RA_TLS) -I$(INCDIR) -I$(SGX_SDK)/include -I$(INCDIR) $(SGX_DCAP_INC) -fPIC -I$(BINDIR)
#CFLAGSERRORS := -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS += $(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS += -DSGX_GROUP_OUT_OF_DATE
ifdef ECDSA
  CFLAGS += -DRATLS_ECDSA
endif
#CFLAGS += -I$(SGX_GIT)/common/inc/internal -I$(EPID_SDK) -I$(SGX_GIT)/common/inc

CC ?= gcc
GO ?= go

all: ra-tls-server 

ifeq ($(DEBUG),1)
  GCFLAGS=-gcflags "-N -l"
endif
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")

# glibc-static is required for the static linkage
LDFLAGS := -L$(LIBDIR) -L/opt/intel/sgxsdk/lib64 -Llib -lsgx_uae_service -lsgx_uae_service -lsgx_urts lib/libra-tls-server.a $(LIBDIR)/libcurl-wolfssl.a $(LIBDIR)/libwolfssl.a -lz -lm 

ra-tls-server: ra-tls-server.c lib/libra-tls-server.a
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

lib/libra-tls-server.a:
	make -C lib 

install: ra-tls-server
	cp -f inclavared $(BINDIR)

clean:
	rm -f *.o ra-tls-server
	$(MAKE) -C lib clean

.PHONY: clean install

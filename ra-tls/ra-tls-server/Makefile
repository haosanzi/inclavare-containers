TOPDIR := $(shell readlink -f ..)

DEBUG ?=
EXTRA_FLAGS ?=

PREFIX ?= $(TOPDIR)/build
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
INCDIR := $(PREFIX)/include

CFLAGS += -std=gnu99 -I$(INCDIR) -fPIC
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

ifneq ($(GO111MODULE),off)
  MOD_VENDOR := "-mod=vendor"
endif
ifeq ($(DEBUG),1)
  GCFLAGS=-gcflags "-N -l"
endif
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")
# glibc-static is required for the static linkage
GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) -buildmode=pie $(GCFLAGS) $(EXTRA_FLAGS) \
  -ldflags "-X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"
#GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) $(GCFLAGS) $(EXTRA_FLAGS) \
        -ldflags "-w -extldflags -static -X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"

ra-tls-server: ra-tls-server.c
	$(GO_BUILD) -o $@ .

install: ra-tls-server
	cp -f inclavared $(BINDIR)

clean:
	rm -f *.o ra-tls-server

.PHONY: clean install

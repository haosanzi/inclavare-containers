.PHONY: all install clean uninstall package

export INCLAVARE_CONTAINERS_VERSION := $(shell cat ./VERSION)
components := rune shim epm sgx-tools

all:




	for name in $(components); do \
		$(MAKE) -C $$name; \
	done

install:
	for name in $(components); do \
		$(MAKE) -C $$name install; \
	done

clean:
	for name in $(components); do \
		$(MAKE) -C $$name clean; \
	done

uninstall:
	for name in $(components); do \
		$(MAKE) -C $$name uninstall; \
	done

package:
	for name in $(components); do \
		$(MAKE) -C $$name package; \
	done

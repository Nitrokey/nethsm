TOP_DIR := $(abspath .)
all: build

GPG_SIGN_DETACHED := $(TOP_DIR)/../../tools/gpg-sign-detached.sh

# Override to sign with non-default keys
KEY_DIR ?= $(TOP_DIR)/../../keys/test-key

.PHONY: all build

INSTALL_SCRIPT := config/includes.chroot/etc/skel/bin/nitrohsm-install

# Source this from ../../tools so that it can live in one place
$(INSTALL_SCRIPT): ../../tools/nitrohsm-install.sh
	cp $< $@
	chmod 755 $@

build: $(INSTALL_SCRIPT)
	sudo \
	    LIVE_SIGN_DETACHED=$(GPG_SIGN_DETACHED) \
	    LIVE_SIGN_KEY_DIR=$(KEY_DIR) \
	    lb build

.PHONY: clean

clean:
	sudo \
	    lb clean
	$(RM) $(INSTALL_SCRIPT)

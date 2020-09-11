TOP_DIR := $(abspath .)

GPG_SIGN_DETACHED := $(TOP_DIR)/../../tools/gpg-sign-detached.sh

# Override to sign with non-default keys
KEY_DIR ?= $(TOP_DIR)/../../keys/test-key

.PHONY: build

build:
	sudo \
	    LIVE_SIGN_DETACHED=$(GPG_SIGN_DETACHED) \
	    LIVE_SIGN_KEY_DIR=$(KEY_DIR) \
	    lb build

.PHONY: clean

clean:
	sudo \
	    lb clean

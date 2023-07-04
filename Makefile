# Copyright 2023 - 2023, Nitrokey GmbH
# SPDX-License-Identifier: EUPL-1.2

# This Makefile is a meta-Makefile that passes most targets through to
# Makefile.sub. See there for the action, and for documented user-settable
# parameters. Please ask before adding targets here.

OS := $(shell uname -s)

ifeq ($(OS),Darwin)
MODE ?= test
else
MODE ?= dev
endif

.PHONY: all
all:
	@cat Makehelp

Makefile: ;

.SUFFIXES:

.NOTPARALLEL:

.stamp-mode:
	@echo "$(MODE)" >$@
	@$(RM) .stamp-prepare

.PHONY: check-mode
ifneq ($(I_KNOW_WHAT_IM_DOING),)
check-mode: ;
else
check-mode: .stamp-mode
	@if test "`cat $<`" != "$(MODE)"; then \
	  echo "Error: MODE is set to '`cat $<`', but '$(MODE)' was requested" 1>&2; \
	  echo "Error: Cannot change MODE without running 'make distclean' first" 1>&2;  \
	  false; \
	else \
	  true; \
	fi
endif

.PHONY: distclean
distclean:
	$(MAKE) -f Makefile.sub distclean
	$(RM) .stamp-mode

HOST_UID := $(shell id -u)
HAVE_KVM := $(shell test -w /dev/kvm && echo "--device=/dev/kvm:/dev/kvm")
ifneq ($(HAVE_KVM),)
KVM_GID := $(shell getent group kvm | cut -d: -f3)
ifneq ($(KVM_GID),)
HAVE_KVM_GROUP := --group-add=$(KVM_GID)
endif
endif

DOCKER_IMAGE_NAME ?= registry.git.nitrokey.com/nitrokey/nethsm/nethsm/builder
.PHONY: local-container-enter
local-container-enter:
	docker run --rm -ti \
	    --net=host \
	    --cap-add NET_ADMIN \
	    --device=/dev/net/tun:/dev/net/tun \
	    $(HAVE_KVM) $(HAVE_KVM_GROUP) \
	    --user=$(HOST_UID) \
	    --mount type=bind,src=$(abspath .),dst=/builds/nitrokey/nethsm \
	    --mount type=tmpfs,dst=/tmp \
	    $(DOCKER_IMAGE_NAME)

.PHONY: local-container-setup
local-container-setup:
ifneq ($(HOST_UID),1000)
	sudo chown -R $(HOST_UID) /home/opam
endif
	git -C /home/opam/opam-repository fetch origin --depth=1 $$(cat $(abspath .)/.opam-repository-commit)
	git -C /home/opam/opam-repository reset --hard FETCH_HEAD
	opam update

# This rule passes through any target not defined above to Makefile.sub.
%:: check-mode
	$(MAKE) -f Makefile.sub $@

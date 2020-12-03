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
check-mode: .stamp-mode
	@if test "`cat $<`" != "$(MODE)"; then \
	  echo "Error: MODE is set to '`cat $<`', but '$(MODE)' was requested" 1>&2; \
	  echo "Error: Cannot change MODE without running 'make distclean' first" 1>&2;  \
	  false; \
	else \
	  true; \
	fi

.PHONY: check-submodules

ifeq ($(MODE),test)
check-submodules: ;
else ifneq ($(NO_GIT)$(I_KNOW_WHAT_IM_DOING),)
check-submodules: ;
else
check-submodules:
	@if test -z "$$(git submodule --quiet foreach echo .)"; then \
	  echo "Error: Git submodules not present." 1>&2; \
	  echo "Error: Please run 'make fetch-submodules' in this tree." 1>&2; \
	  if test -f "/.dockerenv"; then \
	    echo "Error: Note that you are in a container, this should be run ON THE HOST." 1>&2; \
	  fi; \
	  false; \
	else \
	  true; \
	fi
endif

.PHONY: fetch-submodules
fetch-submodules:
	MODE=$(MODE) NO_GIT=$(NO_GIT) NO_SHALLOW=$(NO_SHALLOW) \
	     tools/fetch-git-submodules.sh

.PHONY: deinit-submodules
deinit-submodules:
	git submodule deinit --all --force
	@echo "Note: If it's still broken, try 'rm -rf .git/modules'."

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

DOCKER_IMAGE_NAME ?= mato/nethsm-builder
.PHONY: local-container-enter
local-container-enter:
	docker run --rm -ti \
	    --net=host \
	    --cap-add NET_ADMIN \
	    --device=/dev/net/tun:/dev/net/tun \
	    $(HAVE_KVM) $(HAVE_KVM_GROUP) \
	    --user=$(HOST_UID) \
	    --mount type=bind,src=$(abspath .),dst=/builds/nitrokey/nitrohsm \
	    --mount type=tmpfs,dst=/tmp \
	    $(DOCKER_IMAGE_NAME)

.PHONY: local-container-setup
local-container-setup:
ifneq ($(HOST_UID),1000)
	sudo chown -R $(HOST_UID) /home/opam
endif
	cd /home/opam/opam-repository && \
	    git fetch origin master
	cd /home/opam/opam-repository && \
	    git reset --hard $$(cat $(abspath .)/.opam-repository-commit)
	opam update

# This rule passes through any target not defined above to Makefile.sub.
%:: check-mode check-submodules
	$(MAKE) -f Makefile.sub $@

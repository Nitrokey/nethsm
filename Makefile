export TOPDIR := $(abspath .)

MODE ?= dev
ifeq ($(MODE), dev)
    TARGET := hvt
else ifeq ($(MODE), muen)
    TARGET := muen
endif

S_KEYFENDER := src/s_keyfender/keyfender.$(TARGET)

.PHONY: all
all:
	@echo Read the README.md

.PHONY: prepare
prepare:
	opam install -y mirage solo5-bindings-$(TARGET) mirage-solo5
	opam pin add -y -n keyfender $(TOPDIR)/src/keyfender#HEAD
	opam install -y --deps-only keyfender

.PHONY: force-it
# Always build the keyfender unikernel, since we have no way of propagating
# dependencies from ocamlbuild/mirage to the top-level make.
$(S_KEYFENDER): force-it
	cd src/s_keyfender && mirage configure -t $(TARGET)
	cd src/s_keyfender && $(MAKE) depend
	cd src/s_keyfender && $(MAKE)

.PHONY: build
build: $(S_KEYFENDER)

ifeq ($(MODE), dev)
.PHONY: run
run: build
	solo5-hvt --net:external=tap200 --net:internal=tap201 $(S_KEYFENDER)

endif

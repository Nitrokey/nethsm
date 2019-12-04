export TOPDIR := $(abspath .)

MODE ?= dev
ifeq ($(MODE), dev)
    TARGET := hvt
else ifeq ($(MODE), muen)
    TARGET := muen
endif

S_KEYFENDER := src/s_keyfender/keyfender.$(TARGET)
GIT_DAEMON ?= src/git/git-daemon

.PHONY: all
all:
	@echo Read the README.md

.PHONY: prepare
prepare:
	opam install -y mirage solo5-bindings-$(TARGET) mirage-solo5
	opam pin add -y -n keyfender $(TOPDIR)/src/keyfender#HEAD
	opam install -y --deps-only keyfender

$(GIT_DAEMON):
	$(MAKE) -C src/git NO_PERL=1 NO_OPENSSL=1 NO_CURL=1 NO_EXPAT=1 NO_TCLTK=1 NO_GETTEXT=1 NO_PYTHON=1 all

.PHONY: keyfender force-it
# Always build the keyfender library and s_keyfender unikernel, since we have
# no way of propagating dependencies from ocamlbuild/mirage to the top-level
# make.
keyfender:
	opam reinstall -y keyfender

$(S_KEYFENDER): keyfender force-it
	cd src/s_keyfender && mirage configure -t $(TARGET)
	cd src/s_keyfender && $(MAKE) depend
	cd src/s_keyfender && $(MAKE)

.PHONY: build
build: $(GIT_DAEMON) $(S_KEYFENDER)

ifeq ($(MODE), dev)
run/git/keyfender-data.git:
	mkdir -p $@
	git init --bare $@

run/git-daemon.pid: | run/git/keyfender-data.git
	src/git/bin-wrappers/git daemon \
	    --listen=169.254.169.2 \
	    --base-path=run/git \
	    --export-all \
	    --enable=receive-pack \
	    --pid-file=$@ &

.PHONY: run
run: build run/git-daemon.pid
	solo5-hvt --net:external=tap200 --net:internal=tap201 $(S_KEYFENDER)

.PHONY: clean
clean:
	-opam remove -y keyfender
	-test -f run/git-daemon.pid && kill $$(cat run/git-daemon.pid) && rm run/git-daemon.pid
	$(RM) -r run/

endif

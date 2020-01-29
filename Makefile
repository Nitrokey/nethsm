MODE ?= dev

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

.PHONY: distclean
distclean:
	$(MAKE) -f Makefile.sub distclean
	$(RM) .stamp-mode

%:: check-mode
	$(MAKE) -f Makefile.sub $@

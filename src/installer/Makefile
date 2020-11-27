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

QEMU ?= qemu-system-x86_64

IMAGE := live-image-amd64.hybrid.iso

# Should be kept in sync with ../../Makefile.sub
QEMU_OPTS := \
    -serial file:serial.out \
    -drive if=none,id=stick,file=$(IMAGE),format=raw \
    -drive if=pflash,format=raw,file=coreboot.flash \
    -machine q35,accel=kvm,kernel-irqchip=split \
    -cpu host,+invtsc \
    -m 5120 \
    -smp cores=2,threads=2,sockets=1 \
    -device intel-iommu,intremap=on,device-iotlb=on \
    -device ioh3420,id=pcie.1,chassis=1 \
    -device virtio-net-pci,bus=pcie.1,addr=0.0,netdev=net0,disable-legacy=on,disable-modern=off,iommu_platform=on,ats=on \
    -device qemu-xhci,id=xhci,bus=pcie.0,addr=3.0 \
    -device usb-tablet,bus=xhci.0 \
    -device usb-storage,bus=xhci.0,drive=stick \
    -netdev user,id=net0 \
    -curses

coreboot.flash: $(TOP_DIR)/../../obj/coreboot.rom
	cp $< $@

# Since the ISO is built as root, and needs to be writable to be mounted as an
# USB stick, fix if necessary.
.PHONY: do-chown
do-chown:
	@-! test -w $(IMAGE) && sudo chown $(shell id -u) $(IMAGE)

.PHONY: run
run: coreboot.flash do-chown
	$(QEMU) $(QEMU_OPTS)


## Coreboot images for Muen system

The Coreboot images in this directory are currently built manually.

For QEMU, the image in `qemu/` can be reproduced as follows:

Clone Coreboot for NitroHSM:

```
git clone -b nitrohsm git@git.dotplex.com:nitrokey/nitrohsm-coreboot.git
cd nitrohsm-coreboot
```

If you've not built a Coreboot from this tree, build the cross toolchain:

```
make crossgcc-i386 CPUS=$(nproc)
```

Build Coreboot configured for QEMU Q35, with GRUB2 payload including 9elements XHCI support, produces `build/coreboot.rom`:

```
make defconfig KBUILD_DEFCONFIG=configs/config.nitrohsm_qemu_q35
make -j$(nproc)
```

Note that GRUB is configured by embedding a grub.cfg into the ROM to use a serial console on COM1, 115200 baud, N81 _exclusively_, so you will not get anything on the VGA console.

The embedded GRUB configuration files can be found in `payloads/external/GRUB2`. If you want to change it, it is sufficient to rebuild with `make`, which will ensure that the embedded file in the ROM image is updated.

To manually run QEMU for testing, etc. it is sufficient to use something like:

```
qemu-system-x86_64 -machine q35 -enable-kvm -cpu host -bios build/coreboot.rom -serial stdio <...>
```

A full command line with an USB XHCI flash disk attached, and userspace virtualized networking, suitable e.g. for booting a mugenhwcfg-live ISO:

```
qemu-system-x86_64 \
    -bios coreboot.rom.xhci \
    -drive file=internaldisk.img,format=raw \
    -serial stdio \
    -machine q35,accel=kvm,kernel-irqchip=split \
    -cpu host,+invtsc \
    -m 5120 \
    -smp cores=2,threads=2,sockets=1 \
    -device intel-iommu,intremap=on,device-iotlb=on \
    -device ioh3420,id=pcie.1,chassis=1 \
    -device virtio-net-pci,bus=pcie.1,addr=0.0,netdev=net0,disable-legacy=on,disable-modern=off,iommu_platform=on,ats=on \
    -device qemu-xhci,id=xhci,bus=pcie.0,addr=3.0 \
    -device usb-storage,bus=xhci.0,drive=usb0 \
    -blockdev file,node-name=usb0,filename=usbdisk.img \
    -netdev user,id=net0,ipv6=off
```

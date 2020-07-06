## Coreboot images for Muen system

The Coreboot images in this directory are currently built manually.

For QEMU, the image in `qemu/` can be reproduced as follows:

Obtain Coreboot 4.12:

```
git clone https://review.coreboot.org/coreboot
cd coreboot
git checkout -b nitrohsm 4.12
```

If you've not built a Coreboot in this tree, build the cross toolchain:

```
make crossgcc-i386 CPUS=$(nproc)
```

Build Coreboot configured for QEMU Q35 with stock Grub payload, produces `build/coreboot.rom`:

```
cp ../coreboot_defconfig ./.config
make oldconfig
make -j$(nproc)
```

Embed GRUB configuration file into ROM:

```
build/cbfstool build/coreboot.rom add -f ../grub.cfg -n etc/grub.cfg -t raw
```


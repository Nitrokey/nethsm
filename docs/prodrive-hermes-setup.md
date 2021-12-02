% NetHSM deploy and setup onto the Prodrive Hermes
% Hannes Mehnert; Martin Lucina; Stefanie Schirmer; Sven Anderson; Jan Suhr; Markus Meissner
% Robur.io, Nitrokey GmbH, 20th November 2020

# Introduction {#sec-i}

To deploy NetHSM onto a Prodrive Hermes-based system the following steps are to be taken:

* Flash coreboot firmware 
* Install the NetHSM system image & data on a hard-drive

This guide assumes that the full repository with Prodrive Hermes as the hardware plattform
was compiled and inside the `objs` directory there should be at least: `system.img.cpio`
and `coreboot.rom`.

Furthermore, a USB-device with a bootable linux (e.g., grml) that includes `flashrom` 
is needed.

# Flash coreboot firmware {#sec-flash-firmware}

Currently the generated `coreboot.rom` does not contain an IFD, this means
the resulting image is not suited for flashing it directly on the NAND.

As of now the only way to flash a new image is as followed:

* Open the BMC frontend in the browser, navigate to *Administration* -> *Firmware update* ->
	*bios*

* Upload a (release) bios update to enable booting a "simple" Linux

* Fully power off the system (real power off, not just mainboard's the power button)

* Connect the bootable USB-device. To interact with the system the BMC remote console shall be used.

* Before booting into the system make sure the linux commandline arguments contain: `nopat iomem=relaxed`
	in order to enable flashing the NAND using `flashrom`

* Once inside the Linux system, start `sshd` and copy over the `coreboot.rom` into the running
	system

* flash the (bios region) of the NAND using the following command:

```
$ flashrom --ifd -i bios -p internal --noverify-all -w coreboot.rom
```

* Once this is done, shut off the system completly 


# Install the NetHSM system image & data on a hard-drive {#sec-nethsm-install}

* Connect a hard-drive to your computer (any data on the device will be deleted!)

* The following steps assume your hard-drive is available as `/dev/sdb`, please adapt accordingly!

* Install the *NetHSM System Image*:
	```
  $ tools/nethsm-install.sh /dev/sdb objs/system.img.cpio
	```
* make sure to properly eject/umount the partitions and done!




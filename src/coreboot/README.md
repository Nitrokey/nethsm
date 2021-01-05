## Coreboot images for Muen system

The Coreboot images for NetHSM are now built automatically when using MODE=muen.

The `blobs/` directory contains Intel ME blobs for the Supermicro X11-SSH-TF platform. To reproduce these, assuming you have a stock BIOS dump from the platform in `./supermicro_bios.bin`, use:

```
# ifdtool is built by Coreboot in build/util/ifdtool/ifdtool
ifdtool -x ./supermicro_bios.bin
# Disable ME by switching on the HAP bit
ifdtool -M 1 ./flashregion_0_flashdescriptor.bin
cp flashregion_0_flashdescriptor.bin.new blobs/descriptor.bin
cp flashregion_2_intel_me.bin blobs/me.bin
```

The Flash IC on the Supermicro X11SSH-TF is [located](https://doc.coreboot.org/mainboard/supermicro/x11-lga1151-series/x11ssh-tf/x11ssh-tf.html) near the battery, with an arrow marking pin 1.

#!/bin/bash

#OFFSET=$(grep -obaF __FMAP__ $1 | head -1 | sed s/:.*//)
#echo Found offset: $OFFSET

OFFSET=0x1710000

dd if=$1 bs=1024 skip=$(($OFFSET/1024)) of=/tmp/coreboot.bin

sshpass -p root scp /tmp/coreboot.bin root@$2:coreboot.bin

sshpass -p root ssh root@$2 <<EOF
echo 1 >/sys/devices/platform/ahb/ahb\:apb/1e6e2000.syscon/1e6e2070.hwstraps/passthrough
sleep 1
flash_erase /dev/mtd/bios-part $OFFSET 0
sleep 1
dd if=coreboot.bin of=/dev/mtd/bios-part bs=1024 seek=$(($OFFSET/1024))
sleep 1
echo 3 >/sys/devices/platform/ahb/ahb\:apb/1e6e2000.syscon/1e6e2070.hwstraps/passthrough
sleep 1
bmc_test -m payload -s 2
EOF

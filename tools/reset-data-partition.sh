#!/bin/bash

if [[ "$1" = "" ]]; then
	echo "Usage: $0 <data-partition>"
fi

dev=$1

rm -rf /tmp/empty /tmp/data

mkdir -p /tmp/empty /tmp/data/git
git init --bare --template=/tmp/empty /tmp/data/git/keyfender-data.git
mke2fs -t ext4 -E discard -F -m0 -L data -d /tmp/data $dev

echo "finished creating the NetHSM data partition"

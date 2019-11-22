#!/bin/sh

case $(uname -s) in
    Linux)
	ip tuntap add tap200 mode tap
	ip addr add 192.168.1.100/24 dev tap200
	ip link set dev tap200 up

	ip tuntap add tap201 mode tap
	ip addr add 169.254.169.2/24 dev tap201
	ip link set dev tap201 up
	;;
    *)
	echo "Unkown system $(uname -s)"
	;;
esac

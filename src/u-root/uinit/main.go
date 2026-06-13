// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

// uinit is our main extension point for u-root. This code gets compiled into
// "/bbin/uinit" and executed by u-root's "init" at boot time.
//
// As our u-root is shared between all Muen Linux subjects, uinit expects a
// single argument on the command line, which selects what actions are taken
// depending on the Linux subject that is being booted.
//
// Additionally, an argument of "mock" may be used to run a "mock" uinit for
// testing purposes. See mock.go for details on how this works.
package main

import (
	"log"
	"os"

	"nethsm/internal/hw"
	"nethsm/internal/util"
)

const (
	// Both subjects: transport protocol for the platform and network listeners.
	listenerProtocol = "tcp4"

	// S-Platform
	// platform protocol listener address.
	platListenerAddress = "169.254.169.2:1023"
	// GPT partition to write firmware updates to.
	sysInactivePartition = hw.DiskPrefix + "2"
	// UID/GID for the etcd process (conventionally "daemon").
	etcdUIDGID = 1
	// entropy destination on S-Keyfender.
	keyfenderEntropyIP   = "169.254.169.1"
	keyfenderEntropyPort = "4444"

	// S-Net-External
	// network configuration listener address.
	netListenerAddress = "169.254.100.1:1023"
)

// Current kernel version; used when loading kernel modules (muen.go, s_platform.go).
var kernelRelease = util.GetKernelRelease()

func main() {
	// We expect a hostname to be passed in via the kernel's boot parameters,
	// as uroot.uinitargs=HOSTNAME.
	hostname := "(none)"
	if len(os.Args) == 2 {
		hostname = os.Args[1]
	}
	log.SetOutput(os.Stdout)
	log.SetPrefix(hostname + ": ")

	switch hostname {
	case "net_external":
		log.Printf("Booting subject: S-Net-External")
		sNetExternalActions()
	case "platform":
		log.Printf("Booting subject: S-Platform")
		sPlatformActions()
	default:
		log.Printf("Unknown subject hostname: %s", hostname)
	}

	// If we get here then we are done with boot-time actions. We don't want to
	// halt, so just pause forever, rather than exiting which would result in
	// u-root init's default behaviour of dropping into a shell.
	log.Printf("Done")
	select {}
}

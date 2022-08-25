package main

import (
	"log"
	"path/filepath"
)

// sNetExternalActions are executed for S-Net-External.
func sNetExternalActions() {
	mountMuenFs()
	G.s.Logf("Channels:")
	G.s.Execf("/bbin/ls -l /muenfs")

	loadUnikernelNets()

	// Enumerate eth* and net*, and bridge them all on br0.
	// Note that Linux bridges will "acquire" the MAC address of the first
	// child interface attached to the bridge, so intentionally start with
	// eth* here.
	G.s.Execf("/bbin/ip link add br0 type bridge")
	netPaths := G.s.Glob("/sys/class/net/eth*")
	netPaths = append(netPaths, G.s.Glob("/sys/class/net/net*")...)
	for _, netPath := range netPaths {
		_, netIf := filepath.Split(netPath)
		G.s.Execf("/bbin/ip link set %s master br0", netIf)
		G.s.Execf("/bbin/ip link set dev %s up", netIf)
	}
	G.s.Execf("/bbin/ip link set dev br0 up")

	dumpNetworkStatus()

	if err := G.s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}
}

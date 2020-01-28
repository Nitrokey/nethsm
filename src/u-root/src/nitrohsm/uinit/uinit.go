// uinit is our main extension point for u-root. This code gets compiled into
// "/bbin/uinit" and executed by u-root's "init" at boot time.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"nitrohsm/uinit/script"
)

// s represents our global Script context.
var s = Script.New()

// Load muenfs kernel module and mount /muenfs.
// Uses global Script context.
func mountMuenFs() {
	s.Logf("Loading muenfs")
	s.Execf("/bbin/insmod /lib/modules/4.18.5-muen/extra/muenfs.ko")
	s.Execf("/bbin/mkdir -p /muenfs")
	s.Execf("/bbin/mount -t muenfs none /muenfs")
}

// Load muennet kernel module for all unikernel interfaces found on the system.
// Requires /muenfs mounted, uses global Script context.
func loadUnikernelNets() {
	// Enumerate all channels with a xxx|in and xxx|out pair.
	channels := []string{}
	channelPaths := s.Glob("/muenfs/*|in")
	for _, channelPath := range channelPaths {
		if s.FileExists(strings.ReplaceAll(channelPath, "|in", "|out")) {
			_, channel := filepath.Split(channelPath)
			channel = strings.ReplaceAll(channel, "|in", "")
			channels = append(channels, channel)
		}
	}
	if len(channels) > 0 {
		// Construct the muennet module options for each unikernel channel
		// (pair), naming the Linux interfaces starting with net0...
		s.Logf("Loading muennet for channels: %v", channels)
		index := 0
		names := []string{}
		inChannels := []string{}
		outChannels := []string{}
		readerProtos := []string{}
		writerProtos := []string{}
		flags := []string{}
		for _, channel := range channels {
			names = append(names, fmt.Sprintf("net%d", index))
			index += 1
			// xxx|out is our in=, xxx|in is our out=, this is intentional.
			inChannels = append(inChannels, fmt.Sprintf("%s|out", channel))
			outChannels = append(outChannels, fmt.Sprintf("%s|in", channel))
			readerProtos = append(readerProtos, "0x7ade5c549b08e814")
			writerProtos = append(writerProtos, "0x7ade5c549b08e814")
			flags = append(flags, "eth_dev")
		}
		join := func(a []string) string { return strings.Join(a, ",") }
		s.Execf("/bbin/insmod /lib/modules/4.18.5-muen/extra/muennet.ko "+
			"name=%s in=%s out=%s reader_protocol=%s writer_protocol=%s flags=%s",
			join(names), join(inChannels), join(outChannels),
			join(readerProtos), join(writerProtos), join(flags))
	}
}

// Dump network status.
// Uses global Script context.
func dumpNetworkStatus() {
	s.Logf("Interfaces:")
	s.Execf("/bbin/ip link")
	s.Logf("Addresses:")
	s.Execf("/bbin/ip addr")
	s.Logf("Routes:")
	s.Execf("/bbin/ip route")
}

// nicActions are executed for "nic_linux".
func nicActions() {
	mountMuenFs()
	s.Logf("Channels:")
	s.Execf("/bbin/ls -l /muenfs")

	loadUnikernelNets()

	// Enumerate eth* and net*, and bridge them all on br0.
	// Note that Linux bridges will "acquire" the MAC address of the first
	// child interface attached to the bridge, so intentionally start with
	// eth* here.
	s.Execf("/bbin/ip link add br0 type bridge")
	netPaths := s.Glob("/sys/class/net/eth*")
	netPaths = append(netPaths, s.Glob("/sys/class/net/net*")...)
	for _, netPath := range netPaths {
		_, netIf := filepath.Split(netPath)
		s.Execf("/bbin/ip link set %s master br0", netIf)
		s.Execf("/bbin/ip link set dev %s up", netIf)
	}
	s.Execf("/bbin/ip link set dev br0 up")

	dumpNetworkStatus()

	s.Logf("Hit ENTER to shut down")
	s.ReadLine()
	s.Execf("/bbin/shutdown halt")

	if err := s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
	}
}

// storageActions are executed for "storage_linux".
func storageActions() {
	mountMuenFs()
	s.Logf("Channels:")
	s.Execf("/bbin/ls -l /muenfs")

	loadUnikernelNets()

	s.Execf("/bbin/ip addr add 169.254.169.2/24 dev net0")
	s.Execf("/bbin/ip link set dev net0 up")

	dumpNetworkStatus()

	s.Logf("Mounting /data")
	s.Execf("/bbin/mkdir -p /data")
	s.Execf("/bbin/mount -t ext4 /dev/sda2 /data")
	s.Logf("Starting Git server")
	s.Execf("/bin/git daemon --base-path=/data/git --export-all --enable=receive-pack")
	s.Logf("Git server exited")

	s.Logf("Hit ENTER to shut down")
	s.ReadLine()
	s.Execf("/bbin/shutdown halt")

	if err := s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
	}
}

func main() {
	// We expect a hostname to be passed in via boot parameters, as
	// uroot.uinitargs=HOSTNAME.
	var hostname = "(none)"
	if len(os.Args) == 2 {
		hostname = os.Args[1]
	}

	switch hostname {
	case "nic_linux":
		nicActions()
	case "storage_linux":
		storageActions()
	default:
		log.Printf("Unknown hostname: %s", hostname)
		log.Print("Not running any actions")
	}
	log.Print("Uinit Done!")
}

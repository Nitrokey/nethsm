// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Load muenfs kernel module and mount /muenfs.
// Uses global Script context.
func mountMuenFs() {
	G.s.Logf("Loading muenfs")
	G.s.Execf("/bbin/insmod /lib/modules/%s/extra/muenfs.ko", G.kernelRelease)
	G.s.Execf("/bbin/mkdir -p /muenfs")
	G.s.Execf("/bbin/mount -t muenfs none /muenfs")
}

// Load muenevents kernel module and mount /muenevents.
// Uses global Script context.
func mountMuenEvents() {
	G.s.Logf("Loading muenevents")
	G.s.Execf("/bbin/insmod /lib/modules/%s/extra/muenevents.ko", G.kernelRelease)
	G.s.Execf("/bbin/mkdir -p /muenevents")
	G.s.Execf("/bbin/mount -t muenevents none /muenevents")
}

// Trigger muen event.
func triggerMuenEvent(event string) {
	f, err := os.OpenFile("/muenevents/"+event, os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("Error triggering event '%s': %v", event, err)
		return
	}
	defer f.Close()

	_, err = f.Write([]byte{1})
	if err != nil {
		log.Printf("Error triggering event '%s': %v", event, err)
		return
	}
}

// Load muennet kernel module for all unikernel interfaces found on the system.
// Requires /muenfs mounted, uses global Script context.
func loadUnikernelNets() {
	// Enumerate all channels with a xxx|in and xxx|out pair.
	channels := []string{}
	channelPaths := G.s.Glob("/muenfs/*|in")
	for _, channelPath := range channelPaths {
		if G.s.FileExists(strings.ReplaceAll(channelPath, "|in", "|out")) {
			_, channel := filepath.Split(channelPath)
			channel = strings.ReplaceAll(channel, "|in", "")
			channels = append(channels, channel)
		}
	}
	if len(channels) > 0 {
		// Construct the muennet module options for each unikernel channel
		// (pair), naming the Linux interfaces starting with net0...
		G.s.Logf("Loading muennet for channels: %v", channels)
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
		G.s.Execf("/bbin/insmod /lib/modules/"+G.kernelRelease+"/extra/muennet.ko "+
			"name=%s in=%s out=%s reader_protocol=%s writer_protocol=%s flags=%s",
			join(names), join(inChannels), join(outChannels),
			join(readerProtos), join(writerProtos), join(flags))
	}
}

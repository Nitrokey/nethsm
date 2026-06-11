// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"nethsm/internal/script"
)

// Load muenfs kernel module and mount /muenfs.
func mountMuenFs(s *script.Script) {
	s.Logf("Loading muenfs")
	s.Execf("/bbin/insmod /lib/modules/%s/extra/muenfs.ko", kernelRelease)
	s.Execf("/bbin/mkdir -p /muenfs")
	s.Execf("/bbin/mount -t muenfs none /muenfs")
}

// Load muenevents kernel module and mount /muenevents.
func mountMuenEvents(s *script.Script) {
	s.Logf("Loading muenevents")
	s.Execf("/bbin/insmod /lib/modules/%s/extra/muenevents.ko", kernelRelease)
	s.Execf("/bbin/mkdir -p /muenevents")
	s.Execf("/bbin/mount -t muenevents none /muenevents")
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
// Requires /muenfs mounted.
func loadUnikernelNets(s *script.Script) {
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
		s.Execf("/bbin/insmod /lib/modules/"+kernelRelease+"/extra/muennet.ko "+
			"name=%s in=%s out=%s reader_protocol=%s writer_protocol=%s flags=%s",
			join(names), join(inChannels), join(outChannels),
			join(readerProtos), join(writerProtos), join(flags))
	}
}

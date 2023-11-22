// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"io"
	"log"
	"math"
	"net"
	"os"
	"time"

	"github.com/u-root/u-root/pkg/termios"
)

const (
	trngDev       = "/dev/ttyS1"
	trngRandSize  = 4096 // this must be in sync with values in startTrngListener in unikernel.ml
	totalRandSize = trngRandSize + tpmRandSize
	timeout       = time.Second * 10
)

var (
	fullySeededNotify func()
	randIsFullySeeded func() bool
)

func init() {
	ch := make(chan struct{})
	fullySeededNotify = func() {
		close(ch)
	}
	randIsFullySeeded = func() bool {
		select {
		case <-ch:
			return true
		case <-time.After(timeout):
			return false
		}
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func trngTask() {
	f, err := os.Open(trngDev)
	check(err)

	settings, err := termios.GetTermios(f.Fd())
	check(err)

	settings, err = termios.MakeSerialBaud(settings, 115200)
	check(err)

	settings = termios.MakeRaw(settings)

	err = termios.SetTermios(f.Fd(), settings)
	check(err)

	trngLoop(f)
}

func randReader(trng io.Reader) func() []byte {
	ch := make(chan []byte)
	reader := func() []byte {
		var buf []byte
		select {
		case buf = <-ch:
			ent := shannonEntropy(buf)
			if ent < 7.2 {
				log.Printf("ERROR: entropy %f from TRNG too low, dropping data.\n", ent)
				buf = buf[:0]
			}
		case <-time.After(timeout):
			log.Printf("ERROR: reading from TRNG timed out! Using only entropy from TPM!")
		}
		tpmRand, err := tpmRand()
		if err != nil {
			log.Printf("ERROR: reading entropy from TPM failed: %v", err)
		} else {
			buf = append(buf, tpmRand...)
		}
		if len(buf) > 0 {
			return buf
		} else {
			log.Printf("ERROR: couldn't read any entropy from RNGs!")
			return nil
		}
	}
	go func() {
		defer log.Println("TRNG reader stopped")
		bufA := &[totalRandSize]byte{}
		bufB := &[totalRandSize]byte{}
		for {
			buf := bufA[:trngRandSize]
			_, err := io.ReadFull(trng, buf)
			check(err)
			ch <- buf
			bufA, bufB = bufB, bufA
		}
	}()
	return reader
}

func trngLoop(trng io.Reader) {
	keyfender, err := net.Dial("udp", net.JoinHostPort(G.keyfenderIP, G.entropyPort))
	check(err)
	defer keyfender.Close() // nolint

	devRand, err := os.OpenFile("/dev/random", os.O_WRONLY, 0)
	check(err)
	defer devRand.Close() // nolint

	fullySeeded := false
	seed := func(buf []byte) {
		_, err = devRand.Write(buf)
		check(err)
		if !fullySeeded && len(buf) == totalRandSize {
			fullySeededNotify()
			fullySeeded = true
		}
	}

	send := func(buf []byte) {
		_, err = keyfender.Write(buf)
		if err != nil {
			log.Printf("Sending entropy failed: %v", err)
		}
	}

	getRand := randReader(trng)
	for {
		seed(getRand())
		time.Sleep(time.Second)
		send(getRand())
		time.Sleep(time.Second)
	}
}

// calculate the Shannon Entropy of a byte slice
func shannonEntropy(data []byte) float64 {
	n := float64(len(data))
	var histogram [256]int
	for _, b := range data {
		histogram[b]++
	}
	var entropy float64
	for _, count := range histogram {
		if count > 0 {
			pval := float64(count) / n
			entropy -= pval * math.Log2(pval)
		}
	}
	return entropy
}

package main

import (
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/u-root/u-root/pkg/termios"
)

const (
	trngDev       = "/dev/ttyS1"
	randBlockSize = 4096 // this must be in sync with values in startTrngListener in unikernel.ml
	randTotalSize = randBlockSize * 2
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

func getTPMBlock(buf []byte) []byte {
	return buf[:randBlockSize]
}

func getTRNGBlock(buf []byte) []byte {
	return buf[randBlockSize:]
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

func randReader(trng io.Reader) func(func([]byte)) {
	ch := make(chan []byte)
	noTRNG := make([]byte, randBlockSize)
	reader := func(handler func([]byte)) {
		var buf []byte
		select {
		case buf = <-ch:
			ent := entropy(getTRNGBlock(buf))
			if ent < 7.2 {
				log.Printf("ERROR: entropy %f from TRNG too low, dropping data.\n", ent)
				buf = noTRNG
			}
		case <-time.After(timeout):
			log.Printf("ERROR: reading from TRNG timed out! Using only entropy from TPM!")
			buf = noTRNG
		}
		err := tpmRand(getTPMBlock(buf))
		if err != nil {
			log.Printf("ERROR: reading entropy from TPM failed: %v", err)
			buf = getTRNGBlock(buf)
		}
		if len(buf) > 0 {
			handler(buf)
		} else {
			log.Printf("ERROR: couldn't read any entropy from RNGs!")
		}
	}
	buf1 := make([]byte, randTotalSize)
	buf2 := make([]byte, randTotalSize)
	go func() {
		defer log.Println("TRNG reader stopped")
		for {
			_, err := io.ReadFull(trng, getTRNGBlock(buf1))
			check(err)
			ch <- buf1
			buf1, buf2 = buf2, buf1
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
	seeder := func(buf []byte) {
		rand.Seed(rand.Int63() ^
			*(*int64)(unsafe.Pointer(&buf[0])) ^
			*(*int64)(unsafe.Pointer(&buf[len(buf)/2])))
		_, err = devRand.Write(buf)
		check(err)
		if !fullySeeded && len(buf) == randTotalSize {
			fullySeededNotify()
			fullySeeded = true
		}
	}

	sender := func(buf []byte) {
		_, err = keyfender.Write(buf)
		if err != nil {
			log.Printf("Sending entropy failed: %v", err)
		}
	}

	getRand := randReader(trng)
	for {
		getRand(seeder)
		getRand(sender)
		time.Sleep(time.Second)
	}
}

// calculate the Shannon Entropy of a byte slice
func entropy(data []byte) float64 {
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

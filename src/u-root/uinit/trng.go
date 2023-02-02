package main

import (
	"encoding/binary"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/u-root/u-root/pkg/termios"
)

const trngDev = "/dev/ttyS1"

var rngNotify, rngWait func()

func init() {
	ch := make(chan struct{})
	rngNotify = func() {
		rngNotify = func() {}
		close(ch)
	}
	rngWait = func() { <-ch }
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

func trngReader(trng io.Reader) chan []byte {
	ch := make(chan []byte)
	buf := make([]byte, 8192)
	buf2 := make([]byte, 8192)
	go func() {
		defer log.Println("TRNG reader stopped")
		for {
			_, err := io.ReadFull(trng, buf)
			check(err)
			ch <- buf
			buf, buf2 = buf2, buf
		}
	}()
	return ch
}

func trngLoop(trng io.Reader) {
	var buf []byte

	con, err := net.Dial("udp", net.JoinHostPort(G.keyfenderIP, G.entropyPort))
	check(err)
	defer con.Close() // nolint

	devRand, err := os.OpenFile("/dev/random", os.O_WRONLY, 0)
	check(err)
	defer devRand.Close() // nolint

	feeder := func(buf []byte) {
		if buf == nil {
			return
		}
		_, err = con.Write(buf[:len(buf)/2])
		if err != nil {
			log.Printf("Sending entropy failed: %v", err)
		}
		seed := rand.Int63() ^ int64(binary.LittleEndian.Uint64(buf))
		rand.Seed(seed)
		_, err = devRand.Write(buf[len(buf)/2:])
		check(err)
		rngNotify()
	}

	trngCh := trngReader(trng)

	for {
		select {
		case buf = <-trngCh:
			ent := entropy(buf)
			if ent > 7.2 {
				feeder(buf)
				time.Sleep(time.Second)
			} else {
				log.Printf("WARNING: Entropy %f from TRNG too low, dropping data.\n", ent)
			}
		case <-time.After(time.Second * 30):
			log.Println("WARNING: reading from TRNG timed out! Using only entropy from TPM!")
		}
		buf, err = tpmRand()
		if err != nil {
			log.Printf("reading random from TPM failed: %v", err)
		} else {
			feeder(buf)
		}
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

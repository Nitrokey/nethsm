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

const trngPort = "ttyS1"

var trngNotify, trngWait func()

func init() {
	ch := make(chan struct{})
	trngNotify = func() {
		trngNotify = func() {}
		close(ch)
	}
	trngWait = func() { <-ch }
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func trngTask() {
	trng, err := termios.NewTTYS(trngPort)
	check(err)

	settings, err := trng.Get()
	check(err)

	settings, err = termios.MakeSerialBaud(settings, 115200)
	check(err)

	settings = termios.MakeRaw(settings)

	err = trng.Set(settings)
	check(err)

	trngLoop(trng)
}

func trngLoop(trng io.Reader) {
	buf := make([]byte, 8192)

	con, err := net.Dial("udp", net.JoinHostPort(G.keyfenderIP, G.entropyPort))
	check(err)
	defer con.Close() // nolint

	devRand, err := os.OpenFile("/dev/random", os.O_WRONLY, 0)
	check(err)
	defer devRand.Close() // nolint

	watchdog := watchdog(30 * time.Second)
	defer func() { watchdog <- false }()

	for {
		_, err := io.ReadFull(trng, buf)
		check(err)
		ent := entropy(buf)
		if ent < 7.2 {
			log.Printf("Entropy %f from TRNG too low, dropping data.\n", ent)
			continue
		}
		watchdog <- true
		// log.Printf("Bytes: %v\n", hex.EncodeToString(buf[:20]))
		_, err = con.Write(buf[:4096])
		if err != nil {
			log.Printf("TRNG: %v", err)
		}
		seed := rand.Int63() ^ int64(binary.LittleEndian.Uint64(buf))
		rand.Seed(seed)
		_, err = devRand.Write(buf[4096:])
		check(err)
		trngNotify()
		time.Sleep(time.Second)
	}
}

func watchdog(to time.Duration) chan bool {
	ch := make(chan bool)
	go func() {
		defer log.Println("TRNG watchdog stopped")
		for {
			timeout := time.NewTimer(to)
			select {
			case <-timeout.C:
				log.Println("WARNING: reading from TRNG timed out!")
			case w := <-ch:
				timeout.Stop()
				if !w {
					return
				}
			}
		}
	}()
	return ch
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

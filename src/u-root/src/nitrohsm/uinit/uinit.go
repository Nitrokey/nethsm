// uinit is our main extension point for u-root. This code gets compiled into
// "/bbin/uinit" and executed by u-root's "init" at boot time.
package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nitrohsm/uinit/script"
)

// s represents our global Script context.
var s = Script.New()

// UID and GID that the Git server is run as. We use 1 (coventionally,
// "daemon").
var GIT_UIDGID = 1

// Load muenfs kernel module and mount /muenfs.
// Uses global Script context.
func mountMuenFs() {
	s.Logf("Loading muenfs")
	s.Execf("/bbin/insmod /lib/modules/4.18.5-muen/extra/muenfs.ko")
	s.Execf("/bbin/mkdir -p /muenfs")
	s.Execf("/bbin/mount -t muenfs none /muenfs")
}

// Load muenevents kernel module and mount /muenevents.
// Uses global Script context.
func mountMuenEvents() {
	s.Logf("Loading muenevents")
	s.Execf("/bbin/insmod /lib/modules/4.18.5-muen/extra/muenevents.ko")
	s.Execf("/bbin/mkdir -p /muenevents")
	s.Execf("/bbin/mount -t muenevents none /muenevents")
}

// Trigger muen event.
func triggerMuenEvent(event string) {
	f, err := os.OpenFile("/muenevents/"+event, os.O_WRONLY, 0600)
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

	if err := s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}
}

// platformListener runs the "platform" protocol on the requested protocol and
// port.
//
// This is intended to be run as a goroutine, and upon receiving a terminal
// request will shut itself down, returning the request (command) via the
// result channel.
//
// Due to there being no way to set a listen(2) backlog in Go, >1 connections
// will be accepted but only served one at a time, in the order that the OS
// queues them.
func platformListener(result chan string, protocol string, port string) {
	listener, err := net.Listen(protocol, port)
	if err != nil {
		log.Fatal("Unable to launch listener on %s%s: %v", protocol, port, err)
	}
	defer listener.Close()
	log.Printf("platformListener: Listening on %s%s.", protocol, port)

	for {
		// No way to set listen(2) backlog here, see golang issues #39000, #6079.
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		remoteAddr := conn.RemoteAddr()
		terminalRequest := false

		// The read/write code here is intentionally very simplistic and uses
		// unbuffered reads and writes.
		//
		// TODO: We may want bufio here, but it's unclear what its semantics
		// are regarding buffer-sizes / SPAMming with an oversize command on
		// the read path.
		//
		// TODO: If we stay with unbuffered reads and writes, consider using
		// SetDeadline() to get the connection to time out if the other end
		// hangs?
		requestBuf := make([]byte, 512)
		if _, err := conn.Read(requestBuf); err != nil {
			log.Printf("[%s] Error reading from connection: %v", remoteAddr, err)
			conn.Close()
			continue
		}
		separator := bytes.Index(requestBuf, []byte("\n"))
		if separator == -1 {
			log.Printf("[%s] No command found, closing connection.", remoteAddr)
			conn.Close()
			continue
		}
		command := string(requestBuf[0:separator])

		var response []byte
		switch command {
		case "DEVICE-ID":
			log.Printf("[%s] Requested DEVICE-ID.", remoteAddr)
			// TODO: Not implemented yet.
			response = []byte("OK BAADC0DEBBADC0DEBCADC0DEBDADC0DE\n")
		case "SHUTDOWN":
			log.Printf("[%s] Requested SHUTDOWN.", remoteAddr)
			response = []byte("OK\n")
			terminalRequest = true
		case "REBOOT":
			log.Printf("[%s] Requested REBOOT.", remoteAddr)
			response = []byte("OK\n")
			terminalRequest = true
		case "RESET":
			log.Printf("[%s] Requested RESET.", remoteAddr)
			response = []byte("OK\n")
			terminalRequest = true
		default:
			log.Printf("[%s] Unknown command, closing connection.", remoteAddr)
			response = []byte("ERROR\n")
		}

		if _, err := conn.Write(response); err != nil {
			log.Printf("[%s] Error writing to connection: %v", remoteAddr, err)
			conn.Close()
			continue
		}

		conn.Close()
		if terminalRequest {
			result <- command
			return
		}
	}
}

// Kill all processes except self with sig.
// Note that this relies on Linux-specific behaviour of kill(2), where sending
// a signal to PID -1 will idempotently send it to all processes the caller has
// permission to kill, except the caller itself and init (PID 1). For details
// see the Linux manual page for the kill system call.
func killAll(sig os.Signal) {
	if err := syscall.Kill(-1, sig.(syscall.Signal)); err != nil {
		log.Printf("Error sending kill(-1, %s): %v", sig, err)
	}
}

// Extract the CPIO archiveFile in destDir, which must exist and be a directory.
func extractCpioArchive(archiveFile string, destDir string) (err error) {
	f, err := os.Open(archiveFile)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.Command("/bbin/cpio", "i")
	cmd.Stdin = f
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Dir = destDir
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

// storageActions are executed for "storage_linux".
func storageActions() {
	c := make(chan string)
	go platformListener(c, "tcp", ":1023")

	mountMuenFs()
	s.Logf("Channels:")
	s.Execf("/bbin/ls -l /muenfs")

	mountMuenEvents()
	s.Logf("Events:")
	s.Execf("/bbin/ls -l /muenevents")

	loadUnikernelNets()

	s.Execf("/bbin/ip addr add 169.254.169.2/24 dev net0")
	s.Execf("/bbin/ip link set dev net0 up")

	dumpNetworkStatus()

	s.Logf("Mounting /data")
	s.Execf("/bbin/mkdir -p /data")
	s.Execf("/bbin/mount -t ext4 /dev/sda2 /data")

	if err := s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}

	// If /data/initialised-v1 does NOT exist, assume /data is empty and
	// populate it from the template CPIO archive included in the initramfs.
	if _, err := os.Stat("/data/initialised-v1"); os.IsNotExist(err) {
		log.Printf("Populating /data")
		if err := extractCpioArchive("/tmpl/data.cpio", "/data"); err != nil {
			log.Printf("Error extracting /data template: %v", err)
			return
		}
	}

	s.Logf("Starting Git server")
	s.BackgroundExecAsf(GIT_UIDGID, "/bin/git daemon --base-path=/data/git --export-all --enable=receive-pack")

	if err := s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}

	// At this point we wait for a terminal request result from platformListener.
	request := <-c

	s.Logf("Terminating all processes.")
	killAll(syscall.Signal(15))
	time.Sleep(5 * time.Second)
	s.Logf("Killing all remaining processes.")
	killAll(syscall.Signal(9))
	s.Logf("Unmounting /data")
	s.Execf("/bbin/umount /data")

	if err := s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}

	switch request {
	case "SHUTDOWN":
		log.Printf("System will power off now.")
		time.Sleep(2 * time.Second)
		triggerMuenEvent("poweroff")
	case "REBOOT":
		log.Printf("System will reboot now.")
		time.Sleep(2 * time.Second)
		triggerMuenEvent("reboot")
	case "RESET":
		s.Logf("Formatting data partition.")
		s.Execf("/bin/mke2fs -t ext4 -E discard -F -m0 -L data /dev/sda2")

		if err := s.Err(); err != nil {
			log.Printf("Script failed: %v", err)
			return
		}

		log.Printf("System will reboot now.")
		time.Sleep(2 * time.Second)
		triggerMuenEvent("reboot")
	default:
		log.Printf("Unknown request, exiting anyway.")
	}
}

// mockActions are executed when testing (run with an argument of "mock").
func mockActions() {
	s.BackgroundExecf("sleep 5")
	if err := s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}

	c := make(chan string)
	go platformListener(c, "tcp", ":12345")
	log.Printf("platformListener returned: %s", <-c)
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
	case "mock":
		mockActions()
	default:
		log.Printf("Unknown hostname: %s", hostname)
		log.Printf("Not running any actions")
	}

	// Failsafe -- we have no console anyways on the Muen system, so we'll just
	// sit here forever.
	s.ClearErr()
	s.Logf("Hit ENTER to shut down")
	s.ReadLine()
	s.Execf("/bbin/shutdown halt")
}

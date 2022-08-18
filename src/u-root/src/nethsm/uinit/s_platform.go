package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// platformListener runs the "platform" protocol on the requested protocol and
// port.
//
// This is intended to be run as a goroutine, and upon receiving a terminal
// command will shut itself down, returning the terminal command via the
// result channel.
//
// Due to there being no way to set a listen(2) backlog in Go, >1 connections
// will be accepted but only served one at a time, in the order that the OS
// queues them.
func platformListener(result chan string) {
	listener, err := net.Listen(G.listenerProtocol, G.listenerPort)
	if err != nil {
		log.Fatal("Unable to launch listener on %s%s: %v", G.listenerProtocol,
			G.listenerPort, err)
	}
	defer listener.Close()
	log.Printf("platformListener: Listening on %s%s.", G.listenerProtocol,
		G.listenerPort)

	// haveUpdate is set to true if an UPDATE command was successfully
	// processed in a previous connection and COMMIT-UPDATE should be enabled.
	// COMMIT-UPDATE resets this value back to false.
	haveUpdate := false

	for {
		// No way to set listen(2) backlog here, see golang issues #39000, #6079.
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		remoteAddr := conn.RemoteAddr()

		// All requests except for UPDATE (see below) must complete within 5
		// seconds, otherwise an i/o timeout will be reported and the
		// connection will be shut down.
		conn.SetDeadline(time.Now().Add(time.Second * 5))

		// Wrap conn in a LimitedReader (lr) to ensure that we can't be DoS'ed
		// / run out of memory when doing operations such as ReadString().
		// Initially limit the amount read to 512 bytes, this limit is raised
		// appropriately when processing commands such as UPDATE which read
		// larger amounts of data from conn.
		lr := &io.LimitedReader{
			R: conn,
			N: 512,
		}
		// Further wrap (lr) in a buffered reader (r) so that we can use bufio
		// operations for reading.
		r := bufio.NewReader(lr)
		command, err := r.ReadString('\n')
		if err != nil {
			log.Printf("[%s] Error reading from connection: %v", remoteAddr, err)
			conn.Close()
			continue
		}
		command = strings.TrimSuffix(command, "\n")

		// Returns an OK response, optionally with a message if not empty.
		okResponse := func(m string) []byte {
			if m != "" {
				return []byte("OK " + m + "\n")
			} else {
				return []byte("OK\n")
			}
		}

		// Returns an ERROR response, optionally with an error message if e is
		// not nil.
		errorResponse := func(e error) []byte {
			if e != nil {
				return []byte("ERROR " + fmt.Sprintf("%v", e) + "\n")
			} else {
				return []byte("ERROR\n")
			}
		}

		// doXXX() are closures that process the actual command, this makes it
		// possible to use defer and return errors from within internal loops
		// easily. XXX Perhaps not the clearest or most idiomatic way to do
		// this.
		//
		// Each of these returns a (possibly nil) response, a (possibly nil)
		// error and the new value for terminalCommand.

		// DEVICE-ID
		doDeviceId := func() ([]byte, error, bool) {
			log.Printf("[%s] Requested DEVICE-ID.", remoteAddr)
			deviceId, err := tpmGetDeviceId(G.tpmDevice)
			if err != nil {
				return errorResponse(err), err, false
			} else {
				return okResponse(hex.EncodeToString(deviceId)), nil, false
			}
		}

		// UPDATE
		doUpdate := func() ([]byte, error, bool) {
			blockSize := 512
			// Read <blocks>\n
			param, err := r.ReadString('\n')
			if err != nil {
				return nil, err, false
			}
			param = strings.TrimSuffix(param, "\n")
			paramU64, err := strconv.ParseUint(param, 10, 0)
			if err != nil {
				return nil, err, false
			}
			// ParseUint() with a bitSize of 0 guarantees that the value can
			// fit in an int.
			updateBlocks := int(paramU64)
			if !(updateBlocks > 0) {
				err := fmt.Errorf("Update size must be >0")
				return errorResponse(err), err, false
			}

			log.Printf("[%s] Requested UPDATE (%d blocks).", remoteAddr, updateBlocks)
			// Allow 30 seconds for the actual UPDATE stream to complete.
			// This is more than enough for current size of the update image;
			// actual times to stream the image on real hardware are on the
			// order of 3 seconds, 10 seconds for KVM/QEMU.
			conn.SetDeadline(time.Now().Add(time.Second * 30))

			w, err := os.OpenFile(G.sysInactivePartition, os.O_WRONLY, 0)
			if err != nil {
				return errorResponse(err), err, false
			}
			defer w.Close()

			// Raise limit of lr to expected amount of data to read plus some
			// slack.
			lr.N = int64((updateBlocks + 1) * blockSize)
			buf := make([]byte, blockSize)
			block := 1
			for block <= updateBlocks {
				rn, err := io.ReadFull(r, buf)
				if err != nil {
					return nil, err, false
				} else if rn != blockSize {
					// This should never happen according to the documentation for
					// io.ReadFull, but better safe than sorry.
					err := fmt.Errorf("(%d/%d) Short read: %d", block, updateBlocks, rn)
					return errorResponse(err), err, false
				}

				wn, err := w.Write(buf)
				if err != nil {
					return errorResponse(err), err, false
				} else if wn != blockSize {
					err := fmt.Errorf("(%d/%d) Short write: %d", block, updateBlocks, wn)
					return errorResponse(err), err, false
				}
				block += 1
			}

			// Enable COMMIT-UPDATE.
			log.Printf("[%s] Successfuly wrote UPDATE to %s. (%d blocks)", remoteAddr,
				G.sysInactivePartition, block-1)
			haveUpdate = true

			return okResponse(""), nil, false
		}

		// COMMIT-UPDATE
		doCommitUpdate := func() ([]byte, error, bool) {
			log.Printf("[%s] Requested COMMIT-UPDATE.", remoteAddr)
			if haveUpdate == false {
				err := fmt.Errorf("No UPDATE in progress")
				return errorResponse(err), err, false
			}

			if err := gptSwapPartitions(G.diskDevice); err != nil {
				return errorResponse(err), err, false
			} else {
				haveUpdate = false
				return okResponse(""), nil, false
			}
		}

		var response []byte = nil
		var cmdErr error = nil
		terminalCommand := false
		switch command {
		case "DEVICE-ID":
			response, cmdErr, terminalCommand = doDeviceId()
		case "UPDATE":
			response, cmdErr, terminalCommand = doUpdate()
		case "COMMIT-UPDATE":
			response, cmdErr, terminalCommand = doCommitUpdate()
		case "SHUTDOWN":
			log.Printf("[%s] Requested SHUTDOWN.", remoteAddr)
			response = okResponse("")
			terminalCommand = true
		case "REBOOT":
			log.Printf("[%s] Requested REBOOT.", remoteAddr)
			response = okResponse("")
			terminalCommand = true
		case "FACTORY-RESET":
			log.Printf("[%s] Requested FACTORY-RESET.", remoteAddr)
			response = okResponse("")
			terminalCommand = true
		default:
			log.Printf("[%s] Unknown command, closing connection.", remoteAddr)
			response = errorResponse(fmt.Errorf("Unknown command"))
		}

		// If doXXX() returned an error, log it.
		if cmdErr != nil {
			log.Printf("[%s] Error processing %s: %v", remoteAddr, command, cmdErr)
		}

		// If doXXX() returned a response, send it out.
		if response != nil {
			if _, err := conn.Write(response); err != nil {
				log.Printf("[%s] Error writing to connection: %v", remoteAddr, err)
			}
		}

		conn.Close()
		if terminalCommand {
			result <- command
			return
		}
	}
}

// sPlatformActions are executed for S-Platform.
func sPlatformActions() {
	// Load TPM kernel modules first, as platformListener needs TPM for
	// GetDeviceId().
	G.s.Logf("Loading TPM driver")
	G.s.Execf("/bbin/insmod /lib/modules/" + G.kernelRelease +
		"/kernel/drivers/char/tpm/tpm_tis_core.ko")
	G.s.Execf("/bbin/insmod /lib/modules/" + G.kernelRelease +
		"/kernel/drivers/char/tpm/tpm_tis.ko force=1 interrupts=0")
	// Refuse to continue if the above failed.
	if err := G.s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}
	c := make(chan string)
	go platformListener(c)

	mountMuenFs()
	G.s.Logf("Channels:")
	G.s.Execf("/bbin/ls -l /muenfs")

	mountMuenEvents()
	G.s.Logf("Events:")
	G.s.Execf("/bbin/ls -l /muenevents")

	loadUnikernelNets()

	G.s.Execf("/bbin/ip addr add 169.254.169.2/24 dev net0")
	G.s.Execf("/bbin/ip link set dev net0 up")

	dumpNetworkStatus()

	G.s.Logf("Mounting /data")
	G.s.Execf("/bbin/mkdir -p /data")
	G.s.Execf("/bbin/mount -t ext4 -o nodev,noexec,nosuid /dev/sda3 /data")

	if err := G.s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}

	// If /data/initialised-<buildTag> does NOT exist, assume /data is empty and
	// populate it from the template CPIO archive included in the initramfs.
	const initFile = "/data/initialised-" + buildTag
	if _, err := os.Stat(initFile); os.IsNotExist(err) {
		_ = os.RemoveAll("/data/./")
		log.Printf("Populating /data")
		if err := extractCpioArchive("/tmpl/data.cpio", "/data"); err != nil {
			log.Printf("Error extracting /data template: %v", err)
			return
		}
		f, err := os.OpenFile(initFile, os.O_RDONLY|os.O_CREATE, 0o644)
		if err != nil {
			log.Printf("Error creating %s: %v", initFile, err)
			return
		}
		f.Close()
	}

	G.s.Logf("Starting etcd server")
	G.s.BackgroundExecAsf(G.etcdUidGid, "/bin/etcd"+
		" --listen-client-urls=http://169.254.169.2:2379"+
		" --advertise-client-urls="+
		" --data-dir=/data/etcd"+
		" --snapshot-count=5000"+
		" --auto-compaction-retention=1h"+
		" --quota-backend-bytes=4294967296"+ // should not be more than RAM
		" --initial-cluster-state=new"+
		" --v2-deprecation=gone"+
		" --enable-v2=false"+
		" --proxy=off"+
		" --force-new-cluster=true"+
		// " --log-level debug"+
		"")

	if err := G.s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}

	// At this point we wait for a terminal request result from platformListener.
	request := <-c

	G.s.Logf("Terminating all processes.")
	killAll(syscall.Signal(15))
	time.Sleep(5 * time.Second)
	G.s.Logf("Killing all remaining processes.")
	killAll(syscall.Signal(9))
	G.s.Logf("Unmounting /data")
	G.s.Execf("/bbin/umount /data")

	if err := G.s.Err(); err != nil {
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
	case "FACTORY-RESET":
		G.s.Logf("Formatting data partition.")
		G.s.Execf("/bin/mke2fs -t ext4 -E discard -F -m0 -L data /dev/sda3")

		if err := G.s.Err(); err != nil {
			log.Printf("Script failed: %v", err)
			return
		}

		// TODO: This is currently done here for testing. We should decide what
		// (if anything) is to be done about "Device ID" at RESET time in any
		// final design.
		log.Printf("Deleting Device ID from TPM.")
		err := tpmDeleteDeviceId(G.tpmDevice)
		if err != nil {
			// Deliberately non-fatal.
			log.Printf("TPM: DeleteDeviceId() failed: %v", err)
		}

		log.Printf("System will reboot now.")
		time.Sleep(2 * time.Second)
		triggerMuenEvent("reboot")
	default:
		log.Printf("Unknown request, exiting anyway.")
	}
}

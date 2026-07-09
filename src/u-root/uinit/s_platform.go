// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nethsm/internal/hw"
	"nethsm/internal/localconf"
	"nethsm/internal/script"
	"nethsm/internal/util"
)

type clusterLogItem = map[string]any

type clusterSnapshot struct {
	Hash      uint32  `json:"hash"`
	Revision  int64   `json:"revision"`
	TotalKey  int     `json:"totalKey"`
	TotalSize int64   `json:"totalSize"`
	Version   *string `json:"version,omitempty"`
}

type clusterState struct {
	Exited   *int `json:"exited,omitempty"`
	Signaled *int `json:"signaled,omitempty"`
	Stopped  *int `json:"stopped,omitempty"`
	Running  bool `json:"running"`
}

type diagnoseData struct {
	ClusterLogs     []clusterLogItem `json:"clusterLogs"`
	ClusterSnapshot *clusterSnapshot `json:"clusterSnapshot,omitempty"`
	ClusterState    clusterState     `json:"clusterState"`
}

// okResponse returns an OK response, optionally with a message if not empty.
func okResponse(m string) []byte {
	if m != "" {
		return []byte("OK " + m + "\n")
	}
	return []byte("OK\n")
}

// errorResponse returns an ERROR response, optionally with an error message if e is not nil.
func errorResponse(e error) []byte {
	if e != nil {
		return []byte("ERROR " + e.Error() + "\n")
	}
	return []byte("ERROR\n")
}

// getClusterState returns the etcd process's state
func getClusterState(processState *os.ProcessState) (cs clusterState) {
	if processState == nil {
		cs.Running = true
		return
	}
	cs.Running = false

	if processState.Exited() {
		code := processState.ExitCode()
		cs.Exited = &code
		return
	}

	if sys, ok := processState.Sys().(syscall.WaitStatus); ok {
		if sys.Exited() {
			code := sys.ExitStatus()
			cs.Exited = &code
		}
		if sys.Signaled() {
			sig := int(sys.Signal())
			cs.Signaled = &sig
		}
		if sys.Stopped() {
			stopSig := int(sys.StopSignal())
			cs.Stopped = &stopSig
		}
	}
	return
}

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
func platformListener(
	result chan string,
	platformDataCh <-chan platformData,
	proto, addr string,
	supervisor *etcdSupervisor,
) {
	listener, err := net.Listen(proto, addr)
	if err != nil {
		log.Fatalf("Unable to launch listener on %s:%s: %v", proto, addr, err)
	}
	defer util.Close(listener)
	log.Printf("platformListener: Listening on %s:%s.", proto, addr)

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
		err = conn.SetDeadline(time.Now().Add(time.Second * 5))
		if err != nil {
			log.Printf("Failed to set deadline: %v", err)
		}

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
			util.Close(conn)
			continue
		}
		command = strings.TrimSuffix(command, "\n")

		// doXXX() are closures that process the actual command, this makes it
		// possible to use defer and return errors from within internal loops
		// easily. XXX Perhaps not the clearest or most idiomatic way to do
		// this.
		//
		// Each of these returns a (possibly nil) response, a (possibly nil)
		// error and the new value for terminalCommand.

		// PLATFORM-DATA
		doPlatformData := func() ([]byte, error, bool) {
			log.Printf("[%s] Requested PLATFORM-DATA.", remoteAddr)
			data, ok := <-platformDataCh
			if !ok {
				err := fmt.Errorf("platform data has been read already")
				return errorResponse(err), err, false
			}
			json, err := json.Marshal(data)
			if err != nil {
				return errorResponse(err), err, false
			}
			return okResponse(string(json)), nil, false
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
			if updateBlocks <= 0 {
				err := fmt.Errorf("update size must be >0")
				return errorResponse(err), err, false
			}

			log.Printf("[%s] Requested UPDATE (%d blocks).", remoteAddr, updateBlocks)
			// Allow 30 seconds for the actual UPDATE stream to complete.
			// This is more than enough for current size of the update image;
			// actual times to stream the image on real hardware are on the
			// order of 3 seconds, 10 seconds for KVM/QEMU.
			err = conn.SetDeadline(time.Now().Add(time.Second * 30))
			if err != nil {
				log.Printf("Failed to set deadline: %v", err)
			}

			w, err := os.OpenFile(sysInactivePartition, os.O_WRONLY, 0)
			if err != nil {
				return errorResponse(err), err, false
			}
			defer util.Close(w)

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
				block++
			}

			// Enable COMMIT-UPDATE.
			log.Printf("[%s] Successfuly wrote UPDATE to %s. (%d blocks)", remoteAddr,
				sysInactivePartition, block-1)
			haveUpdate = true

			return okResponse(""), nil, false
		}

		// JOIN-CLUSTER
		doJoinCluster := func() ([]byte, error, bool) {
			err = conn.SetDeadline(time.Now().Add(time.Second * 150))
			if err != nil {
				log.Printf("Failed to set deadline: %v", err)
			}
			param, err := r.ReadString('\n')
			if err != nil {
				return nil, err, false
			}
			initialCluster := strings.TrimSuffix(param, "\n")
			log.Printf("[%s] Requested JOIN-CLUSTER (%s).", remoteAddr, initialCluster)
			reply := make(chan error, 1)
			supervisor.SendCmd(EtcdCommand{
				Kind:     EtcdCmdJoin,
				JoinArgs: JoinArgs{initialCluster},
				Reply:    reply,
			})
			if err := <-reply; err != nil {
				return errorResponse(err), err, false
			}
			return okResponse(""), nil, false
		}

		doDiagnose := func() ([]byte, error, bool) {
			log.Printf("[%s] Requested DIAGNOSE!", remoteAddr)
			var data diagnoseData
			data.ClusterState = getClusterState(supervisor.ProcessState.Load())
			if !data.ClusterState.Running {
				log.Printf("DIAGNOSE: Getting etcd snapshot status")
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "/bin/etcdutl", "snapshot", "status", "/data/etcd/member/snap/db", "-w", "json")
				result := make(chan []byte)
				go func() {
					defer close(result)
					output, err := cmd.Output()
					if err != nil {
						log.Printf("DIAGNOSE error: %s", err)
					} else {
						result <- output
					}
				}()
				if out, ok := <-result; ok {
					clusterSnapshot := new(clusterSnapshot)
					if err := json.Unmarshal(out, &clusterSnapshot); err != nil {
						log.Printf("DIAGNOSE: snapshot status: %s", out)
						log.Printf("DIAGNOSE: Failed to parse snapshot status: %s", err)
					} else {
						data.ClusterSnapshot = clusterSnapshot
					}
				} else {
					log.Printf("DIAGNOSE: snapshot status failed or timed out")
				}
			}

			data.ClusterLogs = util.RingCollect[clusterLogItem](supervisor.Logs.Load())

			json, err := json.Marshal(data)
			if err != nil {
				log.Printf("DIAGNOSE: error %v", err)
				return errorResponse(err), err, false
			}
			log.Printf("DIAGNOSE: OK: %s", json)
			return okResponse(string(json)), nil, false
		}

		doForceNewCluster := func() ([]byte, error, bool) {
			log.Printf("[%s] Requested FORCE-NEW-CLUSTER.", remoteAddr)
			reply := make(chan error, 1)
			supervisor.SendCmd(EtcdCommand{
				Kind:  EtcdCmdForceNew,
				Reply: reply,
			})
			if err := <-reply; err != nil {
				return errorResponse(err), err, false
			}
			return okResponse(""), nil, true
		}

		// COMMIT-UPDATE
		doCommitUpdate := func() ([]byte, error, bool) {
			log.Printf("[%s] Requested COMMIT-UPDATE.", remoteAddr)
			if !haveUpdate {
				err := fmt.Errorf("no UPDATE in progress")
				return errorResponse(err), err, false
			}

			if err := gptSwapPartitions(hw.DiskDev); err != nil {
				return errorResponse(err), err, false
			}
			haveUpdate = false
			return okResponse(""), nil, false
		}

		// SET-LOCAL-CONFIG
		doSetLocalConfig := func() ([]byte, error, bool) {
			err = conn.SetDeadline(time.Now().Add(time.Second * 50))
			if err != nil {
				log.Printf("Failed to set deadline: %v", err)
			}
			param, err := r.ReadString('\n')
			if err != nil {
				return nil, err, false
			}
			param = strings.TrimSuffix(param, "\n")
			paramU64, err := strconv.ParseUint(param, 10, 0)
			if err != nil {
				return nil, err, false
			}
			dataSize := int(paramU64)
			log.Printf("[%s] Requested SET-LOCAL-CONFIG (%d bytes).", remoteAddr, dataSize)
			lr.N = int64(dataSize * 2)
			configJSON := make([]byte, dataSize)
			_, err = io.ReadFull(r, configJSON)
			if err != nil {
				return errorResponse(err), err, false
			}
			err = localconf.Set(configJSON, setTimeAndUpdateOffset)
			if err != nil {
				err := fmt.Errorf("couldn't store local config: %w", err)
				return errorResponse(err), err, false
			}
			return okResponse(""), nil, false
		}

		var response []byte
		var cmdErr error
		terminalCommand := false
		switch command {
		case "PLATFORM-DATA":
			response, cmdErr, terminalCommand = doPlatformData()
		case "SET-LOCAL-CONFIG":
			response, cmdErr, terminalCommand = doSetLocalConfig()
		case "UPDATE":
			response, cmdErr, terminalCommand = doUpdate()
		case "COMMIT-UPDATE":
			response, cmdErr, terminalCommand = doCommitUpdate()
		case "FORCE-NEW-CLUSTER":
			response, cmdErr, terminalCommand = doForceNewCluster()
		case "JOIN-CLUSTER":
			response, cmdErr, terminalCommand = doJoinCluster()
		case "DIAGNOSE":
			response, cmdErr, terminalCommand = doDiagnose()
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
			response = errorResponse(fmt.Errorf("unknown command"))
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

		util.Close(conn)
		if terminalCommand {
			result <- command
			return
		}
	}
}

func setupPlatform(s *script.Script) error {
	if hw.IsTesting() {
		err := os.MkdirAll("/data/etcd", 0o755)
		check(err)
		err = os.Chown("/data/etcd", etcdUIDGID, etcdUIDGID)
		check(err)
		return nil
	}

	// Load TPM kernel modules first, as platformListener needs TPM for
	// GetDeviceKey().
	s.Logf("Loading TPM driver")
	s.Execf("/bbin/insmod /lib/modules/%s/kernel/drivers/char/tpm/tpm_tis_core.ko", kernelRelease)
	s.Execf("/bbin/insmod /lib/modules/%s/kernel/drivers/char/tpm/tpm_tis.ko force=1 interrupts=0", kernelRelease)

	mountMuenFs(s)

	s.Logf("Channels:")
	s.Execf("/bbin/ls -l /muenfs")

	mountMuenEvents(s)

	s.Logf("Events:")
	s.Execf("/bbin/ls -l /muenevents")

	loadUnikernelNets(s)

	s.Execf("/bbin/ip addr add 169.254.169.2/24 dev net0") // comm with keyfender
	s.Execf("/bbin/ip -6 addr add fc00:1:169::2/120 dev net0")
	s.Execf("/bbin/ip addr add 169.254.200.2/24 dev net1") // comm with router
	s.Execf("/bbin/ip -6 addr add fc00:1:200::2/120 dev net1")
	s.Execf("/bbin/ip link set dev net0 up")
	s.Execf("/bbin/ip link set dev net1 up")
	// route etcd peer connections through router
	s.Execf("/bbin/ip route replace default via 169.254.200.1 dev net1")
	s.Execf("/bbin/ip -6 route replace default via fc00:1:200::1 dev net1")

	for retry := range 20 {
		net0, err := net.InterfaceByName("net0")
		if err != nil {
			return err
		}
		net1, err := net.InterfaceByName("net1")
		if err != nil {
			return err
		}
		if (net0.Flags&net.FlagRunning != 0) && (net1.Flags&net.FlagRunning != 0) {
			log.Printf("interfaces are UP")
			break
		}
		if retry >= 19 {
			return fmt.Errorf("timeout waiting for net0 and net1 to be UP")
		}
		time.Sleep(1 * time.Second)
	}

	dumpNetworkStatus()

	s.Logf("Mounting /data")
	s.Execf("/bbin/mkdir -p /data")
	s.Execf("/bbin/mount -t ext4 -o nodev,noexec,nosuid " + hw.DiskPrefix + "3 /data")

	if err := s.Err(); err != nil {
		return fmt.Errorf("script failed: %w", err)
	}

	// If /data/initialised-v1 does NOT exist, assume /data is empty and
	// populate it from the template CPIO archive included in the initramfs.
	const initFile = "/data/initialised-v1"
	if _, err := os.Stat(initFile); os.IsNotExist(err) {
		log.Printf("Populating /data")
		if err := util.ExtractCpioArchive("/tmpl/data.cpio", "/data"); err != nil {
			return fmt.Errorf("error extracting /data template: %w", err)
		}
	}

	// Ensure /bin/etcd and /bin/etcdutl are present and executable
	s.Execf("/bin/etcd --version")
	if err := s.Err(); err != nil {
		return fmt.Errorf("etcd is not properly installed: %w", err)
	}
	s.Execf("/bin/etcdutl version")
	if err := s.Err(); err != nil {
		return fmt.Errorf("etcdutl is not properly installed: %w", err)
	}

	return nil
}

// sPlatformActions are executed for S-Platform.
func sPlatformActions() {
	s := script.New()
	if err := setupPlatform(s); err != nil {
		log.Printf("setupPlatform: %v", err)
		return
	}

	terminalCh := make(chan string)
	platformDataCh := make(chan platformData, 1)

	supervisor := NewEtcdSupervisor()
	util.StartTask("TRNG", trngTask)
	util.StartTask("Platform Listener", func() {
		platformListener(
			terminalCh,
			platformDataCh,
			listenerProtocol,
			platListenerAddress,
			supervisor,
		)
	})

	if !hw.IsTesting() {
		if err := tpmCreatePlatformData(platformDataCh); err != nil {
			log.Printf("Creating platform data failed: %v", err)
		}
	} else {
		mockCreatePlatformData(platformDataCh)
	}

	// now localconf is initialized and platformData has been read by keyfender

	util.StartTask("time", NewTimeTask().Run)

	<-TimeInitializedSig // wait for initial NTP attempt before starting etcd

	util.StartTask("etcd supervisor", supervisor.Run)

	// At this point we wait for a terminal request result from platformListener.
	request := <-terminalCh

	if hw.IsTesting() {
		log.Printf("received terminal command, exiting: %s", request)
		return
	}

	supervisor.Shutdown()

	log.Printf("Terminating all processes.")
	util.KillAll(syscall.Signal(15))
	time.Sleep(5 * time.Second)
	log.Printf("Killing all remaining processes.")
	util.KillAll(syscall.Signal(9))
	log.Printf("Unmounting /data")
	s = script.New()
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
	case "FORCE-NEW-CLUSTER":
		fallthrough
	case "REBOOT":
		log.Printf("System will reboot now.")
		time.Sleep(2 * time.Second)
		triggerMuenEvent("reboot")
	case "FACTORY-RESET":
		s = script.New()
		s.Logf("Formatting data partition.")
		s.Execf("/bin/mke2fs -t ext4 -E discard -F -m0 -L data " + hw.DiskPrefix + "3")

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

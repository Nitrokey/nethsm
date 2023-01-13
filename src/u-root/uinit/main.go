// uinit is our main extension point for u-root. This code gets compiled into
// "/bbin/uinit" and executed by u-root's "init" at boot time.
//
// As our u-root is shared between all Muen Linux subjects, uinit expects a
// single argument on the command line, which selects what actions are taken
// depending on the Linux subject that is being booted.
//
// Additionally, an argument of "mock" may be used to run a "mock" uinit for
// testing purposes. See mock.go for details on how this works.
package main

import (
	"log"
	"os"
	"syscall"

	Script "nethsm/uinit/script"
)

// globalState encapsulates global variables shared across the uinit codebase.
// With the exception of s, which mutates, all of these are essentially
// constants intended to be set up once in main(). There are definitely better,
// cleaner and more idiomatic ways to do this in Go, but as uinit is
// essentially a "script", this will have to do.
type globalState struct {
	// s represents our global Script context.
	s *Script.Script
	// UID and GID that the etcd server is run as. We use 1 (coventionally,
	// "daemon").
	etcdUidGid int
	// Current kernel release.
	kernelRelease        string
	diskDevice           string
	sysActivePartition   string
	sysInactivePartition string
	dataPartition        string
	tpmDevice            string
	listenerProtocol     string
	listenerPort         string
}

// This is the actual singleton instance of globalState used throughout. This
// way it is at least obvious from the code when it is referring to a variable
// from globalState, as G.variable.
var G = &globalState{
	s:                    Script.New(),
	etcdUidGid:           1,
	kernelRelease:        getKernelRelease(),
	diskDevice:           "/dev/sda",
	sysActivePartition:   "/dev/sda1",
	sysInactivePartition: "/dev/sda2",
	dataPartition:        "/dev/sda3",
	tpmDevice:            "/dev/tpm0",
	listenerProtocol:     "tcp",
	listenerPort:         ":1023",
}

func main() {
	// We expect a hostname to be passed in via the kernel's boot parameters,
	// as uroot.uinitargs=HOSTNAME.
	hostname := "(none)"
	if len(os.Args) == 2 {
		hostname = os.Args[1]
	}
	log.SetPrefix(hostname + ": ")

	switch hostname {
	case "net_external":
		log.Printf("Booting subject: S-Net-External")
		sNetExternalActions()
	case "platform":
		log.Printf("Booting subject: S-Platform")
		sPlatformActions()
	case "mock":
		log.Printf("Mock mode")
		G.diskDevice = safeGetenv("MOCK_DISK_DEVICE", "/dev/null")
		G.sysActivePartition = safeGetenv("MOCK_SYS_ACTIVE_PARTITION", "/dev/null")
		G.sysInactivePartition = safeGetenv("MOCK_SYS_INACTIVE_PARTITION", "/dev/null")
		G.dataPartition = safeGetenv("MOCK_DATA_PARTITION", "/dev/null")
		G.tpmDevice = safeGetenv("MOCK_TPM_DEVICE", "/dev/null")
		G.listenerPort = safeGetenv("MOCK_LISTENER_PORT", ":12345")

		mockActions()
		// In mock mode we just exit here instead of halting.
		return
	default:
		log.Printf("Unknown subject hostname: %s", hostname)
	}

	// If we get here then we are done with boot-time actions. We don't want to
	// halt, so just pause forever, rather than exiting which would result in
	// u-root init's default behaviour of dropping into a shell.
	G.s.ClearErr()
	G.s.Logf("Done")
	for {
		syscall.Pause()
	}
}

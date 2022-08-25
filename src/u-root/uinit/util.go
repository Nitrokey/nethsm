package main

import (
	"log"
	"os"
	"os/exec"
	"syscall"
)

// Returns the current kernel release (a.k.a. "uname -r").
func getKernelRelease() string {
	toString := func(f [65]int8) string {
		out := make([]byte, 0, 64)
		for _, v := range f[:] {
			if v == 0 {
				break
			}
			out = append(out, uint8(v))
		}
		return string(out)
	}

	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		log.Printf("Could not determine kernel release: %v", err)
		return ""
	}
	return toString(u.Release)
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

// safeGetenv is like os.Getenv but with a default supplied if the environment
// variable does not exist.
func safeGetenv(key string, defaultValue string) string {
	value, found := os.LookupEnv(key)
	if found {
		return value
	} else {
		return defaultValue
	}
}

// Dump network status.
// Uses global Script context.
func dumpNetworkStatus() {
	G.s.Logf("Interfaces:")
	G.s.Execf("/bbin/ip link")
	G.s.Logf("Addresses:")
	G.s.Execf("/bbin/ip addr")
	G.s.Logf("Routes:")
	G.s.Execf("/bbin/ip route")
}

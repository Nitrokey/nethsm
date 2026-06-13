// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

// Package util provides small utility helpers
package util

import (
	"container/ring"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime/debug"
	"sync"
	"syscall"
)

// GetKernelRelease returns the current kernel release (a.k.a. "uname -r").
func GetKernelRelease() string {
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

// KillAll processes except self with sig.
// Note that this relies on Linux-specific behaviour of kill(2), where sending
// a signal to PID -1 will idempotently send it to all processes the caller has
// permission to kill, except the caller itself and init (PID 1). For details
// see the Linux manual page for the kill system call.
func KillAll(sig os.Signal) {
	if err := syscall.Kill(-1, sig.(syscall.Signal)); err != nil {
		log.Printf("Error sending kill(-1, %s): %v", sig, err)
	}
}

// ExtractCpioArchive extracts the CPIO archiveFile in destDir, which must exist and be a directory.
func ExtractCpioArchive(archiveFile string, destDir string) (err error) {
	f, err := os.Open(archiveFile)
	if err != nil {
		return err
	}
	defer Close(f)

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

// SafeGetenv is like os.Getenv but with a default supplied if the environment
// variable does not exist.
func SafeGetenv(key string, defaultValue string) string {
	value, found := os.LookupEnv(key)
	if found {
		return value
	} else {
		return defaultValue
	}
}

// StartTask starts a goroutine that executes function f and logs its lifecycle.
func StartTask(name string, f func()) {
	go func() {
		log.Printf("%s task started.", name)
		defer func() {
			if err := recover(); err != nil {
				log.Printf("%s task failed: %v", name, err)
				log.Print("stacktrace:\n" + string(debug.Stack()))
			} else {
				log.Printf("%s task finished.", name)
			}
		}()
		f()
	}()
}

// MakeNtfyPair creates a 1-to-many pair of a safe one-time-use notify function
// and a broadcast signal channel.
func MakeNtfyPair() (func(), <-chan struct{}) {
	ch := make(chan struct{})
	var once sync.Once
	emit := func() {
		once.Do(func() {
			close(ch)
		})
	}
	return emit, ch
}

// RingCollect returns all non-nil values of type T stored in r.
func RingCollect[T any](r *ring.Ring) []T {
	if r == nil {
		return nil
	}
	result := []T{}
	r.Do(func(v any) {
		if item, ok := v.(T); ok {
			result = append(result, item)
		}
	})
	return result
}

// Close closes the provided Closer and logs any error encountered.
func Close(c io.Closer) {
	err := c.Close()
	if err != nil {
		log.Printf("failed to close: %v", err)
		log.Print("stacktrace:\n" + string(debug.Stack()))
	}
}

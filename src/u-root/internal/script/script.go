// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

// Package script is a grab-bag of functions for easy shell-like "scripting".
//
// To reduce code verbosity, these functions do not return errors. Instead,
// the first occurence of an error causes all invocations on a Script to become
// no-ops, and all functions returning a value to return either false or nil.
// script.Err() should be used at the end of a block relying on any
// side-effects to detect the presence of an error. For example:
//
// s := Script.New()
// s.Execf("/bbin/ip addr add 192.168.1.0/24 dev eth")
// s.Execf("/bbin/ip link set dev eth0 up")
//
//	if err := s.Err(); err != nil {
//	 // Handle err
//	}
package script

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"

	"nethsm/internal/util"
)

// Script type
type Script struct {
	err error
}

// New returns a new Script.
func New() *Script {
	return &Script{}
}

// Err returns the error associated with Script, if any.
func (s *Script) Err() error {
	return s.err
}

// Logf logs a fmt-formatted message.
func (s *Script) Logf(format string, a ...any) {
	if s.err != nil {
		return
	}

	log.Printf(format, a...)
}

// ExecAsf executes a fmt-formatted command as the given UID and GID.
func (s *Script) ExecAsf(uidgid int, format string, a ...any) {
	if s.err != nil {
		return
	}

	cmdString := fmt.Sprintf(format, a...)
	cmdSplit := strings.Split(cmdString, " ")

	cmd := exec.Command(cmdSplit[0], cmdSplit[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if uidgid != -1 {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uidgid), Gid: uint32(uidgid)}
	}

	if err := cmd.Run(); err != nil {
		s.err = fmt.Errorf("Exec(%s) failed: %v", cmdString, err)
	}
}

// Execf executes a fmt-formatted command.
func (s *Script) Execf(format string, a ...any) {
	s.ExecAsf(-1, format, a...)
}

// CancelableBackgroundExecAsf executes a fmt-formatted command in the background. Provision is
// made for retrieving it's exit status, and the child is reaped and a message is
// logged on exit. If uidgid is not -1, the command is executed with an UID
// and GID equal to uidgid.
// This function returns a "cancel" function which, when called, kills the
// running command if running. It also returns a pointer to the process's exit state.
// exitedNtfy is required and called once the command has exited or failed to
// start. It also returns the read end of a pipe with the command's stderr, which
// the caller has to close.
func (s *Script) CancelableBackgroundExecAsf(exitedNtfy func(), processState *atomic.Pointer[os.ProcessState], uidgid int, format string, a ...any) (context.CancelFunc, io.ReadCloser) {
	earlyExitNtfy := exitedNtfy
	defer func() {
		if earlyExitNtfy != nil {
			earlyExitNtfy()
		}
	}()

	if processState != nil {
		processState.Store(nil)
	}

	if s.err != nil {
		return nil, nil
	}

	cmdString := fmt.Sprintf(format, a...)
	cmdSplit := strings.Split(cmdString, " ")

	context, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(context, cmdSplit[0], cmdSplit[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	// Cancel will kill with a SIGINT instead of a SIGKILL
	cmd.Cancel = func() error {
		return cmd.Process.Signal(os.Interrupt)
	}
	// Does go have an option type? Could use that instead of -1.
	if uidgid != -1 {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uidgid), Gid: uint32(uidgid)}
	}
	// Not cmd.StderrPipe(): Wait() would close it, losing unread output.
	logPipe, w, err := os.Pipe()
	if err != nil {
		s.err = fmt.Errorf("cannot create stderr pipe: %v", err)
		return cancel, nil
	}
	defer util.Close(w) // the child has its own copy, ours would prevent EOF
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		util.Close(logPipe)
		s.err = fmt.Errorf("Exec(%s) failed: %v", cmdString, err)
		return cancel, nil
	}
	go func() {
		defer exitedNtfy()
		err := cmd.Wait()
		if processState != nil {
			processState.Store(cmd.ProcessState)
		}
		if err != nil {
			log.Printf("Background process '%s' exited with status: %v", cmdSplit[0], err)
		} else {
			log.Printf("Background process '%s' exited", cmdSplit[0])
		}
	}()
	// we no longer want to call exitedNtfy, the goroutine above will do that
	earlyExitNtfy = nil
	return cancel, logPipe
}

// Glob is the equivalent of filepath.Glob.
func (s *Script) Glob(glob string) []string {
	if s.err != nil {
		return nil // XXX correct?
	}

	matches, err := filepath.Glob(glob)
	if err != nil {
		s.err = fmt.Errorf("Glob(%s) failed: %v", glob, err)
		return nil
	}
	return matches
}

// FileExists returns true if filename exists, false otherwise.
func (s *Script) FileExists(filename string) bool {
	if s.err != nil {
		return false // XXX correct?
	}

	_, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		} else {
			s.err = err
			return false
		}
	}
	return true
}

// WriteFile writes some data into a file
func (s *Script) WriteFile(path string, value string) {
	if s.err != nil {
		return
	}
	err := os.WriteFile(path, []byte(value), 0o644)
	if err != nil {
		s.err = err
	}
}

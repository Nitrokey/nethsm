// Script is a grab-bag of functions for easy shell-like "scripting".
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
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type Script struct {
	err error
}

// New returns a new Script.
func New() *Script {
	return &Script{}
}

// ClearErr clears the error associated with Script, if any.
func (s *Script) ClearErr() {
	s.err = nil
}

// Err returns the error associated with Script, if any.
func (s *Script) Err() error {
	return s.err
}

// Logf logs a fmt-formatted message.
func (s *Script) Logf(format string, a ...interface{}) {
	if s.err != nil {
		return
	}

	log.Printf(format, a...)
}

// Execf executes a fmt-formatted command.
func (s *Script) Execf(format string, a ...interface{}) {
	if s.err != nil {
		return
	}

	cmdString := fmt.Sprintf(format, a...)
	cmdSplit := strings.Split(cmdString, " ")
	if len(cmdSplit) == 0 {
		s.err = fmt.Errorf("Empty command string")
		return
	}

	cmd := exec.Command(cmdSplit[0], cmdSplit[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		s.err = fmt.Errorf("Exec(%s) failed: %v", cmdString, err)
	}
}

// BackgroundExecAsf executes a fmt-formatted command in the background. No provision is
// made for retrieving it's exit status, however the child is reaped and a message is
// logged on exit. If uidgid is not -1, the command is executed with an UID
// and GID equal to uidgid.
func (s *Script) BackgroundExecAsf(uidgid int, format string, a ...interface{}) {
	if s.err != nil {
		return
	}

	cmdString := fmt.Sprintf(format, a...)
	cmdSplit := strings.Split(cmdString, " ")
	if len(cmdSplit) == 0 {
		s.err = fmt.Errorf("Empty command string")
		return
	}

	cmd := exec.Command(cmdSplit[0], cmdSplit[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	// Does go have an option type? Could use that instead of -1.
	if uidgid != -1 {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uidgid), Gid: uint32(uidgid)}
	}
	if err := cmd.Start(); err != nil {
		s.err = fmt.Errorf("Exec(%s) failed: %v", cmdString, err)
	}
	go func(child *exec.Cmd) {
		err := child.Wait()
		if err != nil {
			log.Printf("Background process '%s' exited with status: %v", cmdSplit[0], err)
		} else {
			log.Printf("Background process '%s' exited", cmdSplit[0])
		}
	}(cmd)
}

func (s *Script) BackgroundExecf(format string, a ...interface{}) {
	s.BackgroundExecAsf(-1, format, a...)
}

// ReadLine reads a line from standard input.
func (s *Script) ReadLine() string {
	if s.err != nil {
		return "" // XXX correct?
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	err := scanner.Err()
	if err != nil {
		s.err = fmt.Errorf("ReadLine() failed: %v", err)
		return ""
	}
	return scanner.Text()
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

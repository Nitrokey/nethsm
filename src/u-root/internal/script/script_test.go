// SPDX-License-Identifier: EUPL-1.2

package script

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"nethsm/internal/util"
)

var tests = map[string]struct {
	inCancel    bool
	outSuccess  bool
	outStarted  bool
	outExitCode int
}{
	"/bin/true":                {false, true, true, 0},
	"/bin/false":               {false, false, true, 1},
	"/bin/sleep 120":           {true, false, true, -1},
	"/nonexistent/nonexistent": {false, false, false, -1},
}

func TestCancelableBackgroundExecAsf(t *testing.T) {
	for cmd, test := range tests {
		t.Run(cmd, func(t *testing.T) {
			t.Parallel()
			s := New()
			exitedNtfy, exitedSig := util.MakeNtfyPair()
			processState := new(atomic.Pointer[os.ProcessState])
			cancel, pipe := s.CancelableBackgroundExecAsf(exitedNtfy, processState, -1, "%s", cmd)
			if test.inCancel {
				t.Logf("Calling cancel()")
				cancel()
			}

			if pipe != nil {
				defer util.Close(pipe)
				stderr, err := io.ReadAll(pipe)
				if err != nil {
					t.Errorf("Cannot read stderr: %v", err)
				} else if len(stderr) > 0 {
					t.Errorf("Unexpected stderr output: %s", stderr)
				}
			}

			started := pipe != nil
			if started != test.outStarted {
				t.Errorf("started: got %t, wanted %t", started, test.outStarted)
			}

			<-exitedSig

			state := processState.Load()
			if state == nil && test.outStarted {
				t.Errorf("no processState set")
			} else {
				if got := state.ExitCode(); got != test.outExitCode {
					t.Errorf("got %v, wanted %d", state, test.outExitCode)
				}
			}
		})
	}
}

// The last lines are the ones saying why a process died.
func TestCancelableBackgroundExecAsfKeepsAllOutput(t *testing.T) {
	cmd := filepath.Join(t.TempDir(), "cmd")
	script := "#!/bin/sh\ni=0\nwhile [ $i -lt 400 ]; do echo line$i >&2; i=$((i+1)); done\necho last >&2\nexit 1\n"
	if err := os.WriteFile(cmd, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for range 300 {
		s := New()
		exitedNtfy, exitedSig := util.MakeNtfyPair()
		_, pipe := s.CancelableBackgroundExecAsf(exitedNtfy, nil, -1, "%s", cmd)
		if err := s.Err(); err != nil {
			t.Fatal(err)
		}
		stderr, err := io.ReadAll(pipe)
		util.Close(pipe)
		<-exitedSig
		if err != nil {
			t.Fatalf("Cannot read stderr: %v", err)
		}
		if !strings.HasSuffix(string(stderr), "last\n") {
			t.Fatalf("Last line of stderr lost, got %d bytes", len(stderr))
		}
	}
}

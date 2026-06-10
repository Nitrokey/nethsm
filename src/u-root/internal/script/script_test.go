// SPDX-License-Identifier: EUPL-1.2

package script

import (
	"io"
	"os"
	"sync/atomic"
	"testing"

	. "nethsm/internal/util"
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
			exitedNtfy, exitedSig := MakeNtfyPair()
			processState := new(atomic.Pointer[os.ProcessState])
			cancel, pipe := s.CancelableBackgroundExecAsf(exitedNtfy, processState, -1, "%s", cmd)
			if test.inCancel {
				t.Logf("Calling cancel()")
				cancel()
			}

			if pipe != nil {
				// if child.Wait() was already called then it is expected that we'd fail to read the pipe here
				if stderr, err := io.ReadAll(pipe); err == nil && len(stderr) > 0 {
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

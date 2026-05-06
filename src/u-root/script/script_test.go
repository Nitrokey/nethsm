// SPDX-License-Identifier: EUPL-1.2

package script

import (
	"io"
	"testing"
)

var tests = map[string]struct {
	inCancel   bool
	outSuccess bool
	outStarted bool
}{
	"/bin/true":                {false, true, true},
	"/bin/false":               {false, false, true},
	"/bin/sleep 120":           {true, false, true},
	"/nonexistent/nonexistent": {false, false, false},
}

func TestCancelableBackgroundExecAsf(t *testing.T) {
	for cmd, test := range tests {
		t.Run(cmd, func(t *testing.T) {
			t.Parallel()
			s := New()
			exitCh := make(chan bool)
			cancel, pipe := s.CancelableBackgroundExecAsf(exitCh, -1, "%s", cmd)
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

			var success bool
			success, ok := <-exitCh
			if !ok && test.outStarted {
				t.Errorf("channel closed without providing success value")
			}
			if success != test.outSuccess {
				t.Errorf("%s success: got %t, wanted %t", cmd, success, test.outSuccess)
			}
		})
	}
}

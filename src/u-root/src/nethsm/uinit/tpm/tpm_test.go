package TPM

import (
	"log"
	"testing"
)

// For this test to succeed, you must run a swtpm emulator in the current
// directory as follows:
//
// mkdir -p ./swtpm-state && swtpm socket --server type=unixio,path=./swtpm-socket --tpmstate dir=./swtpm-state --tpm2 --flags not-need-init,startup-clear
//
// Then, run with GOPATH set to the u-root GOPATH:
//
// GOPATH=/path/to/nethsm/src/u-root go test
//
// Successful test output will look something like this the first time round:
//
// 2021/03/10 16:04:26 TPM: nvIndexHandle(0x1800001) does not exist, provisioning it
// 2021/03/10 16:04:26 Got Device ID: e77735f4e4fc39f9e17ba2b39c61a1d213f92b0e594f2f21ba3811198783a84c
// PASS
// ok  	nethsm/uinit/tpm	0.002s
// 
// On subsequent runs, unless the swtpm is "reset" by removing ./swtpm-state,
// the output will look like this:
//
// 021/03/10 16:04:36 Got Device ID: e77735f4e4fc39f9e17ba2b39c61a1d213f92b0e594f2f21ba3811198783a84c
// PASS
// ok  	nethsm/uinit/tpm	0.003s
// 
// i.e. no provisioning is done.
func TestGetDeviceId(t *testing.T) {
	deviceId, err := GetDeviceId("./swtpm-socket")
	if err != nil {
		t.Errorf("GetDeviceId() failed: %v", err)
	}
	log.Printf("Got Device ID: %x", deviceId)
}

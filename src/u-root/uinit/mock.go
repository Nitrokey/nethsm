// Mock mode:
//
// Mock mode provides a way of testing parts of the "platform protocol" on a
// normal Linux host.
//
// To use it, build uinit with "make" in this directory. Then, run with an
// argument of "mock" which will launch platformListener() on TCP port 12345.
//
// You can use "socat" or "nc" to talk to it.
//
// To test "Device Key" functionality against "swtpm", launch swtpm as follows:
//
// mkdir -p ./swtpm-state && swtpm socket --tpmstate dir=./swtpm-state --server type=unixio,path=./swtpm.socket --log level=5 --tpm2 --flags not-need-init,startup-clear
//
// Then, run "MOCK_TPM_DEVICE=./swtpm.socket ./uinit mock".
//
// TODO: Document the other MOCK_ parameters and their use in testing UPDATE /
// COMMIT-UPDATE against e.g. run/disk.img for the QEMU target.
//
// TODO: Could we do some automated testing of this during the QEMU build? Is
// it worth the work?

package main

import (
	"log"
)

// mockActions are executed when testing (run with an argument of "mock").
func mockActions() {
	log.Printf("Kernel release is: %s", G.kernelRelease)
	G.s.BackgroundExecf("sleep 5")
	if err := G.s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}

	c := make(chan string)
	go platformListener(c)
	request := <-c
	log.Printf("platformListener returned: %s", request)
	if request == "FACTORY-RESET" {
		log.Printf("Deleting Device Key from TPM.")
		err := tpmDeleteDeviceKey(G.tpmDevice)
		if err != nil {
			// Deliberately non-fatal.
			log.Printf("TPM: DeleteDeviceKey() failed: %v", err)
		}
	}
}

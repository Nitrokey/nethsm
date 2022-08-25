// gpt.go contains functions used to manipulate the GPT.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// gptSwapPartitions swaps the order of the first two partitions in the GPT,
// without making any other changes.
//
// diskDevice is the block device of the disk to operate on.
//
// Note that the kernel is explicity NOT told to re-read the partition table,
// as the disk device will be in use and the operation would fail. Therefore,
// the caller MUST ENSURE that the system partitions affected are not touched
// after calling this function and before a reboot.
//
// Implementation notes:
//
// The GPT structures are quite complex -- there are two copies of the GPT on
// disk, and CRC32 integrity checksums in several places. I considered both
// writing native Go code to manipulate the GPT from scratch, or adapting an
// existing Go GPT library. The former would have been a lot of work and likely
// resulted in re-inventing a bad wheel, and all examples of the latter were
// unfortunately not suitable for our purposes.
//
// Therefore, I decided to re-use the production quality "sfdisk" utility from
// util-linux instead. This code performs the equivalent of:
//
//     sfdisk -d diskDevice | (swap the first two partitions) | sfdisk diskDevice
//
// The output of "sfdisk" looks something like this, with line numbers:
//
// 1: label: gpt
// 2: label-id: 226302C6-ACC7-DB41-988A-D3CC72620C27
// 3: device: run/disk.img
// 4: unit: sectors
// 5: first-lba: 34
// 6: last-lba: 2097118
// 7: sector-size: 512
// 8:
// 9: run/disk.img1 : start=         128, size=      524288, type=FE3A2A5D-4F32-41A7-B725-ACCC3285A309, uuid=2F8DB682-3E0F-7149-96F2-55B2C82A3548, name="system1"
// 10: run/disk.img2 : start=      524416, size=      524288, type=FE3A2A5D-4F32-41A7-B725-ACCC3285A309, uuid=5373D8ED-591A-794D-9B72-47C7B0710B97, name="system2"
// 11: run/disk.img3 : start=     1048704, size=     1048415, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, uuid=50467BDB-B0F3-A840-AB5B-1DF6DB161834, name="data"
//
// Note that the header varies between versions; if the version of "sfdisk" is updated then this code needs to be re-tested.
//
// The "pathname" (e.g. "run/disk.img" in the above output) is not used by
// sfdisk to determine which device to operate on, it only reflects the
// pathname of the device the "-d" operation was performed on.
//
// What is relevant is that in the partition entry itself, the DIGIT at the end
// of the path name specifies the index of that partitions entry in the GPT.
// Therefore, it is not sufficient to just swap lines 9 and 10, we must also
// ensure that the end digit reflects the intended order.
func gptSwapPartitions(diskDevice string) (error) {
	// Read the GPT, piping output to stdout.
	cmd := exec.Command("sfdisk", "-d", diskDevice)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("sfdisk failed to read GPT: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sfdisk failed to read GPT: %v", err)
	}

	// Read all of stdout into an array of lines, with the EOL mark removed.
	var lines []string

	scanner := bufio.NewScanner(stdout)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil {
		stdout.Close()
		cmd.Wait()
		return fmt.Errorf("Parse error reading GPT: %v", scanner.Err())
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("sfdisk failed to read GPT: %v")
	}

	// Basic sanity check: Ensure we read exactly 11 lines and lines[7] is
	// blank (separating the header from the partition entries).
	if len(lines) != 11 {
		return fmt.Errorf("Parse error reading GPT")
	} else if lines[7] != "" {
		return fmt.Errorf("Parse error reading GPT")
	}

	// Swap lines[8] with lines[9], and correct the end digits (see
	// implementation notes above).
	tmp := lines[8]
	lines[8] = lines[9]
	lines[9] = tmp
	lines[8] = strings.Replace(lines[8], "2 :", "1 :", 1)
	lines[9] = strings.Replace(lines[9], "1 :", "2 :", 1)

	// Write out the modified GPT.
	// We must use --no-reread and --no-tell-kernel here as the disk is in use
	// so otherwise the operation would fail.
	cmd = exec.Command("sfdisk", "--no-reread", "--no-tell-kernel", diskDevice)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("sfdisk failed to write GPT: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sfdisk failed to write GPT: %v", err)
	}

	cerr := make(chan error)
	go func() {
		defer close(cerr)
		defer stdin.Close()
		for _, l := range lines {
			s := l + "\n"
			n, err := io.WriteString(stdin, s)
			// Verify that the write succeded and all data was written out.
			if err != nil {
				cerr <- err
				return
			} else if n != len(s) {
				cerr <- fmt.Errorf("short write")
				return
			}
			// We actually want to send a <nil> here, but that doesn't work.
			// close(cerr) from the defer achieves the same result.
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("sfdisk failed to write GPT: %v", err)
	}
	if err := <- cerr; err != nil {
		return fmt.Errorf("sfdisk failed to write GPT: %v", err)
	}

	return nil
}

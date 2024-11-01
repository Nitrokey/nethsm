package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

//go:embed .hardware_version
var hardwareVersion string

func isZ790() bool {
	return hardwareVersion[:9] == "msi-z790-"
}

func main() {
	// Load kernel modules
	loadModules()

	// Get file and partition information
	file := "system.img.cpio"
	partitions := `
label: gpt
size=256M, type="ChromeOS kernel", name="system1"
size=256M, type="ChromeOS kernel", name="system2"
name="data"
`
	sep := "--------------------------------------------------"
	reset := false
	fast := false

	diskDev := "/dev/sda"
	partPrefix := "/dev/sda"

	if isZ790() {
		diskDev = "/dev/nvme0n1"
		partPrefix = "/dev/nvme0n1p"
	}

	// Check for factory reset command-line arguments
	for _, arg := range os.Args[1:] {
		if arg == "factory-reset" {
			reset = true
			break
		}
		if arg == "factory-reset-fast" {
			reset = true
			fast = true
			break
		}
	}

	// Wait function
	wait := func(x time.Duration) {
		if !fast {
			time.Sleep(x)
		}
	}

	// Print header
	fmt.Println(`
**************************************
* Nitrokey NetHSM Software Installer *
**************************************
`)

	changeLog := readFile("/update.changelog")

	if reset {
		fmt.Println("Executing factory reset.")
	} else {
		fmt.Println("Executing software update.")
	}
	fmt.Println(sep)
	fmt.Println("Software version to be installed:")
	fmt.Println(changeLog)
	fmt.Println()
	wait(5 * time.Second)

	if reset {
		fmt.Println(sep)
		fmt.Println("Partitioning hard disk")
		partitionDisk(partitions, diskDev)
		fmt.Println(sep)
		fmt.Println("Writing to first system partition")
		writeToPartition(file, partPrefix+"1")
		fmt.Println(sep)
		fmt.Println("Writing to second system partition")
		writeToPartition(file, partPrefix+"2")
		fmt.Println(sep)
		fmt.Println("Formatting data partition")
		formatDataPartition(partPrefix + "3")
		fmt.Println(sep)
		fmt.Println("Successfully installed:")
		fmt.Println(changeLog)
		fmt.Println()
		fmt.Println()
	} else {
		fmt.Println(sep)
		fmt.Println("Writing to first system partition")
		writeToPartition(file, partPrefix+"1")
	}

	fmt.Println(sep)
	fmt.Println("Done. Shutting down in 30 seconds...")
	wait(30 * time.Second)
	fmt.Println("Shutting down...")
	shutdownSystem()
}

func loadModules() {
	modules := []string{
		"/lib/modules/5.16.0-4-amd64/kernel/drivers/scsi/scsi_common.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/drivers/scsi/scsi_mod.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/drivers/ata/libata.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/drivers/ata/libahci.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/drivers/ata/ahci.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/crypto/crct10dif_common.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/arch/x86/crypto/crct10dif-pclmul.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/crypto/crct10dif_generic.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/lib/crc-t10dif.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/block/t10-pi.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/drivers/scsi/sd_mod.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/drivers/nvme/host/nvme-core.ko",
		"/lib/modules/5.16.0-4-amd64/kernel/drivers/nvme/host/nvme.ko",
	}

	for _, module := range modules {
		cmd := exec.Command("insmod", module)
		err := cmd.Run()
		if err != nil {
			fmt.Printf("Error loading module %s: %v\n", module, err)
		}
	}
}

func partitionDisk(partitions, device string) {
	cmd := exec.Command("sfdisk", device)
	cmd.Stdin = strings.NewReader(partitions)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error partitioning disk %s: %v\n", device, err)
	}
	exec.Command("sync").Run()
}

func writeToPartition(file, partition string) {
	cmd := exec.Command("dd", "if="+file, "of="+partition, "ibs=1M", "obs=1M")
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error writing to partition %s: %v\n", partition, err)
	}
}

func formatDataPartition(partition string) {
	cmd := exec.Command("mke2fs", "-t", "ext4", "-E", "discard", "-F", "-m0", "-L", "data", partition)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error formatting data partition %s: %v\n", partition, err)
	}
	exec.Command("sync").Run()
	exec.Command("sync").Run()
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Error reading file %s: %v\n", path, err)
		return ""
	}
	return string(data)
}

func shutdownSystem() {
	cmd := exec.Command("poweroff")
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error shutting down system: %v\n", err)
	}
}

package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"nethsm/internal/hw"
)

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
	fmt.Print(`
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

	err := install(file, partitions, sep, changeLog, reset)
	fmt.Println(sep)
	if err != nil {
		fmt.Printf("INSTALLATION FAILED: %v\n", err)
		fmt.Println("The system may not boot. Please repeat the installation.")
		fmt.Println("Shutting down in 30 seconds...")
	} else {
		fmt.Println("Done. Shutting down in 30 seconds...")
	}
	wait(30 * time.Second)
	fmt.Println("Shutting down...")
	shutdownSystem()
}

// install stops at the first failure, as the later steps would hide it.
func install(file, partitions, sep, changeLog string, reset bool) error {
	if !reset {
		fmt.Println(sep)
		fmt.Println("Writing to first system partition")
		return writeToPartition(file, hw.DiskPrefix+"1")
	}

	fmt.Println(sep)
	fmt.Println("Partitioning hard disk")
	if err := partitionDisk(partitions, hw.DiskDev); err != nil {
		return err
	}
	fmt.Println(sep)
	fmt.Println("Writing to first system partition")
	if err := writeToPartition(file, hw.DiskPrefix+"1"); err != nil {
		return err
	}
	fmt.Println(sep)
	fmt.Println("Writing to second system partition")
	if err := writeToPartition(file, hw.DiskPrefix+"2"); err != nil {
		return err
	}
	fmt.Println(sep)
	fmt.Println("Formatting data partition")
	if err := formatDataPartition(hw.DiskPrefix + "3"); err != nil {
		return err
	}
	fmt.Println(sep)
	fmt.Println("Successfully installed:")
	fmt.Println(changeLog)
	fmt.Println()
	fmt.Println()
	return nil
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

func partitionDisk(partitions, device string) error {
	cmd := exec.Command("sfdisk", device)
	cmd.Stdin = strings.NewReader(partitions)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("partitioning disk %s: %w", device, err)
	}
	_ = exec.Command("sync").Run()
	return nil
}

func writeToPartition(file, partition string) error {
	cmd := exec.Command("dd", "if="+file, "of="+partition, "ibs=1M", "obs=1M")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("writing to partition %s: %w", partition, err)
	}
	return nil
}

func formatDataPartition(partition string) error {
	cmd := exec.Command("mke2fs", "-t", "ext4", "-E", "discard", "-F", "-m0", "-L", "data", partition)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("formatting data partition %s: %w", partition, err)
	}
	_ = exec.Command("sync").Run()
	_ = exec.Command("sync").Run()
	return nil
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

//go:build !prodrive_hermes_1 && !msi_z790_1

package hw

import "github.com/canonical/go-tpm2"

const (
	Version    = "qemu-kvm"
	DiskDev    = "/dev/sda"
	DiskPrefix = "/dev/sda"
)

func MeasuredPCRs() tpm2.PCRSelect {
	return tpm2.PCRSelect{}
}

//go:build qemu_kvm

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

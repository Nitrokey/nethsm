//go:build msi_z790_1

package hw

import "github.com/canonical/go-tpm2"

const (
	Version    = "msi-z790-1"
	DiskDev    = "/dev/nvme0n1"
	DiskPrefix = "/dev/nvme0n1p"
)

func MeasuredPCRs() tpm2.PCRSelect {
	return tpm2.PCRSelect{2}
}

//go:build prodrive_hermes_1

package hw

import "github.com/canonical/go-tpm2"

const (
	Version    = "prodrive-hermes-1"
	DiskDev    = "/dev/sda"
	DiskPrefix = "/dev/sda"
)

func MeasuredPCRs() tpm2.PCRSelect {
	return tpm2.PCRSelect{0, 2}
}

//go:build !msi_z790_1 && !prodrive_hermes_1

package hw

import "github.com/canonical/go-tpm2"

// constants
const (
	Version    = "testing"
	DiskDev    = ""
	DiskPrefix = ""
	TRNGDev    = "/dev/random"
)

func init() {
	isTesting = true
}

// MeasuredPCRs ...
func MeasuredPCRs() tpm2.PCRSelect {
	return tpm2.PCRSelect{}
}

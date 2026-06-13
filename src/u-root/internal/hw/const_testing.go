//go:build testing

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

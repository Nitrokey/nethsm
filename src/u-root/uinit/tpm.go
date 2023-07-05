// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

// tpm.go contains TPM-related functions used to provision/retrieve and delete
// the "Device Key" stored in the TPM.
package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/templates"
	"github.com/canonical/go-tpm2/util"
)

const (
	// PCR index for sealing
	pcrIdx = 2

	sealedDeviceKeyFile = "/data/sealedDeviceKey"
)

var (
	tpmCtxInstance *tpm2.TPMContext
	tpmCtxMutex    sync.Mutex
)

// must be in sync with platform_data in src/keyfender/json.ml
type platformData struct {
	DeviceId  string `json:"deviceId"`
	DeviceKey string `json:"deviceKey"`
	PCR       string `json:"pcr"`
	AKPubP256 string `json:"akPubP256"`
	AKPubP384 string `json:"akPubP384"`
}

func withTPMContext(f func(*tpm2.TPMContext) error) error {
	tpmCtxMutex.Lock()
	defer tpmCtxMutex.Unlock()
	if tpmCtxInstance == nil {
		tcti, err := linux.OpenDevice(G.tpmDevice)
		if err != nil {
			panic(err)
		}
		tpmCtxInstance = tpm2.NewTPMContext(tcti)
	}
	return f(tpmCtxInstance)
}

type tpmRandReader struct{ *tpm2.TPMContext }

func (v tpmRandReader) Read(p []byte) (int, error) {
	l := len(p)
	if l > 48 {
		l = 48
	}
	data, err := v.GetRandom(uint16(l))
	if err != nil {
		return 0, err
	}
	n := copy(p, data)
	return n, nil
}

func tpmRand(buf []byte) error {
	err := withTPMContext(func(tpm *tpm2.TPMContext) error {
		_, err := io.ReadFull(tpmRandReader{tpm}, buf)
		return err
	})
	return err
}

func getIdFromAk(akPub *tpm2.Public) string {
	akName := akPub.Name().Digest()
	return base32.StdEncoding.EncodeToString(akName[:7])[:10]
}

func getDerFromAk(akPub *tpm2.Public) (string, error) {
	akDer, err := x509.MarshalPKIXPublicKey(akPub.Public())
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(akDer), nil
}

var akData platformData

func tpmGetAKData() (platformData, error) {
	var err error
	if akData.DeviceId == "" {
		err = withTPMContext(func(tpm *tpm2.TPMContext) error {
			ak256Ctx, ak256Pub, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil,
				templates.NewRestrictedECCSigningKeyWithDefaults(),
				nil, nil, nil)
			if err != nil {
				return fmt.Errorf("create AK: %v", err)
			}
			defer tpm.FlushContext(ak256Ctx)

			ak256Der, err := getDerFromAk(ak256Pub)
			if err != nil {
				return fmt.Errorf("mashall AK256: %v", err)
			}

			ak384Ctx, ak384Pub, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil,
				templates.NewECCStorageKey(tpm2.HashAlgorithmSHA384, tpm2.SymObjectAlgorithmAES, 192, tpm2.ECCCurveNIST_P384),
				nil, nil, nil)
			if err != nil {
				return fmt.Errorf("create AK: %v", err)
			}
			defer tpm.FlushContext(ak384Ctx)

			ak384Der, err := getDerFromAk(ak384Pub)
			if err != nil {
				return fmt.Errorf("mashall AK384: %v", err)
			}

			akData.DeviceId = getIdFromAk(ak256Pub)
			akData.AKPubP256 = ak256Der
			akData.AKPubP384 = ak384Der
			return nil
		})
	}
	return akData, err
}

// tpmGetDeviceKey returns the 256-bit "Device Key" of the NetHSM.
//
// The Device Key is sealed against PCR-2 with an SRK on the TPM and stored on
// the harddisk. If the Device Key does not exist, a new one is created.
func tpmGetPlatformData() (platformData, error) {
	var data platformData

	err := withTPMContext(func(tpm *tpm2.TPMContext) error {
		srkCtx, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil,
			templates.NewECCStorageKey(tpm2.HashAlgorithmSHA384, tpm2.SymObjectAlgorithmAES, 192, tpm2.ECCCurveNIST_P384),
			nil, nil, nil)
		if err != nil {
			return fmt.Errorf("create SRK: %v", err)
		}
		defer tpm.FlushContext(srkCtx)

		// Select PCR index in the SHA256 bank
		pcrSelection := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{pcrIdx}}}

		key, err := unsealDeviceKey(tpm, srkCtx)
		if err != nil {
			return fmt.Errorf("Unsealing Device Key failed: %w\n", err)
		}
		if len(key) == 0 {
			if !randIsFullySeeded() {
				return fmt.Errorf("waiting for TRNG seeding timed out.")
			}
			key = make([]byte, 32)
			crand.Read(key)

			err = sealDeviceKey(tpm, srkCtx, key, pcrSelection)
			if err != nil {
				return fmt.Errorf("sealing new key failed: %w", err)
			}
			key2, err := unsealDeviceKey(tpm, srkCtx)
			if err != nil {
				return fmt.Errorf("unsealing new key failed: %w", err)
			}
			if !bytes.Equal(key, key2) {
				return fmt.Errorf("unsealed key does not match generated key.")
			}
			log.Printf("Created and sealed new Device Key\n")
		} else {
			log.Printf("Sucessfully unsealed Device Key\n")
		}

		data, err = tpmGetAKData()
		if err != nil {
			return fmt.Errorf("getting AK data failed: %w", err)
		}

		data.DeviceKey = hex.EncodeToString(key)

		_, pcrValues, err := tpm.PCRRead(pcrSelection)
		if err != nil {
			return fmt.Errorf("reading PCR value failed: %w", err)
		}
		data.PCR = hex.EncodeToString(pcrValues[tpm2.HashAlgorithmSHA256][pcrIdx])

		// invalidate PCR afterwards to inhibit unsealing the Device Key again
		tpm.PCRExtend(tpm.PCRHandleContext(pcrIdx),
			tpm2.NewTaggedHashListBuilder().
				Append(tpm2.HashAlgorithmSHA256, make([]byte, 32)).
				MustFinish(),
			nil)
		_, err = unsealDeviceKey(tpm, srkCtx)
		if tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandUnseal, tpm2.AnySessionIndex) {
			log.Printf("Successfully invalidated PCR value.")
		} else {
			return fmt.Errorf("invalidating PCR value failed: %w", err)
		}

		return nil
	})
	return data, err
}

// sealDeviceKey seals the supplied secret to a sealed object in the storage hierarchy
// of the TPM, using a simple authorization policy that is gated on the current
// values of the PCRs included in the specified selection. The sealed object and
// metadata are serialized to the supplied io.Writer.
func sealDeviceKey(
	tpm *tpm2.TPMContext,
	srk tpm2.ResourceContext,
	secret []byte,
	pcrSelection tpm2.PCRSelectionList,
) error {
	f, err := os.Create(sealedDeviceKeyFile)
	if err != nil {
		return fmt.Errorf("create sealed Device Key file: %v", err)
	}
	defer f.Close()

	// Build the sealed object template
	template := templates.NewSealedObject(tpm2.HashAlgorithmSHA384)

	// Disallow passphrase authorization for the user role
	template.Attrs &^= tpm2.AttrUserWithAuth

	// Compute a simple PCR policy using the TPM's current values
	_, values, err := tpm.PCRRead(pcrSelection)
	if err != nil {
		return err
	}

	digest, err := util.ComputePCRDigest(tpm2.HashAlgorithmSHA384, pcrSelection, values)
	if err != nil {
		return err
	}

	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA384)
	trial.PolicyPCR(digest, pcrSelection)

	template.AuthPolicy = trial.GetDigest()

	sensitive := &tpm2.SensitiveCreate{Data: secret}

	// Create the sealed object
	priv, pub, _, _, _, err := tpm.Create(srk, sensitive, template, nil, nil, nil)
	if err != nil {
		return err
	}

	// Encode the sealed object
	_, err = mu.MarshalToWriter(f, priv, pub, pcrSelection)
	return err
}

// unsealDeviceKey attempts to recover a secret previously sealed by the seal function
func unsealDeviceKey(tpm *tpm2.TPMContext, srk tpm2.ResourceContext) ([]byte, error) {
	f, err := os.Open(sealedDeviceKeyFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot open sealed device key file: %v", err)
	}
	defer f.Close()

	// Decode the sealed object
	var priv tpm2.Private
	var pub *tpm2.Public
	var pcrSelection tpm2.PCRSelectionList
	if _, err := mu.UnmarshalFromReader(f, &priv, &pub, &pcrSelection); err != nil {
		return nil, err
	}

	// Load the sealed object into the TPM
	object, err := tpm.Load(srk, priv, pub, nil)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(object)

	// Settings for symmetric parameter encryption
	AesCfb := tpm2.SymDef{
		Algorithm: tpm2.SymAlgorithmAES,
		KeyBits:   &tpm2.SymKeyBitsU{Sym: 192},
		Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB},
	}

	// Start a parameter encrypted policy session with PCR assertion.
	// The first parameter (tpmKey) must be set, else the parameter encryption
	// is not secure, because the session key can be reconstructed.
	session, err := tpm.StartAuthSession(srk, nil, tpm2.SessionTypePolicy, &AesCfb, tpm2.HashAlgorithmSHA384)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(session)

	if err := tpm.PolicyPCR(session, nil, pcrSelection); err != nil {
		return nil, err
	}

	return tpm.Unseal(object, session)
}

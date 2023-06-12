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
	"encoding/hex"
	"encoding/json"
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
	sealedDeviceKeyFile = "/data/sealedDeviceKey"
)

var (
	// PCR index for sealing
	pcrIdxs = tpm2.PCRSelect{0, 2}

	zeros = make([]byte, 32)

	tpmCtxInstance *tpm2.TPMContext
	tpmCtxMutex    sync.Mutex
)

// must be in sync with platform_data in src/keyfender/json.ml
type platformData struct {
	DeviceId        string            `json:"deviceId"`
	DeviceKey       []byte            `json:"deviceKey"`
	PCR             map[int]string    `json:"pcr"`
	AKPub           map[string][]byte `json:"akPub"`
	HardwareVersion string            `json:"hardwareVersion"`
	FirmwareVersion string            `json:"firmwareVersion"`
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

func tpmGetAKData(tpm *tpm2.TPMContext) (string, map[string][]byte, error) {
	ak256Ctx, ak256Pub, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil,
		templates.NewRestrictedECCSigningKeyWithDefaults(),
		nil, nil, nil)
	if err != nil {
		return "", nil, fmt.Errorf("create AK256: %v", err)
	}
	defer tpm.FlushContext(ak256Ctx)

	ak256Der, err := x509.MarshalPKIXPublicKey(ak256Pub.Public())
	if err != nil {
		return "", nil, fmt.Errorf("marshal AK256: %v", err)
	}

	ak384Ctx, ak384Pub, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil,
		templates.NewRestrictedECCSigningKey(tpm2.HashAlgorithmSHA384, nil, tpm2.ECCCurveNIST_P384),
		nil, nil, nil)
	if err != nil {
		return "", nil, fmt.Errorf("create AK384: %v", err)
	}
	defer tpm.FlushContext(ak384Ctx)

	ak384Der, err := x509.MarshalPKIXPublicKey(ak384Pub.Public())
	if err != nil {
		return "", nil, fmt.Errorf("marshal AK384: %v", err)
	}

	deviceId := getIdFromAk(ak256Pub)
	akPub := make(map[string][]byte)
	akPub["P256"] = ak256Der
	akPub["P384"] = ak384Der
	return deviceId, akPub, nil
}

// tpmGetPlatformData returns TPM derived data of the NetHSM.
//
// The Device Key is sealed against PCR-0 and PCR-2 with an SRK on the TPM and
// stored on the harddisk. If the Device Key does not exist, a new one is
// created.
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

		// Select PCR indexes in the SHA256 bank
		pcrSelection := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: pcrIdxs}}

		_, pcrValues, err := tpm.PCRRead(pcrSelection)
		if err != nil {
			return fmt.Errorf("reading PCR values failed: %w", err)
		}

		for _, i := range pcrIdxs {
			if bytes.Equal(pcrValues[tpm2.HashAlgorithmSHA256][i], zeros) {
				return fmt.Errorf("PCR-%d is empty!", i)
			}
		}

		deviceKey, err := unsealDeviceKey(tpm, srkCtx)
		if err != nil {
			return fmt.Errorf("Unsealing Device Key failed: %w\n", err)
		}
		if len(deviceKey) == 0 {
			if !randIsFullySeeded() {
				return fmt.Errorf("waiting for TRNG seeding timed out.")
			}
			deviceKey = make([]byte, 32)
			crand.Read(deviceKey)

			err = sealDeviceKey(tpm, srkCtx, deviceKey, pcrSelection)
			if err != nil {
				return fmt.Errorf("sealing new key failed: %w", err)
			}
			key2, err := unsealDeviceKey(tpm, srkCtx)
			if err != nil {
				return fmt.Errorf("unsealing new key failed: %w", err)
			}
			if !bytes.Equal(deviceKey, key2) {
				return fmt.Errorf("unsealed key does not match generated key.")
			}
			log.Printf("Created and sealed new Device Key\n")
		} else {
			log.Printf("Sucessfully unsealed Device Key\n")
		}

		// cap PCRs afterwards to inhibit unsealing the Device Key again
		for _, i := range pcrIdxs {
			tpm.PCRExtend(tpm.PCRHandleContext(i),
				tpm2.NewTaggedHashListBuilder().
					Append(tpm2.HashAlgorithmSHA256, zeros).
					MustFinish(),
				nil)
		}
		_, err = unsealDeviceKey(tpm, srkCtx)
		if tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandUnseal, tpm2.AnySessionIndex) {
			log.Printf("Successfully capped PCR values.")
		} else {
			return fmt.Errorf("capping PCR values failed: %w", err)
		}

		_, pcrValues, err = tpm.PCRRead(pcrSelection)
		if err != nil {
			return fmt.Errorf("reading PCR values failed: %w", err)
		}

		data.PCR = make(map[int]string)
		for _, i := range pcrIdxs {
			data.PCR[i] = hex.EncodeToString(pcrValues[tpm2.HashAlgorithmSHA256][i])
		}

		data.DeviceId, data.AKPub, err = tpmGetAKData(tpm)
		if err != nil {
			return fmt.Errorf("getting AK data failed: %w", err)
		}

		data.FirmwareVersion = getFirmwareVersion(data.PCR)

		data.HardwareVersion = hardwareVersion

		platformDataJson, _ := json.MarshalIndent(data, "", "    ")
		log.Printf("Platform Data: %v\n", string(platformDataJson))

		data.DeviceKey = deviceKey

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

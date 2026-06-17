// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

// Package localconf provides local configuration management for NetHSM.
package localconf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	localConfigFile = "/data/localConfig"
	authData        = "local-config"
)

var localConfigKey, setLocalConfigKey = func() (func() []byte, func([]byte)) {
	var key []byte
	get := func() []byte {
		if key == nil {
			log.Fatal("localConfigKey is unset")
		}
		return key
	}
	// Derive the encryption key: SHA256(device-key + "local-config")
	set := func(deviceKey []byte) {
		if key != nil {
			log.Fatal("tried to set local config key twice")
		}
		keyMaterial := slices.Concat(deviceKey, []byte(authData))
		hash := sha256.Sum256(keyMaterial)
		key = hash[:] // 32 bytes for AES-256
	}
	return get, set
}()

// LocalConf is the stored and wire format for local configuration.
// All fields are optional pointers: nil means absent, omitted from JSON.
// TimeOffsetS is owned by S-Platform and never present in wire messages.
// TimeMs is wire-only and never stored.
type LocalConf struct {
	TLSCert            *string `json:"tls_cert,omitempty"`
	TLSKey             *string `json:"tls_key,omitempty"`
	TLSTrustedCA       *string `json:"tls_cluster_ca,omitempty"`
	DeviceID           *string `json:"device_id,omitempty"`
	NetworkConfig      *string `json:"network_config,omitempty"`
	FailedUnlockSalt   string  `json:"failed_unlock_salt,omitempty"`
	FailedUnlockDigest string  `json:"failed_unlock_digest,omitempty"`
	NtpIP              *string `json:"ntp_ip,omitempty"`
	NtsName            *string `json:"nts_name,omitempty"`
	TimeOffsetS        *int    `json:"time_offset_s,omitempty"` // storage only
	TimeMs             *int64  `json:"time_ms,omitempty"`       // wire only
}

// ChangeReq is the notification dispatched to registered consumers sent after a
// SET-LOCAL-CONFIG update from Keyfender. Reply is set by notifyConsumers
// before dispatch; consumers MUST send on it.
type ChangeReq struct {
	Reply chan<- error
}

var (
	localConfig atomic.Pointer[LocalConf]
	consumers   []chan<- ChangeReq
	consumersMu sync.Mutex
	setMu       sync.Mutex
)

// RegisterConsumer registers ch to receive a ChangeReq whenever Set succeeds
// and the config has changed. Set blocks until all consumers have replied.
func RegisterConsumer(ch chan<- ChangeReq) {
	consumersMu.Lock()
	consumers = append(consumers, ch)
	consumersMu.Unlock()
}

func loadFromCache() error {
	log.Printf("Loading local config from cache file")

	if localConfig.Load() != nil {
		return fmt.Errorf("local config already set")
	}

	var conf LocalConf

	fileData, err := os.ReadFile(localConfigFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("No local config cache file found")
		} else {
			return fmt.Errorf("cannot read %s: %w", localConfigFile, err)
		}
	} else {
		block, err := aes.NewCipher(localConfigKey())
		if err != nil {
			return fmt.Errorf("failed to create cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("failed to create GCM: %w", err)
		}

		nonceSize := gcm.NonceSize()
		if len(fileData) < nonceSize {
			return fmt.Errorf("local config file too short (%d bytes)", len(fileData))
		}
		nonce := fileData[:nonceSize]
		encrypted := fileData[nonceSize:]

		plaintext, err := gcm.Open(nil, nonce, encrypted, []byte(authData))
		if err != nil {
			return fmt.Errorf("failed to decrypt: %w", err)
		}

		if err := json.Unmarshal(plaintext, &conf); err != nil {
			return fmt.Errorf("failed to unmarshal JSON: %w", err)
		}
	}

	if !localConfig.CompareAndSwap(nil, &conf) {
		return fmt.Errorf("local config already set")
	}
	return nil
}

// Init initializes the localconf package
func Init(key []byte) error {
	setLocalConfigKey(key)
	return loadFromCache()
}

// Get returns a copy of localConfig.
func Get() LocalConf {
	lc := localConfig.Load()
	if lc == nil {
		log.Fatal("localconf used before initialization")
	}
	lc.TimeMs = nil
	return *lc
}

// saveConf encrypts and atomically writes conf to disk. Must be called with setMu held.
func saveConf(conf *LocalConf) error {
	jsonData, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("failed to marshal local config: %w", err)
	}

	block, err := aes.NewCipher(localConfigKey())
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt: Seal prepends the nonce to the encrypted data
	fileData := gcm.Seal(nonce, nonce, jsonData, []byte(authData))

	if err := os.WriteFile(localConfigFile+".tmp", fileData, 0o666); err != nil {
		return fmt.Errorf("write local config file: %w", err)
	}
	if err := os.Rename(localConfigFile+".tmp", localConfigFile); err != nil {
		return fmt.Errorf("rename local config file: %w", err)
	}
	syscall.Sync()
	return nil
}

func notifyConsumers() error {
	consumersMu.Lock()
	cs := append([]chan<- ChangeReq(nil), consumers...)
	consumersMu.Unlock()

	errs := make([]error, len(cs))
	var wg sync.WaitGroup
	for i, ch := range cs {
		wg.Add(1)
		go func(i int, ch chan<- ChangeReq) {
			defer wg.Done()
			reply := make(chan error)
			ch <- ChangeReq{Reply: reply}
			errs[i] = <-reply
		}(i, ch)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Set updates the local config from a SET-LOCAL-CONFIG message and stores changes to the local
// cache file. Fields absent from jsonConf keep their existing values;
// TimeOffsetS is always preserved (S-Platform owns it). Notifies all registered
// consumers when the config changes or TimeMs is non-nil, and waits for replies.
func Set(jsonConf []byte, setTime func(time.Duration) error) error {
	var upd LocalConf
	if err := json.Unmarshal(jsonConf, &upd); err != nil {
		return fmt.Errorf("failed to parse local config: %w", err)
	}

	var errs []error
	// Handle manual time set forwarded from PUT /config/time.
	if upd.TimeMs != nil && setTime != nil {
		// Convert to a monotonic offset immediately so scheduling delays
		// between here and the syscall don't accumulate into the correction.
		clockOffset := time.Until(time.UnixMilli(*upd.TimeMs))
		if setErr := setTime(clockOffset); setErr != nil {
			log.Printf("Failed to set system time from Keyfender: %v", setErr)
			errs = append(errs, setErr)
		}
	}
	upd.TimeMs = nil

	confChanged := false
	update := func(old **string, upd *string) {
		if *old == nil {
			*old = new(string) // make sure the field is populated
		}
		if upd != nil && **old != *upd {
			*old = upd
			confChanged = true
		}
	}

	setMu.Lock()
	conf := Get()
	// Apply each present field, tracking whether anything actually changed.
	// TimeOffsetS is never in the wire message; TimeMs is wire-only, not stored.
	update(&conf.TLSCert, upd.TLSCert)
	update(&conf.TLSKey, upd.TLSKey)
	update(&conf.TLSTrustedCA, upd.TLSTrustedCA)
	update(&conf.DeviceID, upd.DeviceID)
	update(&conf.NetworkConfig, upd.NetworkConfig)
	update(&conf.NtpIP, upd.NtpIP)
	update(&conf.NtsName, upd.NtsName)

	var saveErr error
	if confChanged {
		saveErr = saveAndStore(&conf)
		errs = append(errs, saveErr)
	} else {
		log.Printf("No change in local config")
	}
	setMu.Unlock()

	if confChanged && saveErr == nil {
		err := notifyConsumers()
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// UpdateTimeOffset updates the stored TimeOffsetS without notifying consumers.
// Safe to call from within a ChangeReq handler (avoids deadlock).
func UpdateTimeOffset(offsetS int) error {
	setMu.Lock()
	defer setMu.Unlock()

	conf := Get()
	if conf.TimeOffsetS != nil && *conf.TimeOffsetS == offsetS {
		return nil
	}
	conf.TimeOffsetS = &offsetS
	return saveAndStore(&conf)
}

// saveAndStore requires locked setMu
func saveAndStore(conf *LocalConf) error {
	conf.TimeMs = nil // never persist
	if err := saveConf(conf); err != nil {
		return err
	}
	localConfig.Store(conf)
	return nil
}

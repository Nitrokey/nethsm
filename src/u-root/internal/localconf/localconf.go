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

type LocalConf struct {
	TLSCert       string `json:"tls_cert"`
	TLSKey        string `json:"tls_key"`
	TLSTrustedCA  string `json:"tls_cluster_ca,omitempty"`
	DeviceID      string `json:"device_id"`
	TimeOffsetS   int    `json:"time_offset_s"` // 0 if unknown
	NetworkConfig string `json:"network_config"`
}

// ChangeReq is sent to registered consumers when the local config changes.
// The consumer must send a result (nil or an error) on Reply.
type ChangeReq struct {
	Conf  *LocalConf
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
	return *lc
}

// Set updates the local config from JSON and stores changes to the local cache
// file. It then notifies all registered consumers concurrently and waits for
// all of them to reply before returning. Returns nil if the config is unchanged.
func Set(jsonConf []byte) error {
	var newConf LocalConf
	if err := json.Unmarshal(jsonConf, &newConf); err != nil {
		return fmt.Errorf("failed to parse local config: %w", err)
	}

	setMu.Lock()
	defer setMu.Unlock()

	oldConf := Get()

	if oldConf == newConf {
		log.Printf("No change in local config")
		return nil
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
	fileData := gcm.Seal(nonce, nonce, jsonConf, []byte(authData))

	if err := os.WriteFile(localConfigFile+".tmp", fileData, 0o666); err != nil {
		return fmt.Errorf("write local config file: %w", err)
	}
	if err := os.Rename(localConfigFile+".tmp", localConfigFile); err != nil {
		return fmt.Errorf("rename local config file: %w", err)
	}
	syscall.Sync()

	localConfig.Store(&newConf)

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
			ch <- ChangeReq{Conf: &newConf, Reply: reply}
			errs[i] = <-reply
		}(i, ch)
	}
	wg.Wait()
	return errors.Join(errs...)
}

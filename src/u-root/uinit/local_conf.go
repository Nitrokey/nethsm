// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

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
		keyMaterial := append(deviceKey, []byte("local-config")...)
		hash := sha256.Sum256(keyMaterial)
		key = hash[:] // 32 bytes for AES-256
	}
	return get, set
}()

type localConf struct {
	TLSCert      string `json:"tls_cert"`
	TLSKey       string `json:"tls_key"`
	TLSTrustedCA string `json:"tls_trusted_ca"`
}

var localConfig Observable[localConf]

func loadLocalConfigFromCache() error {
	last, _ := localConfig.Get()
	if last != nil {
		return nil
	}

	fileData, err := os.ReadFile(localConfigFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("cannot read %s: %w", localConfigFile, err)
	}

	block, err := aes.NewCipher(localConfigKey())
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()

	nonce := fileData[:nonceSize]
	encrypted := fileData[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encrypted, []byte(authData))
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	var conf localConf
	if err := json.Unmarshal(plaintext, &conf); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	_ = localConfig.Set(&conf)

	return nil
}

func setLocalConfig(conf *localConf) error {
	jsonConf, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
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

	err = os.WriteFile(localConfigFile+".tmp", fileData, 0o666)
	if err != nil {
		return fmt.Errorf("create sealed Device Key file: %w", err)
	}
	err = os.Rename(localConfigFile+".tmp", localConfigFile)
	if err != nil {
		return fmt.Errorf("rename sealed Device Key file: %w", err)
	}
	syscall.Sync()

	_ = localConfig.Set(conf)

	return nil
}

// Copyright 2026, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package localconf

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var setTestKey = sync.OnceFunc(func() { setLocalConfigKey(make([]byte, 32)) })

// useTestConf starts a test without config, with its cache file in a temporary
// directory.
func useTestConf(t *testing.T) {
	t.Helper()
	setTestKey()
	old := localConfigFile
	t.Cleanup(func() { localConfigFile = old })
	localConfigFile = filepath.Join(t.TempDir(), "localConfig")
	localConfig.Store(nil)
}

func TestDamagedCacheFile(t *testing.T) {
	useTestConf(t)
	if err := os.WriteFile(localConfigFile, []byte("this is not a local config file"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := loadOrEmpty(); err == nil {
		t.Fatal("damaged cache file accepted")
	}
	if got := Get(); got.DeviceID != nil {
		t.Errorf("config not empty: %v", got)
	}

	// The next update replaces the damaged file.
	if err := Set([]byte(`{"device_id":"id"}`), nil); err != nil {
		t.Fatal(err)
	}
	localConfig.Store(nil)
	if err := loadOrEmpty(); err != nil {
		t.Fatal(err)
	}
	if got := Get(); got.DeviceID == nil || *got.DeviceID != "id" {
		t.Errorf("config not restored: %v", got)
	}
}

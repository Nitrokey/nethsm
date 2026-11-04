// Copyright 2026, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package localconf

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
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

// Fails with the race detector if Get() writes to the shared config.
func TestGetConcurrently(t *testing.T) {
	useTestConf(t)
	localConfig.Store(&LocalConf{})
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			for range 1000 {
				Get()
			}
		})
	}
	wg.Wait()
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func TestSetKeepsAbsentFields(t *testing.T) {
	useTestConf(t)
	if err := loadOrEmpty(); err != nil {
		t.Fatal(err)
	}

	for _, update := range []string{`{"ntp_ip":"1.2.3.4","nts_name":"a"}`, `{"nts_name":"b"}`} {
		if err := Set([]byte(update), nil); err != nil {
			t.Fatal(err)
		}
	}

	// Compare what comes back from the file, not only the memory.
	localConfig.Store(nil)
	if err := loadOrEmpty(); err != nil {
		t.Fatal(err)
	}
	got := Get()
	if ip, name := deref(got.NtpIP), deref(got.NtsName); ip != "1.2.3.4" || name != "b" {
		t.Errorf("got ntp_ip %s, nts_name %s", ip, name)
	}
}

func TestSetTimeIsNotStored(t *testing.T) {
	useTestConf(t)
	if err := loadOrEmpty(); err != nil {
		t.Fatal(err)
	}

	called := false
	setTime := func(time.Duration) error {
		called = true
		return nil
	}
	if err := Set([]byte(`{"time_ms":1000,"device_id":"id"}`), setTime); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("time not forwarded")
	}
	if got := Get().TimeMs; got != nil {
		t.Errorf("time_ms stored: %d", *got)
	}
}

func TestUpdateTimeOffsetKeepsConfig(t *testing.T) {
	useTestConf(t)
	if err := loadOrEmpty(); err != nil {
		t.Fatal(err)
	}
	if err := Set([]byte(`{"device_id":"id"}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := UpdateTimeOffset(42); err != nil {
		t.Fatal(err)
	}
	got := Get()
	if deref(got.DeviceID) != "id" || got.TimeOffsetS == nil || *got.TimeOffsetS != 42 {
		t.Errorf("got device_id %s, offset %v", deref(got.DeviceID), got.TimeOffsetS)
	}
}

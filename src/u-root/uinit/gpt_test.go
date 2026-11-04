// Copyright 2026, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const gptHeader = `label: gpt
label-id: 226302C6-ACC7-DB41-988A-D3CC72620C27
device: run/disk.img
unit: sectors
first-lba: 34
last-lba: 2097118
sector-size: 512

`

const gptData = `run/disk.img3 : start=     1048704, size=     1048415, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, uuid=50467BDB-B0F3-A840-AB5B-1DF6DB161834, name="data"
`

// fakeSfdisk puts an sfdisk on PATH that dumps the given GPT for "-d" and
// otherwise stores its stdin in the returned file.
func fakeSfdisk(t *testing.T, dump string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dump"), []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
dir=$(dirname "$0")
if [ "$1" = -d ]; then cat "$dir/dump"; else cat >"$dir/written"; fi
`
	if err := os.WriteFile(filepath.Join(dir, "sfdisk"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return filepath.Join(dir, "written")
}

func TestGptSwapPartitions(t *testing.T) {
	written := fakeSfdisk(t, gptHeader+
		`run/disk.img1 : start=         128, size=      524288, type=FE3A2A5D-4F32-41A7-B725-ACCC3285A309, uuid=2F8DB682-3E0F-7149-96F2-55B2C82A3548, name="system1"
run/disk.img2 : start=      524416, size=      524288, type=FE3A2A5D-4F32-41A7-B725-ACCC3285A309, uuid=5373D8ED-591A-794D-9B72-47C7B0710B97, name="system2"
`+gptData)

	if err := gptSwapPartitions("run/disk.img"); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(written)
	if err != nil {
		t.Fatal(err)
	}
	want := gptHeader +
		`run/disk.img1 : start=      524416, size=      524288, type=FE3A2A5D-4F32-41A7-B725-ACCC3285A309, uuid=5373D8ED-591A-794D-9B72-47C7B0710B97, name="system2"
run/disk.img2 : start=         128, size=      524288, type=FE3A2A5D-4F32-41A7-B725-ACCC3285A309, uuid=2F8DB682-3E0F-7149-96F2-55B2C82A3548, name="system1"
` + gptData
	if diff := cmp.Diff(want, string(got)); diff != "" {
		t.Errorf("unexpected GPT written (-want +got):\n%s", diff)
	}
}

// Copyright 2026, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeTools puts programs on PATH that log their name to the returned file. The
// ones named in failing exit with an error.
func fakeTools(t *testing.T, failing ...string) string {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	for _, tool := range []string{"sfdisk", "dd", "mke2fs", "sync"} {
		script := "#!/bin/sh\necho " + tool + " >>" + calls + "\n"
		for _, f := range failing {
			if f == tool {
				script += "exit 1\n"
			}
		}
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return calls
}

func TestInstall(t *testing.T) {
	tests := map[string]struct {
		reset   bool
		failing []string
		wantErr bool
		want    string
	}{
		"update":          {false, nil, false, "dd\n"},
		"update dd fails": {false, []string{"dd"}, true, "dd\n"},
		"reset":           {true, nil, false, "sfdisk\nsync\ndd\ndd\nmke2fs\nsync\nsync\n"},
		"reset dd fails":  {true, []string{"dd"}, true, "sfdisk\nsync\ndd\n"},
		"sfdisk fails":    {true, []string{"sfdisk"}, true, "sfdisk\n"},
		"mke2fs fails":    {true, []string{"mke2fs"}, true, "sfdisk\nsync\ndd\ndd\nmke2fs\n"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			calls := fakeTools(t, test.failing...)
			err := install("image", "partitions", "-", "changes", test.reset)
			if (err != nil) != test.wantErr {
				t.Errorf("got error %v, wanted error: %t", err, test.wantErr)
			}
			got, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Errorf("got calls %q, wanted %q", got, test.want)
			}
		})
	}
}

// Copyright 2026, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"nethsm/internal/localconf"
)

const (
	fakeEtcdReady = `echo "ready to serve client requests" >&2; exec sleep 300`
	fakeEtcdFail  = `echo "fatal: no quorum" >&2; exit 1`
)

var initLocalConf = sync.OnceFunc(func() {
	if err := localconf.Init(make([]byte, 32)); err != nil {
		panic(err)
	}
})

// useFakeEtcd runs a shell script instead of etcd, with all its files in a
// temporary directory.
func useFakeEtcd(t *testing.T, script string) {
	t.Helper()
	initLocalConf()
	dir := t.TempDir()
	bin := filepath.Join(dir, "etcd")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}

	oldBin, oldData, oldJoin, oldSnapshot := etcdBin, etcdDataDir, etcdBackupJoin, etcdBackupSnapshot
	oldUtl := etcdutlBin
	oldUser, oldDelay := etcdUser, etcdRetryDelay
	t.Cleanup(func() {
		etcdBin, etcdDataDir, etcdBackupJoin, etcdBackupSnapshot = oldBin, oldData, oldJoin, oldSnapshot
		etcdutlBin = oldUtl
		etcdUser, etcdRetryDelay = oldUser, oldDelay
	})
	etcdBin, etcdDataDir = bin, data
	etcdBackupJoin = filepath.Join(dir, "backup")
	etcdBackupSnapshot = filepath.Join(dir, "backup.snapshot")
	etcdutlBin = filepath.Join(dir, "etcdutl") // missing unless a test adds it
	etcdUser, etcdRetryDelay = -1, time.Millisecond
}

// startSupervisor runs a new etcd supervisor until the end of the test.
func startSupervisor(t *testing.T) *etcdSupervisor {
	t.Helper()
	s := NewEtcdSupervisor()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run()
	}()
	t.Cleanup(func() {
		s.Shutdown()
		<-done
	})
	return s
}

// sendCmd sends a command to the supervisor and fails the test if it does not
// answer, which is what keeps the platform listener from serving anything else.
func sendCmd(t *testing.T, s *etcdSupervisor, c EtcdCommand) error {
	t.Helper()
	reply := make(chan error, 1)
	c.Reply = reply
	go s.SendCmd(c)
	select {
	case err := <-reply:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("etcd supervisor did not answer")
		return nil
	}
}

// etcdRunning waits for etcd to be in the wanted state.
func etcdRunning(s *etcdSupervisor, want bool) bool {
	for range 500 {
		if getClusterState(s.ProcessState.Load()).Running == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// makeEtcdData creates a directory with etcd data, identified by its file.
func makeEtcdData(t *testing.T, dir, file string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "member"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "member", file), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func hasEtcdData(dir, file string) bool {
	return pathExists(filepath.Join(dir, "member", file))
}

// fakeEtcdutl restores by creating the file "restored" in the data directory.
func fakeEtcdutl(t *testing.T) {
	t.Helper()
	script := `#!/bin/sh
while [ $# -gt 0 ]; do [ "$1" = --data-dir ] && dir=$2; shift; done
mkdir "$dir/member" && touch "$dir/member/restored"
`
	if err := os.WriteFile(etcdutlBin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

// waitForSupervisor returns when the supervisor is done with starting etcd.
func waitForSupervisor(t *testing.T, s *etcdSupervisor) {
	t.Helper()
	if err := sendCmd(t, s, EtcdCommand{Kind: -1}); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestEtcdSupervisorStartsEtcd(t *testing.T) {
	useFakeEtcd(t, fakeEtcdReady)
	s := startSupervisor(t)
	if err := sendCmd(t, s, EtcdCommand{Kind: -1}); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestEtcdSupervisorServesCommandsAfterGivingUp(t *testing.T) {
	useFakeEtcd(t, fakeEtcdFail)
	s := startSupervisor(t)
	// There is no etcdutl to restore with, what matters is getting an answer.
	if err := sendCmd(t, s, EtcdCommand{Kind: EtcdCmdForceNew}); err == nil {
		t.Fatal("force new cluster without etcdutl succeeded")
	}
}

func TestEtcdSupervisorSurvivesFailedForceNew(t *testing.T) {
	useFakeEtcd(t, fakeEtcdReady)
	makeEtcdData(t, etcdDataDir, "old")
	s := startSupervisor(t)
	if err := sendCmd(t, s, EtcdCommand{Kind: EtcdCmdForceNew}); err == nil {
		t.Fatal("force new cluster without etcdutl succeeded")
	}
	if !etcdRunning(s, true) {
		t.Error("etcd was not restarted")
	}
	waitForSupervisor(t, s)
	if !hasEtcdData(etcdDataDir, "old") {
		t.Error("data lost")
	}
}

// Etcd not starting after a restore is why FORCE-NEW-CLUSTER gets repeated.
func TestForceNewReplacesOldBackup(t *testing.T) {
	useFakeEtcd(t, fakeEtcdFail)
	fakeEtcdutl(t)
	makeEtcdData(t, etcdDataDir, "old")
	makeEtcdData(t, etcdBackupSnapshot, "older")
	s := startSupervisor(t)
	if err := sendCmd(t, s, EtcdCommand{Kind: EtcdCmdForceNew}); err != nil {
		t.Fatal(err)
	}
	if !hasEtcdData(etcdDataDir, "restored") {
		t.Error("data not restored")
	}
	if !hasEtcdData(etcdBackupSnapshot, "old") {
		t.Error("old data not in backup")
	}
}

func TestBackupEtcdReplacesOldBackup(t *testing.T) {
	useFakeEtcd(t, fakeEtcdReady)
	makeEtcdData(t, etcdDataDir, "old")
	makeEtcdData(t, etcdBackupJoin, "older")
	if err := backupEtcd(etcdBackupJoin); err != nil {
		t.Fatal(err)
	}
	if !hasEtcdData(etcdBackupJoin, "old") {
		t.Error("old data not in backup")
	}
	if !pathExists(etcdDataDir) {
		t.Error("no new data directory")
	}
}

func TestEtcdSupervisorKeepsEtcdRunningOnRejectedJoin(t *testing.T) {
	useFakeEtcd(t, fakeEtcdReady)
	s := startSupervisor(t)
	for _, cluster := range []string{"", " ", " a=https://b:2380", "a=https://b:2380 ", "a=https://b:2380 --log-outputs=stdout"} {
		err := sendCmd(t, s, EtcdCommand{Kind: EtcdCmdJoin, JoinArgs: JoinArgs{cluster}})
		if err == nil {
			t.Fatalf("join with cluster %q succeeded", cluster)
		}
		if !etcdRunning(s, true) {
			t.Errorf("etcd is stopped after cluster %q", cluster)
		}
	}
}

func TestEtcdSupervisorRestoresDataAfterFailedJoin(t *testing.T) {
	useFakeEtcd(t, `case "$*" in *--initial-cluster-state=existing*) echo "fatal: join rejected" >&2; exit 1;; esac
`+fakeEtcdReady)
	makeEtcdData(t, etcdDataDir, "old")
	s := startSupervisor(t)
	waitForSupervisor(t, s)
	err := sendCmd(t, s, EtcdCommand{Kind: EtcdCmdJoin, JoinArgs: JoinArgs{"a=https://b:2380"}})
	if err == nil {
		t.Fatal("failed join succeeded")
	}
	if !etcdRunning(s, true) {
		t.Error("etcd was not restarted")
	}
	if !hasEtcdData(etcdDataDir, "old") {
		t.Error("data not restored")
	}
	if pathExists(etcdBackupJoin) {
		t.Error("backup left behind")
	}
}

func TestEtcdSupervisorRestartsEtcdAfterFailedBackup(t *testing.T) {
	useFakeEtcd(t, fakeEtcdReady)
	s := startSupervisor(t)
	waitForSupervisor(t, s)
	// makes the backup fail
	if err := os.RemoveAll(etcdDataDir); err != nil {
		t.Fatal(err)
	}
	err := sendCmd(t, s, EtcdCommand{Kind: EtcdCmdJoin, JoinArgs: JoinArgs{"a=https://b:2380"}})
	if err == nil {
		t.Fatal("join without data succeeded")
	}
	if !etcdRunning(s, true) {
		t.Error("etcd was not restarted")
	}
}

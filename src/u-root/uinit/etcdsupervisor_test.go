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
	oldUser, oldDelay := etcdUser, etcdRetryDelay
	t.Cleanup(func() {
		etcdBin, etcdDataDir, etcdBackupJoin, etcdBackupSnapshot = oldBin, oldData, oldJoin, oldSnapshot
		etcdUser, etcdRetryDelay = oldUser, oldDelay
	})
	etcdBin, etcdDataDir = bin, data
	etcdBackupJoin = filepath.Join(dir, "backup")
	etcdBackupSnapshot = filepath.Join(dir, "backup.snapshot")
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

func TestEtcdSupervisorStartsEtcd(t *testing.T) {
	useFakeEtcd(t, fakeEtcdReady)
	s := startSupervisor(t)
	if err := sendCmd(t, s, EtcdCommand{Kind: -1}); err == nil {
		t.Fatal("unknown command accepted")
	}
}

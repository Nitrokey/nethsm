// Copyright 2026, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"container/ring"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"nethsm/internal/script"
	. "nethsm/internal/util"

	"github.com/google/go-cmp/cmp"
)

// See write_platform in s_keyfender/unikernel.ml
const commandDeadline = 30 * time.Second

var (
	testSupervisor *etcdSupervisor
	testProto      string
	testAddr       string
)

func send(t *testing.T, conn net.Conn, data string) {
	t.Helper()
	n, err := conn.Write([]byte(data))
	if err != nil {
		t.Fatalf("Cannot write to platformListener: %s", err)
	}
	if expected := len(data); n != expected {
		// according to io.Writer docs short writes must always set error
		t.Fatalf("Short write: %d != %d", n, expected)
	}
}

func command(t *testing.T, cmd string, additionalData string) (bool, string) {
	t.Helper()

	deadline := time.Now().Add(commandDeadline)
	t.Logf("Connecting to platform")
	conn, err := net.DialTimeout(testProto, testAddr, commandDeadline)
	if err != nil {
		t.Fatalf("Failed to connect to platformListener: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(deadline)

	t.Logf("Sending command to platform")
	send(t, conn, cmd+"\n")

	if additionalData != "" {
		send(t, conn, additionalData)
	}

	t.Logf("Reading data from platform")
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("Cannot read reply for command %s: %s", cmd, err)
	}
	t.Logf("data from platform: %s", data)
	status, response, _ := strings.Cut(string(data), " ")
	status = strings.TrimSpace(status)
	switch status {
	case "OK":
		return true, response
	case "ERROR":
		return false, response
	default:
		t.Fatalf("Unknown status %s", status)
		return false, ""
	}
}

func TestDiagnose(t *testing.T) {
	status, response := command(t, "DIAGNOSE", "")

	if !status {
		t.Fatalf("command error: %s", response)
	}

	var got diagnoseData
	if err := json.Unmarshal([]byte(response), &got); err != nil {
		t.Fatalf("Cannot parse reply: %s", err)
	}

	code := 1
	want := diagnoseData{
		ClusterLogs:     []map[string]any{},
		ClusterSnapshot: nil,
		ClusterState:    clusterState{Exited: &code},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("response mismatch (-want +got):\n%s", diff)
	}
}

func mockEtcdFail() error {
	s := script.New()
	exitedNtfy, exitedSig := MakeNtfyPair()
	cancel, _ := s.CancelableBackgroundExecAsf(exitedNtfy, &testSupervisor.ProcessState, -1, "%s", "/bin/false")
	testSupervisor.stopEtcd = func() {
		cancel()
		<-exitedSig
	}
	if err := s.Err(); err != nil {
		log.Printf("Cannot launch process")
		return err
	}
	return nil
}

func mockEtcdRun() error {
	s := script.New()
	exitedNtfy, exitedSig := MakeNtfyPair()
	// sleep more than 30s, which is the default deadline, and more than 60, which is the global deadline
	cancel, _ := s.CancelableBackgroundExecAsf(exitedNtfy, &testSupervisor.ProcessState, -1, "%s", "/bin/sleep 80")
	testSupervisor.stopEtcd = func() {
		cancel()
		<-exitedSig
	}
	if err := s.Err(); err != nil {
		log.Printf("Cannot launch process")
		return err
	}
	return nil
}

func TestDiagnoseRun(t *testing.T) {
	testSupervisor.stopEtcd()
	if err := mockEtcdRun(); err != nil {
		t.Fatalf("Cannot run etcd mock: %s", err)
	}
	defer testSupervisor.stopEtcd()

	// TODO: make snapshot mockable

	status, response := command(t, "DIAGNOSE", "")

	if !status {
		t.Fatalf("command error: %s", response)
	}

	var got diagnoseData
	if err := json.Unmarshal([]byte(response), &got); err != nil {
		t.Fatalf("Cannot parse reply: %s", err)
	}

	want := diagnoseData{
		ClusterLogs:     []map[string]any{},
		ClusterSnapshot: nil,
		ClusterState:    clusterState{Running: true},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("response mismatch (-want +got):\n%s", diff)
	}
}

func TestMain(m *testing.M) {
	c := make(chan string)
	tmpu, err := os.CreateTemp("", "test.*.unix")
	if err != nil {
		panic(err)
	}
	os.Remove(tmpu.Name())

	testProto = "unix"
	testAddr = tmpu.Name()
	testSupervisor = NewEtcdSupervisor()
	testSupervisor.Logs.Store(ring.New(1024))

	err = mockEtcdFail()
	if err != nil {
		panic(err)
	}

	go platformListener(c, testProto, testAddr, testSupervisor)
	fmt.Printf("Using unix socket: %v\n", testAddr)
	time.Sleep(1 * time.Second)
	m.Run()
}

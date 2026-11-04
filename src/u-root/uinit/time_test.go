// Copyright 2026, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"errors"
	"net"
	"testing"

	"github.com/beevik/ntp"

	"nethsm/internal/util"
)

// fakeNTPServer answers every query with the given stratum and returns its
// address.
func fakeNTPServer(t *testing.T, stratum byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { util.Close(conn) })
	go func() {
		query := make([]byte, 48)
		for {
			_, addr, err := conn.ReadFrom(query)
			if err != nil {
				return
			}
			resp := make([]byte, 48)
			resp[0] = 0x24 // NTPv4, server mode
			resp[1] = stratum
			copy(resp[24:32], query[40:48]) // origin = client's transmit time
			resp[40] = 0xE0                 // some transmit time
			_, _ = conn.WriteTo(resp, addr)
		}
	}()
	return conn.LocalAddr().String()
}

func TestSyncTimeRejectsBadServer(t *testing.T) {
	tests := map[string]struct {
		stratum byte
		want    error
	}{
		"kiss of death":  {0, ntp.ErrKissOfDeath},
		"unsynchronized": {16, ntp.ErrInvalidStratum},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := syncTime(fakeNTPServer(t, test.stratum), "")
			if !errors.Is(err, test.want) {
				t.Errorf("got %v, wanted %v", err, test.want)
			}
		})
	}
}

// Copyright 2026 - 2026, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// testPacket is the part of a packet the external drop rules look at.
type testPacket struct {
	iface   string
	nfproto byte
	header  []byte // network header
}

func ipv4Header(dst string, ihl byte) []byte {
	h := make([]byte, int(ihl)*4)
	h[0] = 0x40 | ihl
	copy(h[16:], net.ParseIP(dst).To4())
	return h
}

func ipv6Header(dst string) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	copy(h[24:], net.ParseIP(dst))
	return h
}

// dropped evaluates the expressions of one rule on a packet, using the single
// register the rules work with.
func dropped(t *testing.T, exprs []expr.Any, p testPacket) bool {
	t.Helper()
	var reg []byte
	for _, e := range exprs {
		switch e := e.(type) {
		case *expr.Meta:
			switch e.Key {
			case expr.MetaKeyIIFNAME:
				reg = []byte(p.iface + "\x00")
			case expr.MetaKeyNFPROTO:
				reg = []byte{p.nfproto}
			default:
				t.Fatalf("unexpected meta key %v", e.Key)
			}
		case *expr.Payload:
			reg = p.header[e.Offset : e.Offset+e.Len]
		case *expr.Bitwise:
			masked := make([]byte, e.Len)
			for i := range masked {
				masked[i] = reg[i]&e.Mask[i] ^ e.Xor[i]
			}
			reg = masked
		case *expr.Cmp:
			if bytes.Equal(reg, e.Data) != (e.Op == expr.CmpOpEq) {
				return false
			}
		case *expr.Verdict:
			return e.Kind == expr.VerdictDrop
		default:
			t.Fatalf("unexpected expression %T", e)
		}
	}
	return false
}

func TestExternalDropExprs(t *testing.T) {
	v4 := func(iface, dst string, ihl byte) testPacket {
		return testPacket{iface, unix.NFPROTO_IPV4, ipv4Header(dst, ihl)}
	}
	v6 := func(iface, dst string) testPacket {
		return testPacket{iface, unix.NFPROTO_IPV6, ipv6Header(dst)}
	}

	tests := []struct {
		name   string
		packet testPacket
		drop   bool
	}{
		{"external address", v4(extIface, "192.168.1.1", 5), false},
		{"external address v6", v6(extIface, "2001:db8::1"), false},
		{"external link-local address", v4(extIface, "169.254.1.1", 5), false},
		{"own keyfender side address", v4(extIface, "169.254.100.1", 5), true},
		{"keyfender", v4(extIface, keyfenderIP, 5), true},
		{"own platform side address", v4(extIface, "169.254.200.1", 5), true},
		{"platform", v4(extIface, platformIP, 5), true},
		{"own keyfender side address v6", v6(extIface, "fc00:1:100::1"), true},
		{"keyfender v6", v6(extIface, keyfenderIPv6), true},
		{"platform v6", v6(extIface, platformIPv6), true},
		{"neighbouring subnet v6", v6(extIface, "fc00:1:100::1:1"), false},
		{"IP options", v4(extIface, "192.168.1.1", 6), true},
		{"maximum IP options", v4(extIface, "192.168.1.1", 15), true},
		{"internal interface", v4(intIface, keyfenderIP, 5), false},
		{"IP options on internal interface", v4(intIface, keyfenderIP, 6), false},
		{"platform interface", v4(platIface, platformIP, 5), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			drop := false
			for _, exprs := range externalDropExprs() {
				drop = drop || dropped(t, exprs, tt.packet)
			}
			if drop != tt.drop {
				t.Errorf("dropped = %v, want %v", drop, tt.drop)
			}
		})
	}
}

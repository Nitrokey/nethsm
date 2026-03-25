// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"nethsm/hw"
	"nethsm/script"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	extIface      = "eth0"
	intIface      = "net0"
	platIface     = "net1"
	keyfenderIP   = "169.254.100.2" // us: 169.254.100.1
	platformIP    = "169.254.200.2" // us: 169.254.200.1
	keyfenderIPv6 = "fc00:1:100::2" // us: fc00:1:100::1
	platformIPv6  = "fc00:1:200::2" // us: fc00:1:200::1
)

// keep in sync with network in keyfender/json.ml
type NetworkConfig struct {
	Cidr    string `json:"cidr"`
	Gateway string `json:"gateway"`
}
type Network struct {
	V4 NetworkConfig `json:"ipv4"`
	V6 NetworkConfig `json:"ipv6,omitempty"`
}

// keep in sync with s_net_data in s_keyfender/unikernel.ml
type SNetData struct {
	Network *Network `json:"network,omitempty"`
}

// setProcFsInt writes an integer value to a procfs/sysctl file
func setProcFsInt(path string, value int) {
	err := os.WriteFile(path, []byte(fmt.Sprintf("%d", value)), 0o644)
	if err != nil {
		log.Printf("Failed to set %s to %d: %v", path, value, err)
	}
}

func configNet(conf Network) error {
	if hw.IsTesting() {
		return nil
	}

	cidrV4 := conf.V4.Cidr
	if cidrV4 == "" {
		cidrV4 = "192.168.1.1/24"
	}

	s := script.New()
	// V4 config
	s.Execf("/bbin/ip addr flush %s", extIface)
	s.Execf("/bbin/ip addr add %s dev %s", cidrV4, extIface)
	if conf.V4.Gateway != "" && conf.V4.Gateway != "0.0.0.0" {
		s.Execf("/bbin/ip route replace default via %s dev %s", conf.V4.Gateway, extIface)
	}

	// V6 config
	s.Execf("/bbin/ip -6 addr flush %s", extIface)
	if conf.V6.Cidr != "" {
		s.Execf("/bbin/ip -6 addr add %s dev %s", conf.V6.Cidr, extIface)
	}
	if conf.V6.Gateway != "" {
		s.Execf("/bbin/ip -6 route replace default via %s dev %s", conf.V6.Gateway, extIface)
	}
	return s.Err()
}

// networkListener receives config data from S-Keyfender and applies it.
//
// Due to there being no way to set a listen(2) backlog in Go, >1 connections
// will be accepted but only served one at a time, in the order that the OS
// queues them.
func networkListener(_ chan struct{}) {
	addr := G.netListenerAddress
	listener, err := net.Listen(G.listenerProtocol, addr)
	if err != nil {
		log.Fatalf("Unable to launch listener on %s:%s: %v", G.listenerProtocol,
			addr, err)
	}
	defer listener.Close()
	log.Printf("networkListener: Listening on %s:%s.", G.listenerProtocol,
		addr)

	var currentNetConf Network

	for {
		// No way to set listen(2) backlog here, see golang issues #39000, #6079.
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		remoteAddr := conn.RemoteAddr()

		// All requests except for UPDATE (see below) must complete within 5
		// seconds, otherwise an i/o timeout will be reported and the
		// connection will be shut down.
		conn.SetDeadline(time.Now().Add(time.Second * 5))

		// Wrap conn in a LimitedReader (lr) to ensure that we can't be DoS'ed
		// / run out of memory when doing operations such as ReadString().
		// Initially limit the amount read to 4096 bytes, this limit is raised
		// appropriately when processing commands such as UPDATE which read
		// larger amounts of data from conn.
		lr := &io.LimitedReader{
			R: conn,
			N: 4096,
		}

		var data SNetData
		err = json.NewDecoder(lr).Decode(&data)
		if err != nil {
			log.Printf("[%s] Error decoding JSON: %v", remoteAddr, err)
			conn.Close()
			continue
		}

		// Returns an OK response, optionally with a message if not empty.
		okResponse := func(m string) []byte {
			if m != "" {
				return []byte("OK " + m + "\n")
			} else {
				return []byte("OK\n")
			}
		}

		// Returns an ERROR response, optionally with an error message if e is
		// not nil.
		errorResponse := func(e error) []byte {
			if e != nil {
				return []byte("ERROR " + fmt.Sprintf("%v", e) + "\n")
			} else {
				return []byte("ERROR\n")
			}
		}
		var response []byte = nil

		if data.Network != nil {
			err := configNet(*data.Network)
			if err != nil {
				response = errorResponse(err)
				_ = configNet(currentNetConf)
			} else {
				currentNetConf = *data.Network
				log.Printf("Changed network config to %v", currentNetConf)
				response = okResponse("")
			}
		} else {
			response = errorResponse(fmt.Errorf("received invalid S-Net data"))
		}

		if response != nil {
			if _, err := conn.Write(response); err != nil {
				log.Printf("[%s] Error writing to connection: %v", remoteAddr, err)
			}
		}

		conn.Close()
	}
}

// sNetExternalActions are executed for S-Net-External.
func sNetExternalActions() {
	if !hw.IsTesting() {
		mountMuenFs()
		G.s.Logf("Channels:")
		G.s.Execf("/bbin/ls -l /muenfs")

		loadUnikernelNets()

		G.s.Execf("/bbin/ip addr add 169.254.100.1/24 dev %s", intIface)
		G.s.Execf("/bbin/ip -6 addr add fc00:1:100::1/120 dev %s", intIface)
		G.s.Execf("/bbin/ip addr add 169.254.200.1/24 dev %s", platIface)
		G.s.Execf("/bbin/ip -6 addr add fc00:1:200::1/120 dev %s", platIface)
		G.s.Execf("/bbin/ip link set dev %s up", extIface)
		G.s.Execf("/bbin/ip link set dev %s up", intIface)
		G.s.Execf("/bbin/ip link set dev %s up", platIface)

		// Enable IP forwarding for NAT to work
		G.s.WriteFile("/proc/sys/net/ipv4/ip_forward", "1")
		G.s.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", "1")

		// Increase conntrack table size to handle many concurrent connections
		G.s.WriteFile("/proc/sys/net/netfilter/nf_conntrack_max", "262144")

		if err := G.s.Err(); err != nil {
			log.Printf("Script failed: %v", err)
			// return
		}

		dumpNetworkStatus()
	}

	setupNFTables()

	ch := make(chan struct{})
	startTask("networkListener", func() { networkListener(ch) })
	<-ch
}

func setupNFTables() {
	conn, err := nftables.New()
	if err != nil {
		log.Fatalf("Failed to create nftables connection: %v", err)
	}

	natTable := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "nethsm_nat",
	})

	preroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "PREROUTING",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	postroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "POSTROUTING",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// Utility function to make a DNAT from a port to a given IP (v4 or v6)
	makeDnat := func(port uint16, destIp net.IP, ipFamily uint32) *nftables.Rule {
		return &nftables.Rule{
			Table: natTable,
			Chain: preroutingChain,
			Exprs: []expr.Any{
				// Match input interface
				&expr.Meta{
					Key:      expr.MetaKeyIIFNAME,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(extIface + "\x00"),
				},
				// Match TCP
				&expr.Meta{
					Key:      expr.MetaKeyL4PROTO,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{unix.IPPROTO_TCP},
				},
				// Match dest port
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.BigEndian.PutUint16(port),
				},
				// DNAT to dest
				&expr.Immediate{
					Register: 1,
					Data:     destIp,
				},
				&expr.NAT{
					Type:       expr.NATTypeDestNAT,
					Family:     ipFamily,
					RegAddrMin: 1,
					RegAddrMax: 1,
				},
			},
		}
	}

	// DNAT port 443 to keyfender (IPv4)
	conn.AddRule(makeDnat(443,
		net.ParseIP(keyfenderIP).To4(),
		unix.NFPROTO_IPV4))

	// DNAT port 443 to keyfender (IPv6)
	conn.AddRule(makeDnat(443,
		net.ParseIP(keyfenderIPv6),
		unix.NFPROTO_IPV6))

	// DNAT port 2380 to platform (IPv4)
	conn.AddRule(makeDnat(2380,
		net.ParseIP(platformIP).To4(),
		unix.NFPROTO_IPV4))

	// DNAT port 2380 to platform (IPv6)
	conn.AddRule(makeDnat(2380,
		net.ParseIP(platformIPv6),
		unix.NFPROTO_IPV6))

	// Utility function to make a SNAT rule: masquerading traffic
	// from source IP (v4 or v6) going out on external interface
	makeSnat := func(srcIp net.IP) *nftables.Rule {
		var ipOffset uint32
		var proto byte
		ipLen := len(srcIp)
		if ipLen == 16 {
			ipOffset = 8
			proto = unix.NFPROTO_IPV6
		} else {
			ipOffset = 12
			proto = unix.NFPROTO_IPV4
		}
		return &nftables.Rule{
			Table: natTable,
			Chain: postroutingChain,
			Exprs: []expr.Any{
				// Match output interface
				&expr.Meta{
					Key:      expr.MetaKeyOIFNAME,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(extIface + "\x00"),
				},
				// Match IP kind
				&expr.Meta{
					Key:      expr.MetaKeyNFPROTO,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{proto},
				},
				// Match source IP
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipOffset,
					Len:          uint32(ipLen),
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     srcIp,
				},
				// Masquerade (SNAT to external interface IP)
				&expr.Masq{},
			},
		}
	}

	// Masquerade keyfender to external (IPv4)
	conn.AddRule(makeSnat(net.ParseIP(keyfenderIP).To4()))

	// Masquerade keyfender to external (IPv6)
	conn.AddRule(makeSnat(net.ParseIP(keyfenderIPv6)))

	// Masquerade platform to external (IPv4)
	conn.AddRule(makeSnat(net.ParseIP(platformIP).To4()))

	// Masquerade platform to external (IPv6)
	conn.AddRule(makeSnat(net.ParseIP(platformIPv6)))

	// Commit the changes
	if err := conn.Flush(); err != nil {
		log.Fatalf("Failed to commit nftables changes: %v", err)
	}

	log.Printf("nftables NAT rules added successfully")
}

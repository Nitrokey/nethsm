// Copyright 2023 - 2023, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"log"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	extIface     = "eth0"
	intIface     = "net0"
	keyfenderMAC = "0a:0b:0c:0d:0e:02"
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// sNetExternalActions are executed for S-Net-External.
func sNetExternalActions() {
	mountMuenFs()
	G.s.Logf("Channels:")
	G.s.Execf("/bbin/ls -l /muenfs")

	loadUnikernelNets()

	// Enumerate eth* and net*, and bridge them all on br0.
	// Note that Linux bridges will "acquire" the MAC address of the first
	// child interface attached to the bridge, so intentionally start with
	// eth* here.
	G.s.Execf("/bbin/ip link add br0 type bridge")
	G.s.Execf("/bbin/ip link set %s master br0", extIface)
	G.s.Execf("/bbin/ip link set %s master br0", intIface)
	setProcFs("/sys/class/net/br0/brif/"+extIface+"/learning", false)
	setProcFs("/sys/class/net/br0/brif/"+intIface+"/learning", false)
	G.s.Execf("/bbin/ip link set dev %s up", extIface)
	G.s.Execf("/bbin/ip link set dev %s up", intIface)
	G.s.Execf("/bbin/ip link set dev br0 up")

	setupNFTables()

	dumpNetworkStatus()

	if err := G.s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}
}

func getMACAddress(interfaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}
	return iface.HardwareAddr, nil
}

func setupNFTables() {
	c, err := nftables.New()
	if err != nil {
		log.Fatalf("Failed to create nftables connection: %v", err)
	}

	// Get the real MAC address of iface
	extMAC, err := getMACAddress(extIface)
	if err != nil {
		log.Fatalf("Failed to get MAC address of %s: %v", extIface, err)
	}

	// Parse destination MAC address
	intMAC, err := net.ParseMAC(keyfenderMAC)
	if err != nil {
		log.Fatalf("Failed to parse destination MAC: %v", err)
	}

	// Create the "nat" table in the bridge family if it doesn't exist
	nat := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyBridge,
		Name:   "nat",
	})

	// Create PREROUTING and POSTROUTING chains
	prerouting := c.AddChain(&nftables.Chain{
		Name:     "PREFORWARD",
		Table:    nat,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(-300),
	})

	postrouting := c.AddChain(&nftables.Chain{
		Name:     "POSTFORWARD",
		Table:    nat,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityRef(300),
	})

	// PREROUTING rule
	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
		Exprs: exp{}.iifname(extIface).arpHWTarget(extMAC).arpSetHWTarget(intMAC).cont(),
	})
	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
		Exprs: exp{}.iifname(extIface).etherDst(extMAC).etherSetDst(intMAC).accept(),
	})
	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
		Exprs: exp{}.iifname(extIface).etherDst(broadcastMAC).accept(),
	})
	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
		Exprs: exp{}.iifname(extIface).drop(),
	})

	// POSTROUTING rule
	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: postrouting,
		Exprs: exp{}.oifname(extIface).arpHWSender(intMAC).arpSetHWSender(extMAC).cont(),
	})
	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: postrouting,
		Exprs: exp{}.oifname(extIface).etherSrc(intMAC).etherSetSrc(extMAC).accept(),
	})

	// Commit the changes
	if err := c.Flush(); err != nil {
		log.Fatalf("Failed to commit changes: %v", err)
	}

	log.Printf("nftables rules for %s/%s added successfully", extMAC, intMAC)
}

const (
	offsetEthDst      = 0
	offsetEthSrc      = 6
	offsetEthType     = 12
	offsetArpHWSender = 8
	offsetArpHWTarget = 18
	arpHeader         = "\x00\x01\x08\x00\x06\x04"
	ethTypeArp        = "\x08\x06"
)

type exp []expr.Any

func (e exp) iifname(iface string) exp {
	return ifname(e, expr.MetaKeyIIFNAME, iface)
}

func (e exp) oifname(iface string) exp {
	return ifname(e, expr.MetaKeyOIFNAME, iface)
}

func (e exp) etherDst(mac net.HardwareAddr) exp {
	return match(e, expr.PayloadBaseLLHeader, offsetEthDst, mac)
}

func (e exp) etherSrc(mac net.HardwareAddr) exp {
	return match(e, expr.PayloadBaseLLHeader, offsetEthSrc, mac)
}

func (e exp) etherSetDst(mac net.HardwareAddr) exp {
	return write(e, expr.PayloadBaseLLHeader, offsetEthDst, mac)
}

func (e exp) etherSetSrc(mac net.HardwareAddr) exp {
	return write(e, expr.PayloadBaseLLHeader, offsetEthSrc, mac)
}

func (e exp) arpHWSender(mac net.HardwareAddr) exp {
	return arpHW(e, offsetArpHWSender, mac)
}

func (e exp) arpHWTarget(mac net.HardwareAddr) exp {
	return arpHW(e, offsetArpHWTarget, mac)
}

func (e exp) arpSetHWSender(mac net.HardwareAddr) exp {
	return write(e, expr.PayloadBaseNetworkHeader, offsetArpHWSender, mac)
}

func (e exp) arpSetHWTarget(mac net.HardwareAddr) exp {
	return write(e, expr.PayloadBaseNetworkHeader, offsetArpHWTarget, mac)
}

func ifname(e exp, k expr.MetaKey, iface string) exp {
	e = append(e,
		&expr.Meta{Key: k, Register: 1})
	e = append(e,
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(iface + "\x00"),
		})
	return e
}

func arpHW(e exp, offset uint32, mac net.HardwareAddr) exp {
	e = match(e, expr.PayloadBaseLLHeader, offsetEthType, []byte(ethTypeArp))
	e = match(e, expr.PayloadBaseNetworkHeader, 0, []byte(arpHeader))
	e = match(e, expr.PayloadBaseNetworkHeader, offset, mac)
	return e
}

func match(e exp, base expr.PayloadBase, offset uint32, data []byte) exp {
	// Load
	e = append(e,
		&expr.Payload{
			DestRegister: 1,
			Base:         base,
			Offset:       offset,
			Len:          uint32(len(data)),
		})
	// Match source MAC
	e = append(e,
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     data,
		})
	return e
}

func write(e exp, base expr.PayloadBase, offset uint32, data []byte) exp {
	// Set new source MAC
	e = append(e,
		&expr.Immediate{
			Register: 1,
			Data:     data,
		})
	e = append(e,
		&expr.Payload{
			OperationType:  expr.PayloadWrite,
			SourceRegister: 1,
			Base:           base,
			Offset:         offset,
			Len:            uint32(len(data)),
		})
	return e
}

func (e exp) accept() exp {
	e = append(e,
		&expr.Verdict{Kind: expr.VerdictAccept})
	return e
}

func (e exp) cont() exp {
	e = append(e,
		&expr.Verdict{Kind: expr.VerdictContinue})
	return e
}

func (e exp) drop() exp {
	e = append(e,
		&expr.Verdict{Kind: expr.VerdictDrop})
	return e
}

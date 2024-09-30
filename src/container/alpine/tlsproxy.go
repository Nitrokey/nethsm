// Copyright 2025 - 2025, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
)

const (
	defaultListenAddr = "localhost:2379"
)

func handleConnection(clientConn net.Conn, tlsConfig *tls.Config, etcdAddr string) {
	defer clientConn.Close()

	etcdConn, err := tls.Dial("tcp", etcdAddr, tlsConfig)
	if err != nil {
		log.Printf("Failed to connect to etcd server: %v", err)
		return
	}
	defer etcdConn.Close()

	go io.Copy(etcdConn, clientConn)
	io.Copy(clientConn, etcdConn)
}

func main() {
	var listenAddr string
	var etcdAddr string
	var insecure bool
	var clientCert string
	var clientKey string
	var caCertPath string

	flag.StringVar(&listenAddr, "listen", defaultListenAddr, "Address to listen on")
	flag.StringVar(&etcdAddr, "etcd", "", "Address of the etcd server")
	flag.BoolVar(&insecure, "insecure", false, "Enable insecure mode (skip TLS verification, no client cert required)")
	flag.StringVar(&clientCert, "client-cert", "", "Path to the client certificate")
	flag.StringVar(&clientKey, "client-key", "", "Path to the client key")
	flag.StringVar(&caCertPath, "ca-cert", "", "Path to the CA certificate")
	flag.Parse()

	if etcdAddr == "" {
		log.Fatalf("The etcd server address must be specified.")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"h2"},
	}

	if !insecure {
		if clientCert != "" && clientKey != "" {
			cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
			if err != nil {
				log.Fatalf("Failed to load client certificate: %v", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else {
			log.Printf("Client certificate or key not provided, proceeding without them.")
		}

		if caCertPath != "" {
			caCertPool, err := loadCACertPool(caCertPath)
			if err != nil {
				log.Fatalf("Failed to load CA certificate: %v", err)
			}
			tlsConfig.RootCAs = caCertPool
		} else {
			log.Printf("CA certificate not provided, using default root CAs.")
		}
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()

	log.Printf("TLS proxy listening on: %s", listenAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(clientConn, tlsConfig, etcdAddr)
	}
}

func loadCACertPool(caCertPath string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("Failed to append CA certificate.")
	}

	return caCertPool, nil
}
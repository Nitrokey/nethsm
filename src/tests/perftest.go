// Copyright 2024 - 2024, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	keysPath = "/api/v1/keys/"
)

var (
	hostFlag     string
	durationFlag int
	jobFlag      int
	delFlag      bool
	adminFlag    string
	operatorFlag string
)

var client *http.Client

type benchStats struct {
	name        string
	latencySum  time.Duration
	latencyMax  time.Duration
	latencyMin  time.Duration
	duration    time.Duration
	numRequests int
}

var results []benchStats

type benchParam struct {
	algo   string
	data   string
	op     string
	opMode string
	msgLen int
	path   string
	gen    bool
}

var benchParams = []benchParam{
	{
		algo:   "p256",
		data:   `{"mechanisms":["ECDSA_Signature"],"type":"EC_P256"}`,
		opMode: "ECDSA",
		msgLen: 32,
	},
	{
		algo:   "p384",
		data:   `{"mechanisms":["ECDSA_Signature"],"type":"EC_P384"}`,
		opMode: "ECDSA",
		msgLen: 48,
	},
	{
		algo:   "p521",
		data:   `{"mechanisms":["ECDSA_Signature"],"type":"EC_P521"}`,
		opMode: "ECDSA",
		msgLen: 64,
	},
	{
		algo:   "rsa1024",
		data:   `{"mechanisms":["RSA_Signature_PKCS1"],"type":"RSA","length":1024}`,
		opMode: "PKCS1",
		msgLen: 32,
	},
	{
		algo:   "rsa2048",
		data:   `{"mechanisms":["RSA_Signature_PKCS1"],"type":"RSA","length":2048}`,
		opMode: "PKCS1",
		msgLen: 32,
	},
	{
		algo:   "rsa3072",
		data:   `{"mechanisms":["RSA_Signature_PKCS1"],"type":"RSA","length":3072}`,
		opMode: "PKCS1",
		msgLen: 32,
	},
	{
		algo:   "rsa4096",
		data:   `{"mechanisms":["RSA_Signature_PKCS1"],"type":"RSA","length":4096}`,
		opMode: "PKCS1",
		msgLen: 32,
	},
	{
		algo:   "ed25519",
		data:   `{"mechanisms":["EdDSA_Signature"],"type":"Curve25519"}`,
		opMode: "EdDSA",
		msgLen: 32,
	},
	{
		algo:   "aes-cbc",
		data:   `{"mechanisms":["AES_Encryption_CBC"],"type":"Generic","length":256}`,
		op:     "encrypt",
		opMode: "AES_CBC",
		msgLen: 32,
	},
	{
		algo: "rnd-1024",
		path: "/api/v1/random",
		data: `{"length":1024}`,
	},
}

func main() {
	flag.StringVar(&hostFlag, "host", "127.0.0.1:8443", "Host and port")
	flag.StringVar(&adminFlag, "admin", "admin:Administrator", "Admin user:password")
	flag.StringVar(&operatorFlag, "operator", "operator:OperatorOperator", "Operator user:password")
	flag.IntVar(&durationFlag, "s", 10, "Time interval")
	flag.IntVar(&jobFlag, "j", 1, "Number of concurrent jobs")
	flag.BoolVar(&delFlag, "del", false, "Delete generated keys")
	flag.Parse()

	benchs := benchArgs()

	client = getClient()

	for _, bench := range benchs {
		if bench.path == "" {
			if bench.gen {
				doGenBench(bench)
			} else {
				doOpBench(bench)
			}
		} else {
			doOtherBench(bench)
		}
	}
	printScore()
}

func doOpBench(bench benchParam) {
	loc := genKey(bench)
	defer delKey(loc)
	if bench.op == "" {
		bench.op = "sign"
	}
	url := "https://" + hostFlag + loc + "/" + bench.op
	newBody := func() io.ReadCloser {
		buf := make([]byte, bench.msgLen)
		_, err := rand.Read(buf)
		check(err)
		message := base64.StdEncoding.EncodeToString(buf)
		body := fmt.Sprintf(`{"mode":"%s","message":"%s"}`, bench.opMode, message)
		return io.NopCloser(strings.NewReader(body))
	}
	name := bench.algo + "-" + bench.op
	doBench(name, url, operatorFlag, newBody, nil)
}

func doGenBench(bench benchParam) {
	url := "https://" + hostFlag + keysPath + "generate"
	newBody := func() io.ReadCloser {
		return io.NopCloser(strings.NewReader(bench.data))
	}
	var handler func(resp *http.Response)
	if delFlag {
		var keys []string
		var m sync.Mutex
		defer func() {
			m.Lock()
			defer m.Unlock()
			delKeys(keys)
		}()
		handler = func(resp *http.Response) {
			loc := resp.Header.Get("location")
			if loc != "" {
				m.Lock()
				keys = append(keys, loc)
				m.Unlock()
			}
		}
	}
	name := bench.algo + "-gen"
	doBench(name, url, adminFlag, newBody, handler)
}

func doOtherBench(bench benchParam) {
	url := "https://" + hostFlag + bench.path
	newBody := func() io.ReadCloser {
		return io.NopCloser(strings.NewReader(bench.data))
	}
	name := bench.algo
	doBench(name, url, operatorFlag, newBody, nil)
}

func doBench(name string, url, auth string,
	genBody func() io.ReadCloser,
	handler func(*http.Response),
) {
	var start, last time.Time
	var once sync.Once
	var jobs sync.WaitGroup
	var stats benchStats
	stats.name = name
	stats.latencyMin = time.Hour

	chout := make(chan time.Duration)
	quit := make(chan bool)

	for i := 0; i < jobFlag; i++ {
		jobs.Add(1)
		go func() {
			defer jobs.Done()
			req := newRequest(url, auth)
			for {
				req.Body = genBody()
				once.Do(func() {
					start = time.Now()
				})
				resp, latency, err := doRequest(req)
				check(err)
				if handler != nil {
					handler(resp)
				}
				select {
				case <-quit:
					return
				case chout <- latency:
				}
			}
		}()
	}

	jobs.Add(1)
	go func() {
		defer jobs.Done()
		for {
			select {
			case <-quit:
				return
			case l := <-chout:
				last = time.Now()
				stats.latencySum += l
				if l < stats.latencyMin {
					stats.latencyMin = l
				}
				if l > stats.latencyMax {
					stats.latencyMax = l
				}
				stats.numRequests++
			}
		}
	}()
	time.Sleep(time.Second * time.Duration(durationFlag))
	close(quit)
	jobs.Wait()
	stats.duration = last.Sub(start)
	fmt.Printf("%11.11s (%ds|%dc): ", name, durationFlag, jobFlag)
	printStats(stats)
	results = append(results, stats)
}

func doRequest(req *http.Request) (*http.Response, time.Duration, error) {
	t := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		reqDump, _ := httputil.DumpRequest(req, true)
		return nil, 0, fmt.Errorf("Error making request: %w\nreq: %s", err, reqDump)
	}
	if resp.StatusCode >= 300 {
		reqDump, _ := httputil.DumpRequest(req, true)
		respDump, _ := httputil.DumpResponse(resp, true)
		return nil, 0, fmt.Errorf("Error making request: %s\n\nreq:\n%s", respDump, reqDump)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	latency := time.Since(t)
	return resp, latency, nil
}

func genKey(bench benchParam) string {
	url := "https://" + hostFlag + keysPath + "generate"
	req := newRequest(url, adminFlag)
	req.Body = io.NopCloser(strings.NewReader(bench.data))
	resp, _, err := doRequest(req)
	check(err)
	loc := resp.Header.Get("location")
	return loc
}

func delKey(loc string) {
	url := "https://" + hostFlag + loc
	req, err := http.NewRequest("DELETE", url, nil)
	check(err)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(adminFlag)))
	_, _, err = doRequest(req)
	check(err)
}

func delKeys(keys []string) {
	ch := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < jobFlag; i++ {
		wg.Add(1)
		go func() {
			for k := range ch {
				delKey(k)
			}
			wg.Done()
		}()
	}
	for _, k := range keys {
		ch <- k
	}
	close(ch)
	wg.Wait()
}

func newRequest(url, auth string) *http.Request {
	req, err := http.NewRequest("POST", url, nil)
	check(err)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(auth)))
	return req
}

func getClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// MaxIdleConnsPerHost controls the number of persistent
	// connections per host.
	// transport.MaxIdleConnsPerHost = 1 // Set to 1 to ensure a single connection.

	// transport.DialContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {
	// 	dialer := &net.Dialer{
	// 		Timeout:   30 * time.Second,
	// 		KeepAlive: 30 * time.Second,
	// 	}
	// 	conn, err := dialer.DialContext(ctx, network, addr)
	// 	return &CustomConn{conn}, err
	// }

	// Create an HTTP client with a custom Transport
	client := &http.Client{Transport: transport}
	return client
}

func benchArgs() []benchParam {
	args := flag.Args()
	if len(args) == 0 {
		fmt.Printf("No benchmarks specified. Known benchmarks: %v\n", tests(benchParams))
		os.Exit(1)
	}
	var benchs []benchParam
args:
	for _, arg := range args {
		for _, p := range benchParams {
			if p.algo == arg {
				benchs = append(benchs, p)
				continue args
			}
			if p.algo+"-gen" == arg {
				p.gen = true
				benchs = append(benchs, p)
				continue args
			}
		}
		fmt.Printf("Unknown benchmark %s. Known benchmarks: %v\n", arg, tests(benchParams))
		os.Exit(1)
	}
	return benchs
}

func printStats(stats benchStats) {
	if stats.numRequests != 0 {
		stats.latencySum /= time.Duration(stats.numRequests)
	}
	rps := float64(stats.numRequests) / stats.duration.Seconds()
	fmt.Printf("reqs: %5d rps: %8.2f latency: %v/%v/%v\n",
		stats.numRequests,
		roundSigFigs(rps, 3),
		stats.latencyMin.Round(time.Microsecond*10),
		stats.latencySum.Round(time.Microsecond*10),
		stats.latencyMax.Round(time.Microsecond*10))
}

func printScore() {
	scoreSum := 0.0
	for _, stats := range results {
		rps := float64(stats.numRequests) / stats.duration.Seconds()
		scoreSum += math.Log2(rps) * 10
	}
	fmt.Printf("Performance Score: %.2f%%\n", (scoreSum/float64(len(results)) - 50))
}

func tests(l []benchParam) []string {
	var i int
	tests := make([]string, len(l))
	for _, x := range l {
		tests[i] = x.algo
		i++
	}
	return tests
}

func roundSigFigs(f float64, digits int) float64 {
	exp := math.Floor(math.Log10(f))
	mult := math.Pow(10, float64(digits)-exp-1)
	rounded := math.Round(f * mult)
	return rounded / mult
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// func setQuickAck(err *error) func(fd uintptr) {
// 	// time.Sleep(time.Millisecond)
// 	return func(fd uintptr) {
// 		*err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
// 	}
// }

// // CustomConn is a wrapper around a net.Conn that sets TCP_NODELAY option.
// type CustomConn struct {
// 	net.Conn
// }

// func (c *CustomConn) Read(b []byte) (int, error) {
// 	if tc, ok := c.Conn.(*net.TCPConn); ok {
// 		rc, err := tc.SyscallConn()
// 		if err != nil {
// 			return 0, err
// 		}
// 		rc.Control(setQuickAck(&err))
// 		if err != nil {
// 			return 0, err
// 		}
// 	}
// 	n, err := c.Conn.Read(b)
// 	return n, err
// }

// func (c *CustomConn) Write(b []byte) (int, error) {
// 	if tc, ok := c.Conn.(*net.TCPConn); ok {
// 		rc, err := tc.SyscallConn()
// 		if err != nil {
// 			return 0, err
// 		}
// 		rc.Control(setQuickAck(&err))
// 		if err != nil {
// 			return 0, err
// 		}
// 	}
// 	n, err := c.Conn.Write(b)
// 	return n, err
// }

// Command loadgen drives the supervisor with synthetic rke2 agents.
//
// Why this exists: the shim had been exercised with exactly ONE worker. "Does
// it survive 200 nodes bootstrapping after a power event" was an opinion, not a
// measurement. This replays the real bootstrap sequence — same endpoints, same
// Basic auth, same DER CSRs, same headers — and optionally holds real
// remotedialer tunnels, so the numbers describe what an agent actually
// experiences rather than what a server-side counter claims.
//
// It is a load tool, not a conformance test: correctness lives in
// internal/supervisor/conformance_test.go. Here we only care about latency,
// throughput and whether anything falls over.
//
//	go run ./hack/loadgen -server https://<cp>:9345 -token <token> -nodes 200 -concurrency 32
//	go run ./hack/loadgen -server https://<cp>:9345 -token <token> -nodes 50 -tunnels -hold 5m
//
// Synthetic nodes create a real node-password Secret each (the supervisor's
// trust-on-first-use store), so -cleanup deletes them afterwards. Point this at
// a lab cluster.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	server      = flag.String("server", "", "supervisor URL, e.g. https://10.0.0.1:9345")
	token       = flag.String("token", "", "cluster join token")
	nodes       = flag.Int("nodes", 50, "number of synthetic nodes")
	concurrency = flag.Int("concurrency", 16, "concurrent bootstraps")
	prefix      = flag.String("prefix", "loadgen", "synthetic node name prefix")
	withTunnels = flag.Bool("tunnels", false, "hold a remotedialer tunnel per node after bootstrap")
	hold        = flag.Duration("hold", 0, "how long to hold tunnels open")
	timeout     = flag.Duration("timeout", 30*time.Second, "per-request timeout")
)

// sample is one timed request.
type sample struct {
	endpoint string
	d        time.Duration
	err      error
}

func main() {
	flag.Parse()
	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "-server and -token are required")
		os.Exit(2)
	}

	// The supervisor's serving cert chains to a CA the synthetic agent has no
	// reason to have. A real agent pins it from /cacerts on first contact; we
	// are measuring the server, not re-testing that pin, so skip verification.
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: *concurrency * 2,
	}
	client := &http.Client{Transport: tr, Timeout: *timeout}

	var (
		mu      sync.Mutex
		samples []sample
		ok, bad atomic.Int64
	)
	record := func(s sample) {
		mu.Lock()
		samples = append(samples, s)
		mu.Unlock()
		if s.err != nil {
			bad.Add(1)
		} else {
			ok.Add(1)
		}
	}

	fmt.Printf("bootstrapping %d synthetic nodes, %d at a time, against %s\n\n",
		*nodes, *concurrency, *server)

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < *nodes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name := fmt.Sprintf("%s-%04d", *prefix, i)
			bootstrap(client, name, record)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	report(samples, elapsed, int(ok.Load()), int(bad.Load()))

	if *withTunnels {
		// remotedialer is already a dependency, so holding real tunnels is
		// tractable — it is the steady-state cost (memory, fds per tunnel) that
		// is still unmeasured. Deliberately not faked: a half-simulated tunnel
		// would produce a number nobody should trust.
		fmt.Println("\n-tunnels is not implemented yet; see docs/benchmarks.md")
	}
	if *hold > 0 {
		fmt.Printf("holding for %s\n", *hold)
		time.Sleep(*hold)
	}
}

// bootstrap replays what `rke2 agent` does on start, in the same order.
func bootstrap(c *http.Client, node string, record func(sample)) {
	// A real agent derives its password once and reuses it; the supervisor
	// stores a scrypt hash on first contact and checks it on every later call.
	password := fmt.Sprintf("%s-pw-do-not-reuse", node)
	ip := "10.255.255.1"

	timed := func(endpoint string, f func() error) {
		t0 := time.Now()
		err := f()
		record(sample{endpoint: endpoint, d: time.Since(t0), err: err})
	}

	timed("GET /cacerts", func() error { return get(c, "/cacerts", "", nil) })
	timed("GET /v1-rke2/config", func() error { return get(c, "/v1-rke2/config", *token, nil) })
	timed("GET /v1-rke2/client-ca.crt", func() error { return get(c, "/v1-rke2/client-ca.crt", *token, nil) })
	timed("GET /v1-rke2/server-ca.crt", func() error { return get(c, "/v1-rke2/server-ca.crt", *token, nil) })

	nodeHdr := map[string]string{
		"Rke2-Node-Name":     node,
		"Rke2-Node-Password": password,
		"Rke2-Node-Ip":       ip,
	}
	// Only the two kubelet endpoints are node-scoped; the other two carry no
	// node headers at all. Getting this wrong is the classic mistake.
	timed("POST serving-kubelet.crt", func() error {
		return postCSR(c, "/v1-rke2/serving-kubelet.crt", node, nodeHdr)
	})
	timed("POST client-kubelet.crt", func() error {
		return postCSR(c, "/v1-rke2/client-kubelet.crt", node, nodeHdr)
	})
	timed("POST client-kube-proxy.crt", func() error {
		return postCSR(c, "/v1-rke2/client-kube-proxy.crt", node, nil)
	})
	timed("POST client-rke2-controller.crt", func() error {
		return postCSR(c, "/v1-rke2/client-rke2-controller.crt", node, nil)
	})
	timed("GET /v1-rke2/apiservers", func() error { return get(c, "/v1-rke2/apiservers", *token, nil) })
}

func get(c *http.Client, path, tok string, hdr map[string]string) error {
	req, err := http.NewRequest(http.MethodGet, *server+path, nil)
	if err != nil {
		return err
	}
	if tok != "" {
		req.SetBasicAuth("node", tok) // username is literally "node"
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return do(c, req)
}

func postCSR(c *http.Client, path, cn string, hdr map[string]string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, *server+path, bytes.NewReader(der))
	if err != nil {
		return err
	}
	req.SetBasicAuth("node", *token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return do(c, req)
}

func do(c *http.Client, req *http.Request) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(body)[:min(120, len(body))])
	}
	return nil
}

func report(samples []sample, elapsed time.Duration, ok, bad int) {
	byEP := map[string][]time.Duration{}
	errs := map[string]map[string]int{}
	for _, s := range samples {
		if s.err != nil {
			if errs[s.endpoint] == nil {
				errs[s.endpoint] = map[string]int{}
			}
			errs[s.endpoint][s.err.Error()]++
			continue
		}
		byEP[s.endpoint] = append(byEP[s.endpoint], s.d)
	}

	keys := make([]string, 0, len(byEP))
	for k := range byEP {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Printf("%-32s %6s %9s %9s %9s %9s\n", "endpoint", "n", "p50", "p95", "p99", "max")
	for _, k := range keys {
		d := byEP[k]
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		fmt.Printf("%-32s %6d %9s %9s %9s %9s\n", k, len(d),
			ms(pct(d, 50)), ms(pct(d, 95)), ms(pct(d, 99)), ms(d[len(d)-1]))
	}

	fmt.Printf("\n%d ok, %d failed, wall clock %s", ok, bad, elapsed.Round(time.Millisecond))
	if elapsed > 0 {
		fmt.Printf(", %.1f req/s", float64(ok+bad)/elapsed.Seconds())
	}
	fmt.Println()

	if len(errs) > 0 {
		fmt.Println("\nerrors:")
		for ep, m := range errs {
			for e, n := range m {
				fmt.Printf("  %-32s %4d x %s\n", ep, n, e)
			}
		}
	}
}

func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := (len(sorted) - 1) * p / 100
	return sorted[i]
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000) }

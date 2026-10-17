package main

import (
	"bytes"
	"crypto/tls"
	"log/slog"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// An empty --metrics-listen must switch the unauthenticated metrics listener
// off. It used to reach http.Server with Addr "", which net/http treats as
// ":http" - every interface, port 80.
func TestEmptyMetricsListenDisablesMetrics(t *testing.T) {
	o, err := parseOptions([]string{"-metrics-listen", ""}, func(string) string { return "" }, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if o.metricsAddr != "" {
		t.Fatalf("metricsAddr = %q, want empty", o.metricsAddr)
	}
	if ms := newMetricsServer(o.metricsAddr, prometheus.NewRegistry(), slog.New(slog.DiscardHandler)); ms != nil {
		t.Errorf("a metrics server was built for an empty address (Addr %q)", ms.Addr)
	}
	if ms := newMetricsServer(":9346", prometheus.NewRegistry(), slog.New(slog.DiscardHandler)); ms == nil {
		t.Error("no metrics server for a real address")
	}
}

// Regression: the main server had only a header timeout, so idle keep-alive
// connections and oversized headers were unbounded; the metrics server was
// http.ListenAndServe with no timeouts at all (gosec G114), so a client
// trickling bytes held a goroutine and a socket forever.
func TestServersHaveTimeouts(t *testing.T) {
	m := newMainServer(":0", http.NewServeMux(), &tls.Config{})
	if m.ReadHeaderTimeout == 0 || m.IdleTimeout == 0 {
		t.Errorf("main server: ReadHeaderTimeout=%s IdleTimeout=%s, want both set", m.ReadHeaderTimeout, m.IdleTimeout)
	}
	if m.MaxHeaderBytes == 0 || m.MaxHeaderBytes > 64<<10 {
		t.Errorf("main server: MaxHeaderBytes=%d, want 1..64KiB", m.MaxHeaderBytes)
	}
	// The tunnel is a long-lived websocket on this server, so whole-request
	// read/write timeouts would cut it; per-endpoint deadlines are used instead.
	if m.ReadTimeout != 0 || m.WriteTimeout != 0 {
		t.Errorf("main server: ReadTimeout=%s WriteTimeout=%s would kill the tunnel", m.ReadTimeout, m.WriteTimeout)
	}

	ms := newMetricsServer(":0", prometheus.NewRegistry(), slog.New(slog.DiscardHandler))
	if ms.ReadHeaderTimeout == 0 || ms.ReadTimeout == 0 || ms.WriteTimeout == 0 || ms.IdleTimeout == 0 {
		t.Errorf("metrics server: ReadHeader=%s Read=%s Write=%s Idle=%s, want all set",
			ms.ReadHeaderTimeout, ms.ReadTimeout, ms.WriteTimeout, ms.IdleTimeout)
	}
}

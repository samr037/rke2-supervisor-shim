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
	m := newMainServer(":0", http.NewServeMux(), &tls.Config{}, slog.New(slog.DiscardHandler))
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

// The liveness probe is a bare TCP connect to :9345 (deliberately - see the
// chart), so net/http logged "TLS handshake error ... EOF" every 20s per node,
// as unstructured stderr. Handshake failures go to Debug; anything else the
// server reports stays visible.
func TestHandshakeErrorsAreDebugOnly(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	s := newMainServer(":0", http.NewServeMux(), &tls.Config{}, log)
	if s.ErrorLog == nil {
		t.Fatal("main server has no ErrorLog: net/http writes straight to stderr")
	}
	s.ErrorLog.Print("http: TLS handshake error from 10.0.0.5:4242: EOF")
	if buf.Len() != 0 {
		t.Errorf("handshake error logged at Info: %s", buf.String())
	}
	s.ErrorLog.Print("http: Accept error: too many open files")
	if !bytes.Contains(buf.Bytes(), []byte("too many open files")) {
		t.Errorf("other server errors must stay visible, got %q", buf.String())
	}
}

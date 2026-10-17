package tunnel

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func peerRequest(subject pkix.Name) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1-rke2/connect", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: subject}}}
	return r
}

// Regression: only the CN prefix was checked. The Node authorizer's identity
// is CN=system:node:<name> AND O=system:nodes; a certificate with the CN alone
// is not a node and must not be able to stand in for one.
func TestAuthorizeRequiresNodeIdentity(t *testing.T) {
	auth := authorizeNode(slog.New(slog.DiscardHandler))
	for name, subj := range map[string]pkix.Name{
		"CN without O":      {CommonName: "system:node:n1"},
		"CN with another O": {CommonName: "system:node:n1", Organization: []string{"system:masters"}},
		"kube-proxy":        {CommonName: "system:kube-proxy"},
		"empty node name":   {CommonName: "system:node:", Organization: []string{"system:nodes"}},
		"rke2-controller":   {CommonName: "system:rke2-controller"},
		"O without node CN": {CommonName: "n1", Organization: []string{"system:nodes"}},
	} {
		if _, ok, _ := auth(peerRequest(subj)); ok {
			t.Errorf("%s: tunnel authorized", name)
		}
	}
	node, ok, err := auth(peerRequest(pkix.Name{CommonName: "system:node:n1", Organization: []string{"system:nodes"}}))
	if err != nil || !ok || node != "n1" {
		t.Errorf("genuine node identity refused: node=%q ok=%v err=%v", node, ok, err)
	}
	if _, ok, _ := auth(httptest.NewRequest(http.MethodGet, "/v1-rke2/connect", nil)); ok {
		t.Error("request without a client certificate authorized")
	}
}

// authByHeader stands in for mTLS: the test names the node in a header.
func authByHeader(r *http.Request) (string, bool, error) {
	n := r.Header.Get("X-Test-Node")
	return n, n != "", nil
}

func dial(t *testing.T, srv *httptest.Server, node string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	h := http.Header{}
	h.Set("X-Test-Node", node)
	return websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), h)
}

// syncConnections writes one remotedialer SyncConnections message (type 8)
// with a body of n bytes, split into frames the way a streaming peer would.
func syncConnections(t *testing.T, c *websocket.Conn, n int) {
	t.Helper()
	var hdr bytes.Buffer
	b := make([]byte, binary.MaxVarintLen64)
	for _, v := range []int64{1, 0, 8} { // id, connID, type=SyncConnections
		hdr.Write(b[:binary.PutVarint(b, v)])
	}
	w, err := c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(hdr.Bytes()); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	for n > 0 {
		k := min(n, len(chunk))
		if _, err := w.Write(chunk[:k]); err != nil {
			return // the server hung up mid-message: what we want
		}
		n -= k
	}
	_ = w.Close()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Regression (remotedialer v0.6.1): SyncConnections bodies are read with
// io.ReadAll and no size limit, so a single authenticated peer could make the
// shim buffer an arbitrarily large message - hundreds of MB in the audit PoC.
// The shim never dials through the tunnel, so legitimate messages are tiny.
func TestTunnelMessageSizeIsCapped(t *testing.T) {
	srv := httptest.NewServer(newHandler(authByHeader, slog.New(slog.DiscardHandler)))
	defer srv.Close()

	// A legitimate, empty SyncConnections keeps the session open.
	c, _, err := dial(t, srv, "n1")
	if err != nil {
		t.Fatal(err)
	}
	syncConnections(t, c, 0)
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := c.ReadMessage(); !isTimeout(err) {
		t.Fatalf("a small message ended the session: %v", err)
	}
	c.Close()

	// A 4 MiB one (a multiple of 8, so it would decode) must end it.
	c, _, err = dial(t, srv, "n2")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	syncConnections(t, c, 4<<20)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := c.ReadMessage(); isTimeout(err) {
		t.Fatal("server accepted and buffered a 4 MiB tunnel message")
	}
}

// frame builds a masked client frame header (payload omitted unless given).
func frame(fin bool, opcode byte, length uint64, payload []byte) []byte {
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	out := []byte{b0}
	switch {
	case length < 126:
		out = append(out, 0x80|byte(length))
	case length <= 0xffff:
		out = append(out, 0x80|126)
		out = binary.BigEndian.AppendUint16(out, uint16(length))
	default:
		out = append(out, 0x80|127)
		out = binary.BigEndian.AppendUint64(out, length)
	}
	out = append(out, 1, 2, 3, 4) // mask key
	return append(out, payload...)
}

// The parser must hold up however the stream is split across reads.
func TestFrameLimitParsing(t *testing.T) {
	const limit = 1000
	feed := func(stream []byte) error {
		c := &frameLimitConn{max: limit}
		for i := range stream { // one byte at a time: worst-case splitting
			if err := c.inspect(stream[i : i+1]); err != nil {
				return err
			}
		}
		return nil
	}
	ok := [][]byte{
		frame(true, 0x2, 10, make([]byte, 10)),
		append(frame(false, 0x2, 400, make([]byte, 400)), // fragmented, 900 total,
			append(frame(true, 0x9, 3, []byte("png")), // with a ping in between
				frame(true, 0x0, 500, make([]byte, 500))...)...),
		append(frame(true, 0x2, 900, make([]byte, 900)), frame(true, 0x2, 900, make([]byte, 900))...),
	}
	for i, s := range ok {
		if err := feed(s); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := [][]byte{
		frame(true, 0x2, 1001, nil),
		frame(true, 0x2, 70000, nil),   // 16-bit length
		frame(true, 0x2, 1<<40, nil),   // 64-bit length
		frame(true, 0x2, 1<<63+5, nil), // would overflow int64
		append(frame(false, 0x2, 600, make([]byte, 600)), frame(true, 0x0, 600, nil)...),
	}
	for i, s := range bad {
		if err := feed(s); !errors.Is(err, errMessageTooLarge) {
			t.Errorf("bad[%d]: got %v, want errMessageTooLarge", i, err)
		}
	}
}

// One node identity must not be able to open sessions without bound: each
// costs a goroutine, buffers and a socket.
func TestTunnelSessionsPerNodeAreCapped(t *testing.T) {
	srv := httptest.NewServer(newHandler(authByHeader, slog.New(slog.DiscardHandler)))
	defer srv.Close()

	var open []*websocket.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	for i := 0; i < maxSessionsPerNode; i++ {
		c, _, err := dial(t, srv, "n1")
		if err != nil {
			t.Fatalf("session %d refused: %v", i+1, err)
		}
		open = append(open, c)
	}
	c, resp, err := dial(t, srv, "n1")
	if err == nil {
		c.Close()
		t.Fatalf("session %d for the same node was accepted", maxSessionsPerNode+1)
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("over-limit session: got %v, want 429", resp)
	}
	other, _, err := dial(t, srv, "n2")
	if err != nil {
		t.Fatalf("another node was refused: %v", err)
	}
	other.Close()

	// Slots are returned when a session ends.
	open[0].Close()
	open = open[1:]
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, _, err := dial(t, srv, "n1")
		if err == nil {
			open = append(open, c)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot not released after a session closed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

package supervisor

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Regression: the CSR endpoints read the body with no deadline, and the main
// server cannot have a global ReadTimeout (it would cut the tunnel). A client
// that announced a body and then trickled it - or sent nothing - held the
// handler, its goroutine and the socket indefinitely.
func TestCSRBodyReadHasADeadline(t *testing.T) {
	s := New(Config{Token: "t"}, testCA(t, "ca"), &recordingStore{allow: true}, nil, slog.New(slog.DiscardHandler))
	s.csrReadTimeout = 200 * time.Millisecond
	mux := http.NewServeMux()
	s.Routes(mux, nil)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("node:t"))
	fmt.Fprintf(conn, "POST /v1-rke2/client-kube-proxy.crt HTTP/1.1\r\nHost: x\r\n"+
		"Authorization: Basic %s\r\nContent-Length: 1000\r\n\r\npartial", auth)

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = bufio.NewReader(conn).ReadString('\n')
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("server was still waiting for the CSR body after 3s")
	}
}

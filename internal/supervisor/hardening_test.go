package supervisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samr037/rke2-supervisor-shim/internal/nodepassword"
)

const goodPassword = "0123456789abcdef0123456789abcdef" // rke2 sends 32 hex chars

// errStore fails every check with a fixed error.
type errStore struct{ err error }

func (e errStore) CheckAndSet(context.Context, string, string) (bool, error) { return false, e.err }

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func capturingLogger() (*slog.Logger, *syncBuffer) {
	b := &syncBuffer{}
	return slog.New(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})), b
}

func nodeCertRequest(t *testing.T, kind, node, password, ips string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1-rke2/"+kind+".crt", bytes.NewReader(testCSR(t)))
	req.SetBasicAuth("node", "t")
	req.Header.Set(hdrNodeName, node)
	req.Header.Set(hdrNodePassword, password)
	if ips != "" {
		req.Header.Set(hdrNodeIP, ips)
	}
	return req
}

// An existing node with no password on record (e.g. a Talos control plane)
// must be refused with a conflict and an operator-actionable ERROR, not a
// generic 500.
func TestExistingNodeWithoutPasswordIsAConflict(t *testing.T) {
	log, logs := capturingLogger()
	s := New(Config{Token: "t"}, testCA(t, "ca"),
		errStore{fmt.Errorf("%w: node %q", nodepassword.ErrNodeExistsWithoutPassword, "cp1")}, nil, log)
	rec := httptest.NewRecorder()
	s.handleCert(rec, nodeCertRequest(t, "client-kubelet", "cp1", goodPassword, ""))
	if rec.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409: %s", rec.Code, rec.Body.String())
	}
	out := logs.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "node-password.rke2") {
		t.Errorf("expected an ERROR telling the operator what to do, got:\n%s", out)
	}
}

// Regression: with no password store wired in, node-scoped certificates were
// issued with no password check at all. A missing store is a wiring bug and
// must fail closed.
func TestNilPasswordStoreFailsClosed(t *testing.T) {
	for _, kind := range []string{"serving-kubelet", "client-kubelet"} {
		s := New(Config{Token: "t"}, testCA(t, "ca"), nil, nil, slog.New(slog.DiscardHandler))
		w := httptest.NewRecorder()
		s.handleCert(w, nodeCertRequest(t, kind, "n1", goodPassword, ""))
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with no password store gave %d, want 500", kind, w.Code)
		}
		if strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
			t.Errorf("%s: a certificate was issued without any password check", kind)
		}
	}
}

// Every password that reaches the store costs a scrypt run; ones no agent
// could have sent are refused before that.
func TestNodePasswordLengthIsBounded(t *testing.T) {
	for _, pw := range []string{"short", strings.Repeat("x", 257)} {
		store := &recordingStore{allow: true}
		s := New(Config{Token: "t"}, testCA(t, "ca"), store, nil, slog.New(slog.DiscardHandler))
		w := httptest.NewRecorder()
		s.handleCert(w, nodeCertRequest(t, "client-kubelet", "n1", pw, ""))
		if w.Code != http.StatusBadRequest {
			t.Errorf("password of %d bytes gave %d, want 400", len(pw), w.Code)
		}
		if store.called {
			t.Errorf("password of %d bytes reached the store", len(pw))
		}
	}
}

type recordedExpiry struct{ notAfter time.Time }

func (r *recordedExpiry) RecordIssued(_, _ string, notAfter time.Time) { r.notAfter = notAfter }

// The expiry tracker must be told when the certificate really expires, which
// is capped by the CA's own expiry - not now+MaxTTL.
func TestRecordedExpiryIsTheLeafExpiry(t *testing.T) {
	ca := testCA(t, "ca") // valid for 24h
	ca.MaxTTL = 365 * 24 * time.Hour
	rec := &recordedExpiry{}
	s := New(Config{Token: "t"}, ca, &recordingStore{allow: true}, rec, slog.New(slog.DiscardHandler))
	w := httptest.NewRecorder()
	s.handleCert(w, nodeCertRequest(t, "client-kubelet", "n1", goodPassword, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	leaf := parseLeaf(t, w.Body.Bytes())
	if !rec.notAfter.Truncate(time.Second).Equal(leaf.NotAfter) {
		t.Errorf("recorded expiry %s, leaf expires %s", rec.notAfter, leaf.NotAfter)
	}
}

// A CSR the client got wrong (here: an RSA-1024 key) is a 400, not a 500.
func TestWeakCSRKeyIsABadRequest(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Token: "t"}, testCA(t, "ca"), &recordingStore{allow: true}, nil, slog.New(slog.DiscardHandler))
	req := httptest.NewRequest(http.MethodPost, "/v1-rke2/client-kube-proxy.crt", bytes.NewReader(der))
	req.SetBasicAuth("node", "t")
	rec := httptest.NewRecorder()
	s.handleCert(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("RSA-1024 CSR gave %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

// Regression: the node name header went straight into the certificate CN and
// SANs, so a token holder could mint a kubelet serving cert valid for
// kubernetes.default.svc, or a CN carrying arbitrary bytes.
func TestNodeNameIsValidated(t *testing.T) {
	bad := []string{
		"localhost", "kubernetes", "kubernetes.default", "kubernetes.default.svc",
		"api.svc.cluster.local", "a\x00b,O=system:masters", "UPPER", "-lead",
		"with space", "trailing.", strings.Repeat("a", 254),
	}
	for _, kind := range []string{"serving-kubelet", "client-kubelet"} {
		for _, name := range bad {
			store := &recordingStore{allow: true}
			s := New(Config{Token: "t"}, testCA(t, "ca"), store, nil, slog.New(slog.DiscardHandler))
			rec := httptest.NewRecorder()
			s.handleCert(rec, nodeCertRequest(t, kind, name, goodPassword, ""))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: node name %q gave %d, want 400", kind, name, rec.Code)
			}
			if store.called {
				t.Errorf("%s: node name %q reached the password store", kind, name)
			}
		}
	}
	for _, name := range []string{"n1", "worker-1.example.com", strings.Repeat("a", 63)} {
		s := New(Config{Token: "t"}, testCA(t, "ca"), &recordingStore{allow: true}, nil, slog.New(slog.DiscardHandler))
		rec := httptest.NewRecorder()
		s.handleCert(rec, nodeCertRequest(t, "client-kubelet", name, goodPassword, ""))
		if rec.Code != http.StatusOK {
			t.Errorf("valid node name %q gave %d: %s", name, rec.Code, rec.Body.String())
		}
	}
}

// Regression, found on the live lab: a node-scoped request whose CSR was later
// refused for its key still enrolled the node password first, so a token
// holder could squat node names without ever obtaining a certificate. The CSR
// must be judged before anything is written.
func TestRefusedCSRDoesNotEnrolAPassword(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"client-kubelet", "serving-kubelet"} {
		store := &recordingStore{allow: true}
		s := New(Config{Token: "t"}, testCA(t, "ca"), store, nil, slog.New(slog.DiscardHandler))
		req := httptest.NewRequest(http.MethodPost, "/v1-rke2/"+kind+".crt", bytes.NewReader(der))
		req.SetBasicAuth("node", "t")
		req.Header.Set(hdrNodeName, "squatted-node")
		req.Header.Set(hdrNodePassword, "0123456789abcdef0123456789abcdef")
		req.Header.Set(hdrNodeIP, "192.0.2.50")
		rec := httptest.NewRecorder()
		s.handleCert(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: weak CSR gave %d, want 400", kind, rec.Code)
		}
		if store.called {
			t.Errorf("%s: a refused CSR reached the password store and enrolled the name", kind)
		}
	}
}

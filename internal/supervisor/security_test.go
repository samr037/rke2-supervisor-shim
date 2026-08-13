package supervisor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samr037/rke2-supervisor-shim/internal/pki"
)

// recordingStore lets us assert whether the password check ran at all.
type recordingStore struct {
	called bool
	allow  bool
}

func (r *recordingStore) CheckAndSet(node, password string) (bool, error) {
	r.called = true
	return r.allow, nil
}

func serverWithStore(store NodePasswordStore) *Server {
	return New(Config{Token: "test-token"}, nil, store, nil,
		slog.New(slog.NewTextHandler(os.Stdout, nil)))
}

// Regression: the node password was previously only verified when the header
// was present, so omitting it let anyone holding the join token mint
// certificates in an existing node's name - defeating the entire point of node
// passwords. A missing header must be refused, not skipped.
func TestNodeCertRequiresNodePassword(t *testing.T) {
	for _, kind := range []string{"serving-kubelet", "client-kubelet"} {
		t.Run(kind, func(t *testing.T) {
			store := &recordingStore{allow: true}
			s := serverWithStore(store)

			req := httptest.NewRequest(http.MethodPost, "/v1-rke2/"+kind+".crt",
				strings.NewReader("not-a-real-csr"))
			req.SetBasicAuth("node", "test-token")
			req.Header.Set(hdrNodeName, "victim-node")
			// deliberately no Rke2-Node-Password
			rec := httptest.NewRecorder()
			s.handleCert(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("missing node password gave %d, want 400", rec.Code)
			}
			if store.called {
				t.Error("password store consulted despite no password supplied")
			}
			if !strings.Contains(rec.Body.String(), "node password not set") {
				t.Errorf("unexpected body: %s", rec.Body.String())
			}
		})
	}
}

// A wrong password must be a hard refusal, not a warning.
func TestNodeCertRejectsWrongNodePassword(t *testing.T) {
	store := &recordingStore{allow: false}
	s := serverWithStore(store)

	req := httptest.NewRequest(http.MethodPost, "/v1-rke2/client-kubelet.crt",
		strings.NewReader("csr"))
	req.SetBasicAuth("node", "test-token")
	req.Header.Set(hdrNodeName, "victim-node")
	req.Header.Set(hdrNodePassword, "guessed")
	rec := httptest.NewRecorder()
	s.handleCert(rec, req)

	if !store.called {
		t.Fatal("password store was not consulted")
	}
	if rec.Code != http.StatusConflict {
		t.Errorf("wrong password gave %d, want 409", rec.Code)
	}
}

// The captured agent-config template comes from a different rke2 cluster and
// contains that cluster's IPsec pre-shared key. It must never reach an agent.
func TestSecretsAreScrubbedFromAgentConfig(t *testing.T) {
	for _, v := range versions(t) {
		raw, err := os.ReadFile(filepath.Join(testdata, v, "config.json"))
		if err != nil {
			continue
		}
		// Even if a future capture reintroduces it, serving must strip it.
		var withSecret map[string]any
		if err := json.Unmarshal(raw, &withSecret); err != nil {
			t.Fatal(err)
		}
		withSecret["IPSECPSK"] = "0669cf9fcbeb5365654336b76882d8e5"
		reinjected, _ := json.Marshal(withSecret)

		s := New(Config{AgentConfigRaw: reinjected}, nil, nil, nil,
			slog.New(slog.NewTextHandler(os.Stdout, nil)))
		s.once.Do(s.buildAgentConfig)

		if got := s.agent["IPSECPSK"]; got != "" {
			t.Errorf("%s: IPSECPSK leaked to agents: %v", v, got)
		}
	}
}

// Oversized bodies must be refused rather than buffered.
func TestCSRSizeLimit(t *testing.T) {
	s := serverWithStore(&recordingStore{allow: true})
	req := httptest.NewRequest(http.MethodPost, "/v1-rke2/client-kube-proxy.crt",
		strings.NewReader(strings.Repeat("A", maxCSRBytes+10)))
	req.SetBasicAuth("node", "test-token")
	rec := httptest.NewRecorder()
	s.handleCert(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized CSR gave %d, want 400", rec.Code)
	}
}

// GET on a cert endpoint must not be treated as an issuance request.
func TestCertEndpointsRejectGET(t *testing.T) {
	s := serverWithStore(&recordingStore{allow: true})
	req := httptest.NewRequest(http.MethodGet, "/v1-rke2/client-kubelet.crt", nil)
	req.SetBasicAuth("node", "test-token")
	rec := httptest.NewRecorder()
	s.handleCert(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET gave %d, want 405", rec.Code)
	}
}

// RKE2 splits its PKI: apiservers verify kubelet SERVING certs against
// server-ca but CLIENT certs against client-ca. A single-CA Talos cluster hides
// this, and getting it wrong means `kubectl logs`/`exec` fails through RKE2
// apiservers with "certificate signed by unknown authority" after a worker
// migrates. Pin which CA signs which.
func TestServingCertsUseTheServingCA(t *testing.T) {
	clientCA := testCA(t, "client-ca")
	servingCA := testCA(t, "server-ca")

	s := New(Config{Token: "t"}, clientCA, &recordingStore{allow: true}, nil,
		slog.New(slog.NewTextHandler(os.Stdout, nil)))
	s.SetServingCA(servingCA)

	for _, tc := range []struct {
		kind, wantIssuer string
		nodeScoped       bool
	}{
		{"serving-kubelet", "server-ca", true},
		{"client-kubelet", "client-ca", true},
		{"client-kube-proxy", "client-ca", false},
		{"client-rke2-controller", "client-ca", false},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			csr := testCSR(t)
			req := httptest.NewRequest(http.MethodPost, "/v1-rke2/"+tc.kind+".crt",
				bytes.NewReader(csr))
			req.SetBasicAuth("node", "t")
			if tc.nodeScoped {
				req.Header.Set(hdrNodeName, "n1")
				req.Header.Set(hdrNodePassword, "p")
			}
			rec := httptest.NewRecorder()
			s.handleCert(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
			}
			blk, _ := pem.Decode(rec.Body.Bytes())
			leaf, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if got := leaf.Issuer.CommonName; got != tc.wantIssuer {
				t.Errorf("%s signed by %q, want %q", tc.kind, got, tc.wantIssuer)
			}
		})
	}
}

// Without a serving CA (a Talos-native cluster) everything uses the one CA.
func TestServingCertsFallBackToTheClusterCA(t *testing.T) {
	clientCA := testCA(t, "only-ca")
	s := New(Config{Token: "t"}, clientCA, &recordingStore{allow: true}, nil,
		slog.New(slog.NewTextHandler(os.Stdout, nil)))

	req := httptest.NewRequest(http.MethodPost, "/v1-rke2/serving-kubelet.crt",
		bytes.NewReader(testCSR(t)))
	req.SetBasicAuth("node", "t")
	req.Header.Set(hdrNodeName, "n1")
	req.Header.Set(hdrNodePassword, "p")
	rec := httptest.NewRecorder()
	s.handleCert(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	blk, _ := pem.Decode(rec.Body.Bytes())
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	if leaf.Issuer.CommonName != "only-ca" {
		t.Errorf("issuer %q, want only-ca", leaf.Issuer.CommonName)
	}
}

func testCA(t *testing.T, cn string) *pki.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &pki.CA{
		Cert:   cert,
		Key:    key,
		PEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		MaxTTL: time.Hour,
	}
}

func testCSR(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

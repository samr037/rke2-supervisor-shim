package supervisor

import (
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression: every address in Rke2-Node-Ip went into the kubelet serving
// certificate, so a token holder could get a cert from the cluster CA valid
// for the apiserver's own address, the kubernetes Service IP, loopback-ish
// ranges or any number of hosts.
func TestServingCertSANIPsAreRestricted(t *testing.T) {
	cfg := Config{Token: "t", ServiceCIDR: "10.96.0.0/12", APIServers: []string{"10.0.0.1:6443", "[fd00::1]:6443"}}
	bad := []string{
		"127.0.0.2", "0.0.0.0", "::", "169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1",
		"10.96.0.1",           // the kubernetes Service
		"10.0.0.1", "fd00::1", // a control-plane endpoint
		"10.0.0.249,not-an-ip",
		"10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8,10.0.0.9,10.0.0.10",
	}
	for _, ips := range bad {
		store := &recordingStore{allow: true}
		s := New(cfg, testCA(t, "ca"), store, nil, slog.New(slog.DiscardHandler))
		rec := httptest.NewRecorder()
		s.handleCert(rec, nodeCertRequest(t, "serving-kubelet", "n1", goodPassword, ips))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("Rke2-Node-Ip %q gave %d, want 400", ips, rec.Code)
		}
	}

	s := New(cfg, testCA(t, "ca"), &recordingStore{allow: true}, nil, slog.New(slog.DiscardHandler))
	rec := httptest.NewRecorder()
	s.handleCert(rec, nodeCertRequest(t, "serving-kubelet", "n1", goodPassword, "10.0.0.249, fd00::249"))
	if rec.Code != http.StatusOK {
		t.Fatalf("legitimate node IPs gave %d: %s", rec.Code, rec.Body.String())
	}
	leaf := parseLeaf(t, rec.Body.Bytes())
	got := map[string]bool{}
	for _, ip := range leaf.IPAddresses {
		got[ip.String()] = true
	}
	for _, want := range []string{"127.0.0.1", "::1", "10.0.0.249", "fd00::249"} {
		if !got[want] {
			t.Errorf("SAN %s missing from %v", want, leaf.IPAddresses)
		}
	}
}

// Discovered control-plane endpoints change at runtime; the check must follow.
func TestServingCertSANRejectsDiscoveredAPIServer(t *testing.T) {
	s := New(Config{Token: "t"}, testCA(t, "ca"), &recordingStore{allow: true}, nil, slog.New(slog.DiscardHandler))
	s.SetAPIServers([]string{"10.0.0.7:6443"})
	rec := httptest.NewRecorder()
	s.handleCert(rec, nodeCertRequest(t, "serving-kubelet", "n1", goodPassword, "10.0.0.7"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("discovered apiserver IP gave %d, want 400", rec.Code)
	}
}

func parseLeaf(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		t.Fatal("no PEM in response")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

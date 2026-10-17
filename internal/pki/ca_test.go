package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

// Regression: leaves were issued for now+MaxTTL regardless of the CA, so a CA
// with a month left minted year-long certificates that outlived their issuer.
func TestLeafNeverOutlivesCA(t *testing.T) {
	o := defaultCAOpts()
	o.notAfter = time.Now().Add(30 * time.Minute)
	ca := loadTestCA(t, o, 365*24*time.Hour)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	out, _, err := ca.Sign(csrFor(t, key), Request{CommonName: "x", ClientAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if leaf := leafOf(t, out); leaf.NotAfter.After(ca.Cert.NotAfter) {
		t.Errorf("Sign: leaf NotAfter %s is after CA NotAfter %s", leaf.NotAfter, ca.Cert.NotAfter)
	}

	certPEM, _, notAfter, err := ca.IssueSelf(Request{CommonName: "self"}, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafOf(t, certPEM)
	if leaf.NotAfter.After(ca.Cert.NotAfter) {
		t.Errorf("IssueSelf: leaf NotAfter %s is after CA NotAfter %s", leaf.NotAfter, ca.Cert.NotAfter)
	}
	if notAfter.After(ca.Cert.NotAfter) {
		t.Errorf("IssueSelf reported NotAfter %s past the CA's %s", notAfter, ca.Cert.NotAfter)
	}
}

// LoadCA is the last point at which a wrong file can be caught before the
// shim starts handing out certificates nobody will trust.
func TestLoadCARejectsUnusableCA(t *testing.T) {
	notCA := defaultCAOpts()
	notCA.isCA = false

	noCertSign := defaultCAOpts()
	noCertSign.keyUsage = x509.KeyUsageDigitalSignature

	expired := defaultCAOpts()
	expired.notBefore = time.Now().Add(-48 * time.Hour)
	expired.notAfter = time.Now().Add(-time.Hour)

	future := defaultCAOpts()
	future.notBefore = time.Now().Add(time.Hour)
	future.notAfter = time.Now().Add(48 * time.Hour)

	for name, o := range map[string]caOpts{
		"not a CA": notCA, "no CertSign": noCertSign, "expired": expired, "not yet valid": future,
	} {
		cp, kp := writeCA(t, o, nil)
		if _, err := LoadCA(cp, kp, 0); err == nil {
			t.Errorf("%s: LoadCA accepted it", name)
		}
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp, kp := writeCA(t, defaultCAOpts(), other)
	if _, err := LoadCA(cp, kp, 0); err == nil {
		t.Error("key that does not match the certificate: LoadCA accepted it")
	}

	cp, kp = writeCA(t, defaultCAOpts(), nil)
	if _, err := LoadCA(cp, kp, 0); err != nil {
		t.Errorf("a valid CA was refused: %v", err)
	}
}

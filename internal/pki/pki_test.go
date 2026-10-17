package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type caOpts struct {
	isCA      bool
	keyUsage  x509.KeyUsage
	notBefore time.Time
	notAfter  time.Time
}

func defaultCAOpts() caOpts {
	return caOpts{
		isCA:      true,
		keyUsage:  x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	}
}

// writeCA writes a self-signed CA cert and key to disk and returns the paths.
// keyOverride, when non-nil, is written instead of the CA's real key.
func writeCA(t *testing.T, o caOpts, keyOverride *ecdsa.PrivateKey) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		IsCA:                  o.isCA,
		KeyUsage:              o.keyUsage,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if keyOverride != nil {
		key = keyOverride
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	cp, kp := filepath.Join(d, "ca.crt"), filepath.Join(d, "ca.key")
	if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cp, kp
}

func loadTestCA(t *testing.T, o caOpts, maxTTL time.Duration) *CA {
	t.Helper()
	cp, kp := writeCA(t, o, nil)
	ca, err := LoadCA(cp, kp, maxTTL)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func csrFor(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func leafOf(t *testing.T, out []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(out)
	if blk == nil {
		t.Fatal("no PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Regression: any key the CSR carried was certified, including RSA-1024.
func TestSignEnforcesPublicKeyPolicy(t *testing.T) {
	ca := loadTestCA(t, defaultCAOpts(), time.Hour)

	mustRSA := func(bits int) crypto.Signer {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	mustEC := func(c elliptic.Curve) crypto.Signer {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	for name, k := range map[string]crypto.Signer{"rsa1024": mustRSA(1024), "rsa1536": mustRSA(1536)} {
		if _, _, err := ca.Sign(csrFor(t, k), Request{CommonName: "x", ClientAuth: true}); err == nil {
			t.Errorf("%s: weak key was certified", name)
		}
	}
	for name, k := range map[string]crypto.Signer{
		"rsa2048": mustRSA(2048), "p256": mustEC(elliptic.P256()), "p384": mustEC(elliptic.P384()),
		"p521": mustEC(elliptic.P521()), "ed25519": edKey,
	} {
		if _, _, err := ca.Sign(csrFor(t, k), Request{CommonName: "x", ClientAuth: true}); err != nil {
			t.Errorf("%s: acceptable key refused: %v", name, err)
		}
	}
}

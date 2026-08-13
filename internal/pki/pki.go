// Package pki signs the certificate requests an rke2 agent makes, using the
// Kubernetes cluster CA of the control plane it is joining.
//
// The agent generates its own private key and POSTs a DER CSR; we only ever
// sign. No node private key is ever held or transmitted by the shim.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// CA is the cluster certificate authority used to sign agent CSRs.
type CA struct {
	Cert   *x509.Certificate
	Key    crypto.Signer
	PEM    []byte // the CA certificate, PEM encoded
	MaxTTL time.Duration
}

func LoadCA(certPath, keyPath string, maxTTL time.Duration) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("CA cert is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%s is not a CA certificate", certPath)
	}

	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("CA key is not PEM")
	}
	key, err := parseKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	if maxTTL == 0 {
		maxTTL = 365 * 24 * time.Hour
	}
	return &CA{Cert: cert, Key: key, PEM: certPEM, MaxTTL: maxTTL}, nil
}

func parseKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key of type %T does not implement crypto.Signer", k)
	}
	return signer, nil
}

// Request describes the certificate an endpoint should produce. The subject is
// dictated by the endpoint, NOT taken from the CSR - a real rke2 server does
// the same, and it is what stops an agent from requesting an arbitrary
// identity by crafting its CSR.
type Request struct {
	CommonName   string
	Organization []string
	DNSNames     []string
	IPAddresses  []net.IP
	ClientAuth   bool // false => serverAuth
}

// Sign validates the CSR's self-signature, then issues a certificate for the
// CSR's public key with the subject and SANs we chose. Returns leaf PEM
// followed by the CA PEM, which is the wire format the agent expects.
func (ca *CA) Sign(csrDER []byte, req Request) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR self-signature invalid: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	eku := x509.ExtKeyUsageServerAuth
	if req.ClientAuth {
		eku = x509.ExtKeyUsageClientAuth
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: req.Organization,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ca.MaxTTL),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(out, ca.PEM...), nil
}

// IssueSelf generates a fresh key pair and issues a certificate for it. Used
// for the shim's own serving certificate, so it can mint and rotate its TLS
// identity from the cluster CA instead of relying on a hand-made file.
func (ca *CA) IssueSelf(req Request, ttl time.Duration) (certPEM, keyPEM []byte, notAfter time.Time, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	eku := x509.ExtKeyUsageServerAuth
	if req.ClientAuth {
		eku = x509.ExtKeyUsageClientAuth
	}
	if ttl == 0 {
		ttl = ca.MaxTTL
	}
	now := time.Now()
	notAfter = now.Add(ttl)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: req.CommonName, Organization: req.Organization},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, notAfter, nil
}
